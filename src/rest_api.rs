// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Ex8:Gateway logon key verification + BFF REST order surface.
//!
//! - **Logon handshake**: Username (553) / Password (554) carry a
//!   *session key reference*, not
//!   a password; verification is a constant-time comparison against the
//!   key registry (the shell resolves `secret://` refs out-of-band).
//! - **BFF-proxied REST order API** — the request/response shapes
//!   `POST /proxy/exchange8/v1/orders` serves: submit/cancel/status with
//!   scope names the BFF enforces (`exchange8:gateway:orders:write/read`).
//!   See DESIGN.md §4.
//!
//! Design: `design/sentin8-exchange8-gateway-technical-design.md` §4,
//! `design/sentin8-exchange8-connectivity-operations-technical-design.md` §2.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Logon handshake — session key verification
// ---------------------------------------------------------------------------

/// A registered FIX session key: CompID pair → key material (resolved from
/// the secret store at SOD; never stored plaintext in DB).
#[derive(Clone, Debug, PartialEq)]
pub struct SessionKey {
    pub client_comp_id: String,
    /// The Sentin8-issued session key (from `secret://exchange8/fix/{comp}`).
    pub key: String,
}

/// Registry of issued keys (constant-time verification). `Clone` for the
/// runtime's registry snapshot (armed once at boot; snapshots are cheap).
#[derive(Clone)]
pub struct SessionKeyRegistry {
    keys: HashMap<String, SessionKey>,
}

impl SessionKeyRegistry {
    pub fn new(keys: Vec<SessionKey>) -> Self {
        let mut map = HashMap::new();
        for k in keys {
            map.insert(k.client_comp_id.clone(), k);
        }
        SessionKeyRegistry { keys: map }
    }

    /// Verify a logon (553/554): the CompID must be registered and the key
    /// must match. Constant-time comparison (no early exit on mismatch).
    pub fn verify(&self, username_553: &str, password_554: &str) -> LogonDecision {
        let Some(registered) = self.keys.get(username_553) else {
            return LogonDecision::UnknownCompId;
        };
        if constant_time_eq(registered.key.as_bytes(), password_554.as_bytes()) {
            LogonDecision::Accepted
        } else {
            LogonDecision::BadKey
        }
    }
}

/// Logon outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogonDecision {
    Accepted,
    /// CompID not registered.
    UnknownCompId,
    /// Key mismatch (the logon is rejected without revealing which part).
    BadKey,
}

/// Length-safe constant-time equality.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// BFF-proxied REST order API shapes
// ---------------------------------------------------------------------------

/// `POST /proxy/exchange8/v1/orders` body (normalized).
#[derive(Clone, Debug, PartialEq)]
pub struct RestOrderRequest {
    /// Client order id (idempotency key).
    pub cl_ord_id: String,
    pub symbol: String,
    /// Buy/sell.
    pub side_bid: bool,
    pub qty: u64,
    /// Raw limit price (None = market — equity venues reject; crypto allows).
    pub limit_raw: Option<i128>,
    /// TIF code ("0" day, "3" IOC, "4" FOK).
    pub tif: String,
}

/// Validation outcome for the REST surface.
#[derive(Clone, Debug, PartialEq)]
pub enum RestOrderError {
    MissingClOrdId,
    MissingSymbol,
    ZeroQty,
    MarketOrderRejected,
    BadTif,
}

impl RestOrderRequest {
    /// Validate (the BFF enforces scopes; this is the domain validation).
    pub fn validate(&self, allow_market: bool) -> Result<(), RestOrderError> {
        if self.cl_ord_id.is_empty() {
            return Err(RestOrderError::MissingClOrdId);
        }
        if self.symbol.is_empty() {
            return Err(RestOrderError::MissingSymbol);
        }
        if self.qty == 0 {
            return Err(RestOrderError::ZeroQty);
        }
        if self.limit_raw.is_none() && !allow_market {
            return Err(RestOrderError::MarketOrderRejected);
        }
        match self.tif.as_str() {
            "0" | "1" | "3" | "4" | "6" => Ok(()),
            _ => Err(RestOrderError::BadTif),
        }
    }
}

/// `POST /v1/orders/{id}/cancel` response shape.
#[derive(Clone, Debug, PartialEq)]
pub struct RestCancelResponse {
    pub cl_ord_id: String,
    pub cancelled: bool,
    /// False when the order was unknown or already terminal.
    pub reason: Option<&'static str>,
}

/// `GET /v1/orders/{id}` response shape (status echo).
#[derive(Clone, Debug, PartialEq)]
pub struct RestOrderStatus {
    pub cl_ord_id: String,
    pub status: char, // FIX 39 codes
    pub qty: u64,
    pub filled: u64,
}

// ---------------------------------------------------------------------------
// Crypto REST/WS order entry — the crypto primary path
// ---------------------------------------------------------------------------

/// Crypto order precision: prices/quantities are decimal-scaled ×10⁸
/// — REST/WS carry them as plain integers in that scale.
#[cfg_attr(test, allow(dead_code))]
pub const CRYPTO_SCALE: u8 = 8;

/// `POST /proxy/exchange8/v1/crypto/orders` body.
#[derive(Clone, Debug, PartialEq)]
pub struct CryptoRestOrder {
    pub cl_ord_id: String,
    pub instrument_id: u32,
    pub side_bid: bool,
    /// ×10⁸ quantity.
    pub qty_raw: u64,
    /// ×10⁸ limit price; None = market (crypto allows market orders).
    pub limit_raw: Option<i128>,
    /// Continuous-market TIF: GTC or IOC.
    pub tif: CryptoTif,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoTif {
    Gtc,
    Ioc,
}

impl CryptoTif {
    pub fn from_code(s: &str) -> Option<Self> {
        match s {
            "1" => Some(CryptoTif::Gtc),
            "3" => Some(CryptoTif::Ioc),
            _ => None,
        }
    }
}

/// Crypto REST validation (continuous market, decimal qty).
impl CryptoRestOrder {
    pub fn validate(&self) -> Result<(), RestOrderError> {
        if self.cl_ord_id.is_empty() {
            return Err(RestOrderError::MissingClOrdId);
        }
        if self.qty_raw == 0 {
            return Err(RestOrderError::ZeroQty);
        }
        // Market orders allowed on the crypto path.
        Ok(())
    }
}

/// One WS order-entry/execution event (bidirectional tier).
/// `Ack` is the venue→client direction — constructed by the fill stream.
#[cfg_attr(test, allow(dead_code))]
#[derive(Clone, Debug, PartialEq)]
pub enum CryptoWsOrderEvent {
    /// Client → venue: new order (same shape as REST).
    Submit {
        cl_ord_id: String,
        qty_raw: u64,
        limit_raw: Option<i128>,
    },
    /// Venue → client: ack.
    Ack { cl_ord_id: String, order_id: u64 },
    /// Venue → client: fill.
    Fill {
        cl_ord_id: String,
        fill_qty: u64,
        price_raw: i128,
    },
    /// Venue → client: cancel/kill.
    Done {
        cl_ord_id: String,
        reason: &'static str,
    },
}

impl CryptoWsOrderEvent {
    /// WS JSON frame.
    /// WS JSON frame.
    pub fn to_ws_json(&self) -> String {
        use serde_json::json;
        let v = match self {
            CryptoWsOrderEvent::Submit {
                cl_ord_id,
                qty_raw,
                limit_raw,
            } => json!({
                "e": "submit", "c": cl_ord_id, "q": qty_raw,
                "p": limit_raw.map(|p| p.to_string()),
            }),
            CryptoWsOrderEvent::Ack {
                cl_ord_id,
                order_id,
            } => json!({
                "e": "ack", "c": cl_ord_id, "o": order_id,
            }),
            CryptoWsOrderEvent::Fill {
                cl_ord_id,
                fill_qty,
                price_raw,
            } => json!({
                "e": "fill", "c": cl_ord_id, "q": fill_qty, "p": price_raw,
            }),
            CryptoWsOrderEvent::Done { cl_ord_id, reason } => json!({
                "e": "done", "c": cl_ord_id, "r": reason,
            }),
        };
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logon_key_verified() {
        let reg = SessionKeyRegistry::new(vec![SessionKey {
            client_comp_id: "NORTHWIND".into(),
            key: "issued-key-1".into(),
        }]);
        assert_eq!(
            reg.verify("NORTHWIND", "issued-key-1"),
            LogonDecision::Accepted
        );
        assert_eq!(reg.verify("NORTHWIND", "wrong"), LogonDecision::BadKey);
        assert_eq!(reg.verify("NOBODY", "x"), LogonDecision::UnknownCompId);
        // Wrong-length key fails fast but safely.
        assert_eq!(reg.verify("NORTHWIND", ""), LogonDecision::BadKey);
    }

    #[test]
    fn constant_time_eq_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn rest_order_validation() {
        let good = RestOrderRequest {
            cl_ord_id: "C1".into(),
            symbol: "EX8A".into(),
            side_bid: true,
            qty: 100,
            limit_raw: Some(10_000),
            tif: "0".into(),
        };
        assert!(good.validate(false).is_ok());
        // Market order rejected on equity mode.
        let market = RestOrderRequest {
            limit_raw: None,
            ..good.clone()
        };
        assert_eq!(
            market.validate(false),
            Err(RestOrderError::MarketOrderRejected)
        );
        assert!(market.validate(true).is_ok()); // crypto mode allows
                                                // Field checks.
        let no_id = RestOrderRequest {
            cl_ord_id: String::new(),
            ..good.clone()
        };
        assert_eq!(no_id.validate(false), Err(RestOrderError::MissingClOrdId));
        let zero = RestOrderRequest {
            qty: 0,
            ..good.clone()
        };
        assert_eq!(zero.validate(false), Err(RestOrderError::ZeroQty));
        let bad_tif = RestOrderRequest {
            tif: "9".into(),
            ..good
        };
        assert_eq!(bad_tif.validate(false), Err(RestOrderError::BadTif));
    }

    #[test]
    fn rest_status_shapes() {
        let s = RestOrderStatus {
            cl_ord_id: "C1".into(),
            status: '1',
            qty: 100,
            filled: 40,
        };
        assert_eq!(s.filled, 40);
        let c = RestCancelResponse {
            cl_ord_id: "C1".into(),
            cancelled: false,
            reason: Some("not_found"),
        };
        assert!(!c.cancelled);
    }

    #[test]
    fn crypto_rest_orders_allow_market() {
        let o = CryptoRestOrder {
            cl_ord_id: "C9".into(),
            instrument_id: 1,
            side_bid: true,
            qty_raw: 350_000_000,
            limit_raw: None, // market — allowed on crypto
            tif: CryptoTif::Ioc,
        };
        assert!(o.validate().is_ok());
        // Zero qty still rejected.
        let bad = CryptoRestOrder { qty_raw: 0, ..o };
        assert_eq!(bad.validate(), Err(RestOrderError::ZeroQty));
        // TIF codes.
        assert_eq!(CryptoTif::from_code("1"), Some(CryptoTif::Gtc));
        assert_eq!(CryptoTif::from_code("3"), Some(CryptoTif::Ioc));
        assert_eq!(CryptoTif::from_code("0"), None);
    }

    #[test]
    fn crypto_ws_events_render() {
        let s = CryptoWsOrderEvent::Submit {
            cl_ord_id: "C1".into(),
            qty_raw: 100,
            limit_raw: Some(950_000_000),
        };
        assert!(s.to_ws_json().contains("\"e\":\"submit\""));
        let f = CryptoWsOrderEvent::Fill {
            cl_ord_id: "C1".into(),
            fill_qty: 100,
            price_raw: 950_000_000,
        };
        assert!(f.to_ws_json().contains("\"e\":\"fill\""));
        let d = CryptoWsOrderEvent::Done {
            cl_ord_id: "C1".into(),
            reason: "ioc_expired",
        };
        assert!(d.to_ws_json().contains("\"r\":\"ioc_expired\""));
    }
}
