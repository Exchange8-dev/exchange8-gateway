// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

// Ex8:Gateway submission pipeline + session features.
//
// - **Submission pipeline**: validated `ExchangeOrder` → risk
//   pre-check hook → `gw_order_id` assignment (monotonic counter, the
//   shell leases blocks from the platform sequence facility) → routing
//   by order type
//   (ME direct / OMS peg / SOR external). See DESIGN.md §2.
//   **Cross-service seam (open):** the Ex8:Risk pre-check
//   (`POST /v1/authorize` with `exchange8::contracts::risk::AuthorizeRequest`
//   = the plain `ExchangeOrder`, sync, <5 ms budget, fail-closed on
//   `RiskUnavailable`) is NOT yet mounted by Ex8:Risk (its router carries
//   no `/v1/authorize` route); the call site here stays the documented
//   seam — `route_order` performs shape validation only. Wiring the real
//   call is deferred until Risk mounts the endpoint (design
//   `sentin8-exchange8-risk-technical-design.md` §7: the identity is this
//   service's own workload certificate).
// - **Cancel-on-disconnect**: on session disconnect, every live
//   order of that connection is cancelled (ME `CancelAllForConnection`).
// - **Vendor/on-behalf-of**: OnBehalfOfCompID (115) resolution — a
//   vendor session submits on behalf of the beneficiary firm; the
//   beneficiary is stamped into the order for STP/risk attribution.
// - **FIX 5.0**: version negotiation — FIX 4.2 (default) vs 5.0
//   (FIXT 1.1 transport, 50=BeginString) accepted per session.
//
// Design: `design/sentin8-exchange8-gateway-technical-design.md` §4,
// `design/sentin8-exchange8-connectivity-operations-technical-design.md` §2.

use exchange8::contracts::order::{ExchangeOrder, OrdType};

/// Route decision for one submitted order (pipeline stage "route by type").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Standard limit/market → ME directly.
    MatchingEngine,
    /// Peg orders (OrdType=Pegged) → OMS peg supervisor.
    OmsPeg,
    /// Strategy/routed orders → SOR.
    Sor,
}

/// Submission rejection reasons (pre-ME; ME has its own reject codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitReject {
    /// Missing required identity (account/connection).
    MissingIdentity,
    /// Zero quantity.
    ZeroQty,
    /// Limit order without price.
    LimitWithoutPrice,
    /// Pegged order routed without peg metadata is malformed.
    MalformedPeg,
}

/// The order-id assigner: monotonic per gateway process; the shell leases
/// blocks from the platform sequence facility (10k per block) and refills.
pub struct OrderIdAssigner {
    next: u64,
    end: u64,
}

impl OrderIdAssigner {
    /// New assigner over a leased block [from, from+batch).
    pub fn new(from: u64, batch: u64) -> Self {
        OrderIdAssigner {
            next: from,
            end: from.saturating_add(batch),
        }
    }

    /// Take the next id; `None` = lease exhausted (shell must lease more).
    pub fn next_id(&mut self) -> Option<u64> {
        if self.next >= self.end {
            return None;
        }
        let id = self.next;
        self.next += 1;
        Some(id)
    }

    pub fn refill(&mut self, from: u64, batch: u64) {
        self.next = from;
        self.end = from.saturating_add(batch);
    }
}

/// Route one order by its type (see DESIGN.md §2).
pub fn route_order(o: &ExchangeOrder) -> Result<Route, SubmitReject> {
    // Identity preconditions.
    if o.account.is_empty() || o.client_comp_id.is_empty() {
        return Err(SubmitReject::MissingIdentity);
    }
    if o.qty.raw == 0 {
        return Err(SubmitReject::ZeroQty);
    }
    match o.ord_type {
        OrdType::Limit => {
            if o.price.is_none() {
                // Pegged-limit hybrids carry price; plain limit must too.
                if o.peg_type.is_none() {
                    return Err(SubmitReject::LimitWithoutPrice);
                }
            }
            if o.peg_type.is_some() {
                if o.peg_type.is_none() || o.price.is_none() && o.peg_difference.is_none() {
                    return Err(SubmitReject::MalformedPeg);
                }
                Ok(Route::OmsPeg)
            } else if !o.strategy.is_empty() && o.ex_destination.is_some() {
                // Strategy tokens + external destination → SOR.
                Ok(Route::Sor)
            } else {
                Ok(Route::MatchingEngine)
            }
        }
        OrdType::Pegged => {
            if o.peg_type.is_none() {
                return Err(SubmitReject::MalformedPeg);
            }
            Ok(Route::OmsPeg)
        }
    }
}

/// FIX version negotiation: BeginString (8) values accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixVersion {
    Fix42,
    Fix50,
}

impl FixVersion {
    /// Parse BeginString tag 8.
    pub fn from_begin_string(s: &str) -> Option<Self> {
        match s {
            "FIX.4.2" => Some(FixVersion::Fix42),
            "FIX.5.0" | "FIXT.1.1" => Some(FixVersion::Fix50),
            _ => None,
        }
    }

    pub fn begin_string(self) -> &'static str {
        match self {
            FixVersion::Fix42 => "FIX.4.2",
            FixVersion::Fix50 => "FIXT.1.1",
        }
    }

    /// FIX 5.0 splits session from application version: EncryptedPassword
    /// handling and NextExpectedMsgSeqNum (789) are 5.0 session features.
    pub fn supports_next_expected_seqn(self) -> bool {
        matches!(self, FixVersion::Fix50)
    }
}

/// On-behalf-of resolution: vendor sessions submit for a
/// beneficiary; attribution fields resolve to the beneficiary for
/// STP/risk, while the vendor stays the routing counterparty.
#[derive(Clone, Debug, PartialEq)]
pub struct OnBehalfOf {
    /// Vendor submitting firm (session's client CompID).
    pub vendor_comp_id: String,
    /// Beneficiary firm (tag 115 OnBehalfOfCompID).
    pub on_behalf_comp_id: String,
}

/// Resolve attribution for an on-behalf-of submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribution {
    /// Firm the order is attributed to for STP/risk.
    pub stp_owner: String,
    /// Firm receiving execution reports (drop logic may differ).
    pub report_target: String,
}

impl OnBehalfOf {
    /// Vendor submits, beneficiary owns the risk/STP attribution.
    pub fn resolve(&self) -> Attribution {
        Attribution {
            stp_owner: self.on_behalf_comp_id.clone(),
            report_target: self.vendor_comp_id.clone(),
        }
    }
}

/// Cancel-on-disconnect registry: live orders per connection; on
/// disconnect the shell sends ME `CancelAllForConnection`.
pub struct CancelOnDisconnect {
    /// connection_id → live gw order ids.
    live: std::collections::HashMap<u16, std::collections::HashSet<u64>>,
}

impl CancelOnDisconnect {
    pub fn new() -> Self {
        CancelOnDisconnect {
            live: std::collections::HashMap::new(),
        }
    }

    /// Track a submitted order as live on its connection.
    pub fn on_submitted(&mut self, connection_id: u16, gw_order_id: u64) {
        self.live
            .entry(connection_id)
            .or_default()
            .insert(gw_order_id);
    }

    /// Order left the live set (filled/killed/cancelled).
    pub fn on_done(&mut self, connection_id: u16, gw_order_id: u64) {
        if let Some(set) = self.live.get_mut(&connection_id) {
            set.remove(&gw_order_id);
            if set.is_empty() {
                self.live.remove(&connection_id);
            }
        }
    }

    /// Connection dropped: return the order ids to cancel. Cancel-on-
    /// disconnect semantics: ALL live orders of that connection.
    pub fn on_disconnect(&mut self, connection_id: u16) -> Vec<u64> {
        self.live
            .remove(&connection_id)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default()
    }

    /// Live count for a connection (diagnostics).
    pub fn live_count(&self, connection_id: u16) -> usize {
        self.live.get(&connection_id).map(|s| s.len()).unwrap_or(0)
    }
}

impl Default for CancelOnDisconnect {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exchange8::contracts::enums::{Capacity, Visibility};
    use exchange8::contracts::order::{BookToken, OrdStatus, OrderSide, PegType, Tif};
    use exchange8::fixed::{Price, Qty};

    fn order(mutate: impl FnOnce(&mut ExchangeOrder)) -> ExchangeOrder {
        let mut o = ExchangeOrder {
            env_id: "e".into(),
            gw_order_id: 0,
            cl_ord_id: "C1".into(),
            orig_cl_ord_id: None,
            account: "ACCT".into(),
            client_comp_id: "MEMBER".into(),
            on_behalf_comp_id: None,
            user_id: None,
            connection_id: 7,
            instrument: exchange8::contracts::order::InstrumentRef {
                id: 1,
                symbol: "EX8A".into(),
                isin: None,
                mic: "XL8M".into(),
                currency: "CAD".into(),
                price_scale: 4,
                qty_scale: 0,
                lot_size: Qty::units(100),
                kind: exchange8::contracts::order::InstrumentKind::Equity,
            },
            side: OrderSide::Buy,
            qty: Qty::units(100),
            min_qty: None,
            price: Some(Price::equity(10_000)),
            ord_type: OrdType::Limit,
            tif: Tif::Day,
            peg_type: None,
            peg_difference: None,
            peg_ebbo: false,
            visibility: Visibility::Display,
            max_floor: None,
            capacity: Capacity::Agency,
            anonymous: false,
            bypass: false,
            price_protection: None,
            post_only: false,
            book: BookToken('*'),
            strategy: vec![],
            stp_key: None,
            stp_action: None,
            cross: None,
            ex_destination: None,
            ord_status: OrdStatus::New,
            cum_qty: Qty::ZERO,
            leaves_qty: Qty::units(100),
            avg_px: None,
            timestamp_us: 0,
        };
        mutate(&mut o);
        o
    }

    #[test]
    fn plain_limit_routes_to_me() {
        let o = order(|_| {});
        assert_eq!(route_order(&o), Ok(Route::MatchingEngine));
    }

    #[test]
    fn pegged_routes_to_oms() {
        let o = order(|o| {
            o.ord_type = OrdType::Pegged;
            o.peg_type = Some(PegType::Midpoint);
        });
        assert_eq!(route_order(&o), Ok(Route::OmsPeg));
    }

    #[test]
    fn strategy_with_destination_routes_to_sor() {
        let o = order(|o| {
            o.strategy = vec![BookToken('*')];
            o.ex_destination = Some("XTSE".into());
        });
        assert_eq!(route_order(&o), Ok(Route::Sor));
    }

    #[test]
    fn validation_rejects() {
        // Zero qty.
        let o = order(|o| o.qty = Qty::ZERO);
        assert_eq!(route_order(&o), Err(SubmitReject::ZeroQty));
        // No account.
        let o = order(|o| o.account.clear());
        assert_eq!(route_order(&o), Err(SubmitReject::MissingIdentity));
        // Plain limit without price.
        let o = order(|o| o.price = None);
        assert_eq!(route_order(&o), Err(SubmitReject::LimitWithoutPrice));
        // Pegged without peg type.
        let o = order(|o| {
            o.ord_type = OrdType::Pegged;
            o.peg_type = None;
        });
        assert_eq!(route_order(&o), Err(SubmitReject::MalformedPeg));
    }

    #[test]
    fn order_ids_lease_and_exhaust() {
        let mut a = OrderIdAssigner::new(1, 3);
        assert_eq!(a.next_id(), Some(1));
        assert_eq!(a.next_id(), Some(2));
        assert_eq!(a.next_id(), Some(3));
        assert_eq!(a.next_id(), None);
        a.refill(4, 2);
        assert_eq!(a.next_id(), Some(4));
    }

    #[test]
    fn cancel_on_disconnect_cancels_all_live() {
        let mut c = CancelOnDisconnect::new();
        c.on_submitted(7, 1);
        c.on_submitted(7, 2);
        c.on_submitted(9, 3);
        assert_eq!(c.live_count(7), 2);
        // Order 1 done (filled) — only 2 remains live.
        c.on_done(7, 1);
        assert_eq!(c.live_count(7), 1);
        // Connection 7 drops → cancel order 2 only.
        let to_cancel = c.on_disconnect(7);
        assert_eq!(to_cancel, vec![2]);
        assert_eq!(c.live_count(7), 0);
        // Other connection unaffected.
        assert_eq!(c.live_count(9), 1);
        // Unknown connection → empty.
        assert!(c.on_disconnect(99).is_empty());
    }

    #[test]
    fn fix_version_negotiation() {
        assert_eq!(
            FixVersion::from_begin_string("FIX.4.2"),
            Some(FixVersion::Fix42)
        );
        assert_eq!(
            FixVersion::from_begin_string("FIX.5.0"),
            Some(FixVersion::Fix50)
        );
        assert_eq!(
            FixVersion::from_begin_string("FIXT.1.1"),
            Some(FixVersion::Fix50)
        );
        assert_eq!(FixVersion::from_begin_string("FIX.4.4"), None);
        assert_eq!(FixVersion::Fix42.begin_string(), "FIX.4.2");
        assert!(!FixVersion::Fix42.supports_next_expected_seqn());
        assert!(FixVersion::Fix50.supports_next_expected_seqn());
    }

    #[test]
    fn on_behalf_of_attribution() {
        let ob = OnBehalfOf {
            vendor_comp_id: "VENDOR".into(),
            on_behalf_comp_id: "BENEF".into(),
        };
        let a = ob.resolve();
        // Beneficiary owns STP/risk attribution.
        assert_eq!(a.stp_owner, "BENEF");
        // Vendor session receives the reports.
        assert_eq!(a.report_target, "VENDOR");
    }

    #[test]
    fn me_order_type_surface_present() {
        // The ME AddOrder catalog is shared with the pipeline routing; a
        // plain limit is always routable.
        let o = order(|_| {});
        let r = route_order(&o).unwrap();
        assert!(matches!(r, Route::MatchingEngine));
        let _ = exchange8::contracts::enums::OrderType::Limit; // catalog linkage sanity
    }
}
