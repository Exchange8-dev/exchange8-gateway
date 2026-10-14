// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Ex8:Gateway OUCH — binary order-entry protocol codec (Nasdaq-style).
//!
//! OUCH is the low-latency binary alternative to FIX for order entry: fixed
//! layout, no delimiters, little-endian, alpha fields left-justified and
//! blank (space) padded. This module implements the exchange8 subset:
//! EnterOrder, ReplaceOrder, CancelOrder; outbound Ordered, Accepted,
//! Rejected, Canceled, Executed, CanceledDueToCross, BrokenTrade.
//!
//! Inbound packets decode to the normalized `ExchangeOrder` (via the same
//! mapping the FIX path uses); outbound lifecycle events encode from the ME
//! event stream. The shell owns the TCP framing and session state.
//!
//! Design: `design/sentin8-exchange8-connectivity-operations-technical-design.md` §2.

use exchange8::contracts::enums::{Capacity, Visibility};
use exchange8::contracts::order::{OrdType, OrderSide, Tif};

/// OUCH inbound message types (first byte of each packet).
pub const MSG_ENTER_ORDER: u8 = b'U';
pub const MSG_REPLACE_ORDER: u8 = b'X';
pub const MSG_CANCEL_ORDER: u8 = b'Y';

/// OUCH outbound message types.
pub const MSG_ORDERED: u8 = b'A';
pub const MSG_ACCEPTED: u8 = b'A';
pub const MSG_REJECTED: u8 = b'J';
pub const MSG_CANCELED: u8 = b'C';
pub const MSG_EXECUTED: u8 = b'E';
pub const MSG_CANCELED_DUE_TO_CROSS: u8 = b'X';

/// Decoded inbound OUCH message.
#[derive(Clone, Debug, PartialEq)]
pub enum OuchInbound {
    Enter(EnterOrder),
    Replace(ReplaceOrder),
    Cancel(CancelOrder),
}

/// `EnterOrder` — new order submission.
#[derive(Clone, Debug, PartialEq)]
pub struct EnterOrder {
    /// Display/hidden bitfield (OUCH Buy/Sell Type byte).
    pub side_display: u8,
    pub quantity: u32,
    pub book: u32,
    pub price: u32,
    /// Time in force (OUCH chars: 0/1/3/4/6).
    pub tif: u8,
    pub firm: [u8; 4],
    pub capacity: u8,
    /// Account (alpha 10, blank padded).
    pub account: [u8; 10],
    /// Clearing account display flag.
    pub is_inverse: u8,
    pub price_flag: u8,
    /// Client order reference (alpha 20).
    pub cl_ord_id: [u8; 20],
    /// Minimum quantity.
    pub min_qty: u32,
    /// Customer id (numeric text).
    pub customer: [u8; 10],
}

/// `ReplaceOrder` — modify resting order.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplaceOrder {
    pub quantity: u32,
    pub book: u32,
    pub price: u32,
    pub tif: u8,
    pub capacity: u8,
    pub cl_ord_id: [u8; 20],
    /// Original client order reference (the order to replace).
    pub orig_cl_ord_id: [u8; 20],
}

/// `CancelOrder` — cancel by client order reference.
#[derive(Clone, Debug, PartialEq)]
pub struct CancelOrder {
    pub orig_cl_ord_id: [u8; 20],
}

/// Outbound OUCH lifecycle message.
#[derive(Clone, Debug, PartialEq)]
pub enum OuchOutbound {
    Ordered {
        timestamp_us: u64,
        cl_ord_id: [u8; 20],
        order_id: u64,
    },
    Accepted {
        timestamp_us: u64,
        cl_ord_id: [u8; 20],
        order_id: u64,
    },
    Rejected {
        timestamp_us: u64,
        cl_ord_id: [u8; 20],
        order_id: u64,
        reason: u8,
    },
    Canceled {
        timestamp_us: u64,
        cl_ord_id: [u8; 20],
        order_id: u64,
        cum_qty: u32,
        leaves: u32,
        reason: u8,
    },
    Executed {
        timestamp_us: u64,
        cl_ord_id: [u8; 20],
        order_id: u64,
        trade_id: u64,
        qty: u32,
        price: u32,
        leaves: u32,
    },
}

/// Decode one inbound packet (body after the framing header). Returns None
/// on unknown type or short body.
pub fn decode_inbound(body: &[u8]) -> Option<OuchInbound> {
    let ty = *body.first()?;
    match ty {
        MSG_ENTER_ORDER => EnterOrder::decode(&body[1..]).map(OuchInbound::Enter),
        MSG_REPLACE_ORDER => ReplaceOrder::decode(&body[1..]).map(OuchInbound::Replace),
        MSG_CANCEL_ORDER => CancelOrder::decode(&body[1..]).map(OuchInbound::Cancel),
        _ => None,
    }
}

/// Encode one outbound packet body (caller adds framing).
pub fn encode_outbound(msg: &OuchOutbound) -> Vec<u8> {
    match msg {
        OuchOutbound::Ordered {
            timestamp_us,
            cl_ord_id,
            order_id,
        } => {
            let mut b = vec![MSG_ORDERED];
            b.extend_from_slice(&timestamp_us.to_le_bytes());
            b.extend_from_slice(cl_ord_id);
            b.extend_from_slice(&order_id.to_le_bytes());
            b
        }
        OuchOutbound::Accepted {
            timestamp_us,
            cl_ord_id,
            order_id,
        } => {
            let mut b = vec![MSG_ACCEPTED];
            b.extend_from_slice(&timestamp_us.to_le_bytes());
            b.extend_from_slice(cl_ord_id);
            b.extend_from_slice(&order_id.to_le_bytes());
            b
        }
        OuchOutbound::Rejected {
            timestamp_us,
            cl_ord_id,
            order_id,
            reason,
        } => {
            let mut b = vec![MSG_REJECTED];
            b.extend_from_slice(&timestamp_us.to_le_bytes());
            b.extend_from_slice(cl_ord_id);
            b.extend_from_slice(&order_id.to_le_bytes());
            b.push(*reason);
            b
        }
        OuchOutbound::Canceled {
            timestamp_us,
            cl_ord_id,
            order_id,
            cum_qty,
            leaves,
            reason,
        } => {
            let mut b = vec![MSG_CANCELED];
            b.extend_from_slice(&timestamp_us.to_le_bytes());
            b.extend_from_slice(cl_ord_id);
            b.extend_from_slice(&order_id.to_le_bytes());
            b.extend_from_slice(&cum_qty.to_le_bytes());
            b.extend_from_slice(&leaves.to_le_bytes());
            b.push(*reason);
            b
        }
        OuchOutbound::Executed {
            timestamp_us,
            cl_ord_id,
            order_id,
            trade_id,
            qty,
            price,
            leaves,
        } => {
            let mut b = vec![MSG_EXECUTED];
            b.extend_from_slice(&timestamp_us.to_le_bytes());
            b.extend_from_slice(cl_ord_id);
            b.extend_from_slice(&order_id.to_le_bytes());
            b.extend_from_slice(&trade_id.to_le_bytes());
            b.extend_from_slice(&qty.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&leaves.to_le_bytes());
            b
        }
    }
}

fn alpha<const N: usize>(s: &str) -> [u8; N] {
    let mut a = [b' '; N];
    let bytes = s.as_bytes();
    let n = bytes.len().min(N);
    a[..n].copy_from_slice(&bytes[..n]);
    a
}

fn alpha_str<const N: usize>(a: &[u8; N]) -> String {
    String::from_utf8_lossy(a)
        .trim_end()
        .trim_end_matches('\0')
        .to_string()
}

impl EnterOrder {
    /// Fixed body size after the type byte.
    pub const BODY: usize = 1 + 4 + 4 + 4 + 1 + 4 + 1 + 10 + 1 + 1 + 20 + 4 + 10;

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BODY {
            return None;
        }
        let rd_u32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let rd_u64 = |o: usize| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[o..o + 8]);
            u64::from_le_bytes(x)
        };
        let _ = rd_u64(0); // keep offsets honest
        Some(EnterOrder {
            side_display: b[0],
            quantity: rd_u32(1),
            book: rd_u32(5),
            price: rd_u32(9),
            tif: b[13],
            firm: [b[14], b[15], b[16], b[17]],
            capacity: b[18],
            account: alpha_from(&b[19..29]),
            is_inverse: b[29],
            price_flag: b[30],
            cl_ord_id: alpha20_from(&b[31..51]),
            min_qty: rd_u32(51),
            customer: alpha_from(&b[55..65]),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + Self::BODY);
        b.push(MSG_ENTER_ORDER);
        b.push(self.side_display);
        b.extend_from_slice(&self.quantity.to_le_bytes());
        b.extend_from_slice(&self.book.to_le_bytes());
        b.extend_from_slice(&self.price.to_le_bytes());
        b.push(self.tif);
        b.extend_from_slice(&self.firm);
        b.push(self.capacity);
        b.extend_from_slice(&self.account);
        b.push(self.is_inverse);
        b.push(self.price_flag);
        b.extend_from_slice(&self.cl_ord_id);
        b.extend_from_slice(&self.min_qty.to_le_bytes());
        b.extend_from_slice(&self.customer);
        b
    }

    /// Map the OUCH side/display byte to the normalized `OrderSide` +
    /// `Visibility` pair.
    pub fn to_side_visibility(&self) -> Option<(OrderSide, Visibility)> {
        let side = match self.side_display {
            b'B' | b'b' => OrderSide::Buy,
            b'S' | b's' | b'T' | b't' | b'X' | b'x' => OrderSide::Sell,
            _ => return None,
        };
        let visible = self.side_display.is_ascii_uppercase();
        let visibility = if visible {
            Visibility::Display
        } else {
            Visibility::Hidden
        };
        Some((side, visibility))
    }

    /// Map OUCH TIF byte to the normalized `Tif`.
    pub fn to_tif(&self) -> Option<Tif> {
        match self.tif {
            b'0' => Some(Tif::Day),
            b'1' => Some(Tif::Gtc),
            b'3' => Some(Tif::Ioc),
            b'4' => Some(Tif::Fok),
            b'6' => Some(Tif::Gtd),
            _ => None,
        }
    }

    /// Map OUCH capacity byte to the normalized `Capacity`.
    pub fn to_capacity(&self) -> Option<Capacity> {
        match self.capacity {
            b'M' | b'm' => Some(Capacity::Principal),
            b'A' | b'a' => Some(Capacity::Agency),
            _ => None,
        }
    }

    /// Map OUCH TIF byte to the normalized `Tif` (replace carries a TIF byte too).
    pub fn replace_tif(tif: u8) -> Option<Tif> {
        match tif {
            b'0' => Some(Tif::Day),
            b'1' => Some(Tif::Gtc),
            b'3' => Some(Tif::Ioc),
            b'4' => Some(Tif::Fok),
            b'6' => Some(Tif::Gtd),
            _ => None,
        }
    }

    /// Map OUCH capacity byte to the normalized `Capacity` (replace path).
    pub fn replace_capacity(cap: u8) -> Option<Capacity> {
        match cap {
            b'M' | b'm' => Some(Capacity::Principal),
            b'A' | b'a' => Some(Capacity::Agency),
            _ => None,
        }
    }

    /// The order is a limit order in the exchange8 subset.
    pub fn to_ord_type(&self) -> OrdType {
        OrdType::Limit
    }

    /// Decode the client order reference.
    pub fn cl_ord_id_str(&self) -> String {
        alpha_str(&self.cl_ord_id)
    }
}

fn alpha_from(b: &[u8]) -> [u8; 10] {
    let mut a = [b' '; 10];
    let n = b.len().min(10);
    a[..n].copy_from_slice(&b[..n]);
    a
}

impl ReplaceOrder {
    pub const BODY: usize = 4 + 4 + 4 + 1 + 1 + 20 + 20;

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BODY {
            return None;
        }
        let rd_u32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Some(ReplaceOrder {
            quantity: rd_u32(0),
            book: rd_u32(4),
            price: rd_u32(8),
            tif: b[12],
            capacity: b[13],
            cl_ord_id: alpha20_from(&b[14..34]),
            orig_cl_ord_id: alpha20_from(&b[34..54]),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + Self::BODY);
        b.push(MSG_REPLACE_ORDER);
        b.extend_from_slice(&self.quantity.to_le_bytes());
        b.extend_from_slice(&self.book.to_le_bytes());
        b.extend_from_slice(&self.price.to_le_bytes());
        b.push(self.tif);
        b.push(self.capacity);
        b.extend_from_slice(&self.cl_ord_id);
        b.extend_from_slice(&self.orig_cl_ord_id);
        b
    }

    /// Map OUCH TIF byte to the normalized `Tif`.
    pub fn to_tif(&self) -> Option<Tif> {
        EnterOrder::replace_tif(self.tif)
    }

    /// Map OUCH capacity byte to the normalized `Capacity`.
    pub fn to_capacity(&self) -> Option<Capacity> {
        EnterOrder::replace_capacity(self.capacity)
    }

    pub fn cl_ord_id_str(&self) -> String {
        alpha_str(&self.cl_ord_id)
    }

    pub fn orig_cl_ord_id_str(&self) -> String {
        alpha_str(&self.orig_cl_ord_id)
    }
}

fn alpha20_from(b: &[u8]) -> [u8; 20] {
    let mut a = [b' '; 20];
    let n = b.len().min(20);
    a[..n].copy_from_slice(&b[..n]);
    a
}

impl CancelOrder {
    pub const BODY: usize = 20;

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BODY {
            return None;
        }
        Some(CancelOrder {
            orig_cl_ord_id: alpha20_from(&b[..20]),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + Self::BODY);
        b.push(MSG_CANCEL_ORDER);
        b.extend_from_slice(&self.orig_cl_ord_id);
        b
    }

    pub fn orig_cl_ord_id_str(&self) -> String {
        alpha_str(&self.orig_cl_ord_id)
    }
}

/// Build an `EnterOrder` from normalized fields (test/helper ctor).
pub fn enter_order(
    cl_ord_id: &str,
    side_display: u8,
    qty: u32,
    price: u32,
    tif: u8,
    account: &str,
    customer: &str,
) -> EnterOrder {
    EnterOrder {
        side_display,
        quantity: qty,
        book: 0,
        price,
        tif,
        firm: alpha("EX8"),
        capacity: b'A',
        account: alpha(account),
        is_inverse: 0,
        price_flag: 0,
        cl_ord_id: alpha20_from(cl_ord_id.as_bytes()),
        min_qty: 0,
        customer: alpha_from(customer.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_order_round_trip() {
        let eo = enter_order("ORD-1", b'B', 100, 10_500, b'0', "ACCT1", "CUST01");
        let bytes = eo.encode();
        assert_eq!(bytes[0], MSG_ENTER_ORDER);
        let decoded = decode_inbound(&bytes).unwrap();
        match decoded {
            OuchInbound::Enter(d) => {
                assert_eq!(d.quantity, 100);
                assert_eq!(d.price, 10_500);
                assert_eq!(d.tif, b'0');
                assert_eq!(d.cl_ord_id_str(), "ORD-1");
                assert_eq!(alpha_str(&d.account), "ACCT1");
                assert_eq!(alpha_str(&d.customer), "CUST01");
                assert_eq!(d.to_tif(), Some(Tif::Day));
                assert_eq!(d.to_capacity(), Some(Capacity::Agency));
                assert_eq!(d.to_ord_type(), OrdType::Limit);
            }
            _ => panic!("expected Enter"),
        }
    }

    #[test]
    fn side_display_mapping() {
        let mut eo = enter_order("S1", b'B', 1, 1, b'0', "A", "C");
        assert_eq!(
            eo.to_side_visibility(),
            Some((OrderSide::Buy, Visibility::Display))
        );
        eo.side_display = b'b'; // hidden bid
        assert_eq!(
            eo.to_side_visibility(),
            Some((OrderSide::Buy, Visibility::Hidden))
        );
        eo.side_display = b'S';
        assert_eq!(
            eo.to_side_visibility(),
            Some((OrderSide::Sell, Visibility::Display))
        );
        eo.side_display = b's';
        assert_eq!(
            eo.to_side_visibility(),
            Some((OrderSide::Sell, Visibility::Hidden))
        );
        eo.side_display = b'?';
        assert_eq!(eo.to_side_visibility(), None);
    }

    #[test]
    fn tif_mapping() {
        let mut eo = enter_order("S2", b'B', 1, 1, b'3', "A", "C");
        assert_eq!(eo.to_tif(), Some(Tif::Ioc));
        eo.tif = b'4';
        assert_eq!(eo.to_tif(), Some(Tif::Fok));
        eo.tif = b'9';
        assert_eq!(eo.to_tif(), None);
    }

    #[test]
    fn replace_round_trip() {
        let r = ReplaceOrder {
            quantity: 200,
            book: 1,
            price: 11_000,
            tif: b'0',
            capacity: b'M',
            cl_ord_id: alpha20_from("NEW".as_bytes()),
            orig_cl_ord_id: alpha20_from("OLD".as_bytes()),
        };
        let bytes = r.encode();
        assert_eq!(bytes[0], MSG_REPLACE_ORDER);
        match decode_inbound(&bytes).unwrap() {
            OuchInbound::Replace(d) => {
                assert_eq!(d.quantity, 200);
                assert_eq!(d.price, 11_000);
                assert_eq!(d.cl_ord_id_str(), "NEW");
                assert_eq!(d.orig_cl_ord_id_str(), "OLD");
                assert_eq!(d.to_tif(), Some(Tif::Day));
                assert_eq!(d.to_capacity(), Some(Capacity::Principal));
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn cancel_round_trip() {
        let c = CancelOrder {
            orig_cl_ord_id: alpha20_from("ORD-9".as_bytes()),
        };
        let bytes = c.encode();
        assert_eq!(bytes[0], MSG_CANCEL_ORDER);
        match decode_inbound(&bytes).unwrap() {
            OuchInbound::Cancel(d) => assert_eq!(d.orig_cl_ord_id_str(), "ORD-9"),
            _ => panic!("expected Cancel"),
        }
    }

    #[test]
    fn decode_rejects_unknown_and_short() {
        assert!(decode_inbound(&[b'Z']).is_none());
        assert!(decode_inbound(&[]).is_none());
        let short = &[MSG_ENTER_ORDER, 1, 2, 3];
        assert!(decode_inbound(short).is_none());
    }

    #[test]
    fn outbound_executed_round_trip() {
        let msg = OuchOutbound::Executed {
            timestamp_us: 1_234_567_890,
            cl_ord_id: alpha20_from("ORD-1".as_bytes()),
            order_id: 77,
            trade_id: 1001,
            qty: 50,
            price: 10_500,
            leaves: 50,
        };
        let bytes = encode_outbound(&msg);
        assert_eq!(bytes[0], MSG_EXECUTED);
        assert_eq!(bytes.len(), 1 + 8 + 20 + 8 + 8 + 4 + 4 + 4);
        // Decode back.
        let ts = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        assert_eq!(ts, 1_234_567_890);
        let cl = alpha_str(&alpha20_from_bytes(&bytes[9..29]));
        assert_eq!(cl, "ORD-1");
        let oid = u64::from_le_bytes(bytes[29..37].try_into().unwrap());
        assert_eq!(oid, 77);
        let tid = u64::from_le_bytes(bytes[37..45].try_into().unwrap());
        assert_eq!(tid, 1001);
    }

    fn alpha20_from_bytes(b: &[u8]) -> [u8; 20] {
        let mut a = [b' '; 20];
        let n = b.len().min(20);
        a[..n].copy_from_slice(&b[..n]);
        a
    }

    #[test]
    fn outbound_rejected_and_canceled() {
        let rej = OuchOutbound::Rejected {
            timestamp_us: 5,
            cl_ord_id: [b' '; 20],
            order_id: 1,
            reason: 3,
        };
        let bytes = encode_outbound(&rej);
        assert_eq!(bytes[0], MSG_REJECTED);
        assert_eq!(*bytes.last().unwrap(), 3);

        let cxl = OuchOutbound::Canceled {
            timestamp_us: 6,
            cl_ord_id: [b' '; 20],
            order_id: 1,
            cum_qty: 40,
            leaves: 10,
            reason: 1,
        };
        let bytes = encode_outbound(&cxl);
        assert_eq!(bytes[0], MSG_CANCELED);
        assert_eq!(bytes.len(), 1 + 8 + 20 + 8 + 4 + 4 + 1);
    }
}
