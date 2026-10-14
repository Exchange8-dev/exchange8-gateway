// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Ex8:Gateway FIX ExecutionReport conversion.
//!
//! Converts ME lifecycle events (the outbound wire-spec messages) into FIX
//! ExecutionReport (35=8) field selections: ExecType (150), OrdStatus (39),
//! LeavesQty (151), CumQty (14), LastQty (32), LastPx (31) mapping.
//!
//! The ME event → ExecType/OrdStatus matrix:
//!
//! | ME event          | ExecType (150) | OrdStatus (39) |
//! |-------------------|----------------|----------------|
//! | OrderAccepted     | 0 (New)        | 0 (New)        |
//! | OrderBooked       | 0 (New)        | 0 (New)        |
//! | OrderExecuted     | F (Trade)      | 1/2 (Partial/Filled) |
//! | OrderModified     | 5 (Replace)    | 0/5 (New/Replaced) |
//! | OrderKilled       | 4 (Canceled)   | 4 (Canceled)   |
//! | TransactionRejected | 8 (Rejected) | 8 (Rejected)  |
//! | OrderRepriced     | 0 (New)        | 0 (New)        |
//!
//! Pure conversion; the shell wraps the fields into the FIX session
//! transport (tags 8/9/35/10 framing, MsgSeqNum, PossDup handling).
//!
//! Design: `design/sentin8-exchange8-oms-technical-design.md`
//! (gateway execution-report mapping),
//! `design/sentin8-exchange8-connectivity-operations-technical-design.md` §2.

use exchange8::contracts::events::{
    OrderAccepted, OrderBooked, OrderExecuted, OrderKilled, OrderModified, OrderRepriced,
    TransactionRejected,
};

/// FIX ExecType (150) codes.
pub const EXEC_TYPE_NEW: char = '0';
pub const EXEC_TYPE_TRADE: char = 'F';
pub const EXEC_TYPE_CANCELED: char = '4';
pub const EXEC_TYPE_REJECTED: char = '8';
pub const EXEC_TYPE_REPLACE: char = '5';

/// FIX OrdStatus (39) codes.
pub const ORD_STATUS_NEW: char = '0';
pub const ORD_STATUS_PARTIAL: char = '1';
pub const ORD_STATUS_FILLED: char = '2';
pub const ORD_STATUS_CANCELED: char = '4';
pub const ORD_STATUS_REJECTED: char = '8';
pub const ORD_STATUS_REPLACED: char = '5';

/// One converted ExecutionReport field set (tag/value pairs the shell
/// serializes into the FIX message body).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecReport {
    /// ExecType (150).
    pub exec_type: char,
    /// OrdStatus (39).
    pub ord_status: char,
    /// OrderID (37) — ME order id.
    pub order_id: u64,
    /// Instrument (48) — ME instrument id (mapped to symbol by the shell).
    pub instrument_id: u32,
    /// CumQty (14) — total executed.
    pub cum_qty: u64,
    /// LeavesQty (151) — remaining.
    pub leaves_qty: u64,
    /// LastQty (32) — this fill's qty (Trade only).
    pub last_qty: Option<u64>,
    /// LastPx (31) — this fill's price (Trade only).
    pub last_px: Option<i128>,
    /// TradeID (19) (Trade only).
    pub trade_id: Option<u64>,
    /// OrdRejReason (103) — reject reason code (Rejected only).
    pub reject_reason: Option<u16>,
    /// Text (58) — human context (canceled/rejected reason).
    pub text: Option<String>,
}

impl ExecReport {
    /// Render as a FIX body fragment (tags 150/39/37/48/14/151/... in tag
    /// order) — the shell adds the standard header/trailer.
    pub fn to_fix_body(&self) -> String {
        let mut parts = vec![
            format!("37={}", self.order_id),
            format!("48={}", self.instrument_id),
            format!("150={}", self.exec_type),
            format!("39={}", self.ord_status),
            format!("14={}", self.cum_qty),
            format!("151={}", self.leaves_qty),
        ];
        if let Some(lq) = self.last_qty {
            parts.push(format!("32={}", lq));
        }
        if let Some(lp) = self.last_px {
            parts.push(format!("31={}", lp));
        }
        if let Some(t) = self.trade_id {
            parts.push(format!("19={}", t));
        }
        if let Some(r) = self.reject_reason {
            parts.push(format!("103={}", r));
        }
        if let Some(t) = &self.text {
            parts.push(format!("58={}", t));
        }
        parts.join("\u{1}")
    }
}

/// OrderAccepted → ExecType=0 New, OrdStatus=0 New.
pub fn from_accepted(e: &OrderAccepted) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_NEW,
        ord_status: ORD_STATUS_NEW,
        order_id: e.order_id,
        instrument_id: e.instrument_id,
        cum_qty: 0,
        leaves_qty: 0, // filled by the shell from the order state cache
        last_qty: None,
        last_px: None,
        trade_id: None,
        reject_reason: None,
        text: None,
    }
}

/// OrderBooked → ExecType=0 New, OrdStatus=0 New (order is on the book).
pub fn from_booked(e: &OrderBooked) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_NEW,
        ord_status: ORD_STATUS_NEW,
        order_id: e.order_id,
        instrument_id: e.instrument_id,
        cum_qty: 0,
        leaves_qty: e.volume.raw,
        last_qty: None,
        last_px: None,
        trade_id: None,
        reject_reason: None,
        text: None,
    }
}

/// OrderExecuted → ExecType=F Trade; OrdStatus by remaining volume
/// (0 remaining → Filled, else Partial).
pub fn from_executed(e: &OrderExecuted) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_TRADE,
        ord_status: if e.remaining_volume.raw == 0 {
            ORD_STATUS_FILLED
        } else {
            ORD_STATUS_PARTIAL
        },
        order_id: e.order_id,
        instrument_id: e.instrument_id,
        // CumQty is derived by the shell (order state cache); the event
        // carries remaining — cum = shell-tracked total.
        cum_qty: 0,
        leaves_qty: e.remaining_volume.raw,
        last_qty: Some(e.qty.raw),
        last_px: Some(e.price.raw),
        trade_id: Some(e.trade_id),
        reject_reason: None,
        text: None,
    }
}

/// OrderModified → ExecType=5 Replace; OrdStatus=5 Replaced (still live) or
/// 0 New per the client's view — Replaced carries the new leaves.
pub fn from_modified(e: &OrderModified) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_REPLACE,
        ord_status: ORD_STATUS_REPLACED,
        order_id: e.new_order_id,
        instrument_id: e.instrument_id,
        cum_qty: 0,
        leaves_qty: e.new_volume.raw,
        last_qty: None,
        last_px: Some(e.new_price.raw),
        trade_id: None,
        reject_reason: None,
        text: None,
    }
}

/// OrderKilled → ExecType=4 Canceled, OrdStatus=4 Canceled.
pub fn from_killed(e: &OrderKilled) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_CANCELED,
        ord_status: ORD_STATUS_CANCELED,
        order_id: e.order_id,
        instrument_id: e.instrument_id,
        cum_qty: 0,
        leaves_qty: 0,
        last_qty: None,
        last_px: None,
        trade_id: None,
        reject_reason: None,
        text: Some(format!("{:?}", e.reason)),
    }
}

/// TransactionRejected → ExecType=8 Rejected, OrdStatus=8 Rejected; carries
/// OrdRejReason (103).
pub fn from_rejected(e: &TransactionRejected) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_REJECTED,
        ord_status: ORD_STATUS_REJECTED,
        order_id: e.order_id,
        instrument_id: e.instrument_id,
        cum_qty: 0,
        leaves_qty: 0,
        last_qty: None,
        last_px: None,
        trade_id: None,
        reject_reason: Some(e.reason as u16),
        text: Some(format!("{:?} on {:?}", e.reason, e.rejected_op)),
    }
}

/// OrderRepriced → ExecType=0 New with the new price (the order remains
/// live at a different price).
pub fn from_repriced(e: &OrderRepriced) -> ExecReport {
    ExecReport {
        exec_type: EXEC_TYPE_NEW,
        ord_status: ORD_STATUS_NEW,
        order_id: e.order_id,
        instrument_id: e.instrument_id,
        cum_qty: 0,
        leaves_qty: 0, // unchanged by repricing — shell fills from cache
        last_px: Some(e.price.raw),
        last_qty: None,
        trade_id: None,
        reject_reason: None,
        text: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exchange8::contracts::enums::{KillReason, MeRejectReason};
    use exchange8::contracts::events::RejectedOp;
    use exchange8::fixed::Price;

    const fn px(raw: i128) -> Price {
        Price::equity(raw)
    }

    #[test]
    fn accepted_maps_new() {
        let e = OrderAccepted {
            order_id: 10,
            instrument_id: 3,
            connection_id: 1,
        };
        let r = from_accepted(&e);
        assert_eq!(r.exec_type, '0');
        assert_eq!(r.ord_status, '0');
        assert_eq!(r.order_id, 10);
    }

    #[test]
    fn booked_maps_new_with_leaves() {
        let e = OrderBooked {
            price: px(10_000),
            order_id: 10,
            sub_order_id: 0,
            instrument_id: 3,
            volume: exchange8::fixed::Qty::units(500),
            connection_id: 1,
        };
        let r = from_booked(&e);
        assert_eq!(r.exec_type, '0');
        assert_eq!(r.leaves_qty, 500);
        assert!(r.last_px.is_none());
    }

    fn executed(remaining: u64) -> OrderExecuted {
        OrderExecuted {
            trade_id: 99,
            ts_us: 1,
            price: px(10_500),
            order_id: 10,
            sub_order_id: 0,
            cp_order_id: 11,
            cp_sub_order_id: 0,
            instrument_id: 3,
            qty: exchange8::fixed::Qty::units(100),
            remaining_volume: exchange8::fixed::Qty::units(remaining),
            connection_id: 1,
            counterparty_id: None,
            book_id: 0,
            liquidity: exchange8::contracts::enums::Liquidity::Removed,
            side: exchange8::contracts::enums::Side::Bid,
            lot_type: exchange8::contracts::enums::LotType::Board,
            last_mkt: *b"XL8M",
            principal_trade: false,
            wash_trade: false,
            midpoint_charge: false,
        }
    }

    #[test]
    fn executed_partial_vs_filled() {
        let e = executed(400);
        let r = from_executed(&e);
        assert_eq!(r.exec_type, 'F');
        assert_eq!(r.ord_status, '1'); // partial
        assert_eq!(r.last_qty, Some(100));
        assert_eq!(r.last_px, Some(10_500));
        assert_eq!(r.trade_id, Some(99));

        let e2 = executed(0);
        let r2 = from_executed(&e2);
        assert_eq!(r2.ord_status, '2'); // filled
    }

    #[test]
    fn modified_maps_replace() {
        let e = OrderModified {
            new_price: px(10_200),
            order_id: 10,
            sub_order_id: 0,
            instrument_id: 3,
            new_volume: exchange8::fixed::Qty::units(450),
            new_order_id: 12,
            connection_id: 1,
            side: exchange8::contracts::enums::Side::Bid,
            new_max_floor: exchange8::fixed::Qty::units(0),
        };
        let r = from_modified(&e);
        assert_eq!(r.exec_type, '5');
        assert_eq!(r.ord_status, '5');
        assert_eq!(r.order_id, 12); // new order id after modify
        assert_eq!(r.leaves_qty, 450);
    }

    #[test]
    fn killed_maps_canceled() {
        let e = OrderKilled {
            order_id: 10,
            sub_order_id: 0,
            instrument_id: 3,
            connection_id: 1,
            reason: KillReason::ClientRequest,
        };
        let r = from_killed(&e);
        assert_eq!(r.exec_type, '4');
        assert_eq!(r.ord_status, '4');
        assert!(r.text.is_some());
    }

    #[test]
    fn rejected_maps_ordrejreason() {
        let e = TransactionRejected {
            order_id: 10,
            instrument_id: 3,
            connection_id: 1,
            reason: MeRejectReason::InstrumentHalted,
            rejected_op: RejectedOp::Add,
        };
        let r = from_rejected(&e);
        assert_eq!(r.exec_type, '8');
        assert_eq!(r.ord_status, '8');
        assert!(r.reject_reason.is_some());
    }

    #[test]
    fn repriced_maps_new_with_price() {
        let e = OrderRepriced {
            price: px(9_800),
            order_id: 10,
            sub_order_id: 0,
            instrument_id: 3,
            connection_id: 1,
            reason: KillReason::PriceProtection,
        };
        let r = from_repriced(&e);
        assert_eq!(r.exec_type, '0');
        assert_eq!(r.last_px, Some(9_800));
    }

    #[test]
    fn fix_body_fragment_tags() {
        let r = ExecReport {
            exec_type: 'F',
            ord_status: '1',
            order_id: 10,
            instrument_id: 3,
            cum_qty: 100,
            leaves_qty: 400,
            last_qty: Some(100),
            last_px: Some(10_500),
            trade_id: Some(99),
            reject_reason: None,
            text: None,
        };
        let body = r.to_fix_body();
        assert!(body.contains("150=F"));
        assert!(body.contains("39=1"));
        assert!(body.contains("32=100"));
        assert!(body.contains("31=10500"));
        assert!(body.contains("19=99"));
        assert!(body.contains("37=10"));
        // SOH separator present between tags.
        assert!(body.contains('\u{1}'));
    }
}
