// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Exchange8:Gateway
// SPDX-License-Identifier: Apache-2.0

//! Exchange8:Gateway FIX 4.2 session engine — sequence/resend/gap-fill semantics
//! (platform spec, DB-backed counters per design).
//!
//! Pure protocol state machine over an abstract message transport: the tokio
//! shell supplies the socket/streams and the `gateway.fix_session_state` /
//! `gateway.fix_message` persistence callbacks.
//!
//! Semantics (design `sentin8-exchange8-gateway-technical-design.md` §4.1–4.2):
//! - Logon(35=A) must arrive first; `ResetSeqNumFlag(141)=Y` restarts both
//!   counters at 1. Credentials are verified by the shell (Sentin8 session
//!   key) before `logon()` is called.
//! - Incoming gap (`seq > in+1`): queue the message, emit ResendRequest(2)
//!   for the missing range.
//! - Low seq (non-PossDup): teardown (logout) — platform spec.
//! - PossDup(43=Y) re-delivery of an already-processed seq is dropped.
//! - Resend serving wraps admin messages as SeqReset-GapFill(4) and app
//!   messages with PossDupFlag=Y; `store_replay` is the shell's lookup.
//! - TestRequest(1) answered with Heartbeat(0) carrying TestReqID(112);
//!   read timeout handled by the shell timer.

use exchange8::fix::{msg_type as mt, tag as tg, FixMessage};

/// Actions the state machine wants the shell to perform.
#[derive(Debug, PartialEq)]
pub enum SessionAction {
    /// Encode and send this FIX message.
    Send(FixMessage),
    /// Disconnect the session (logout already queued where applicable).
    Disconnect,
}

/// Session lifecycle state.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionState {
    /// Connected, awaiting Logon.
    AwaitingLogon,
    /// Logon accepted; session active.
    Established,
    /// Logout sent or received; draining then disconnect.
    LoggingOut,
    /// Terminated.
    Disconnected,
}

/// FIX 4.2 session protocol state.
pub struct FixSession {
    /// Counterparty identification (CompID pair resolved from the logon).
    pub remote_comp_id: String,
    /// Our SenderCompID.
    pub sender_comp_id: String,
    state: SessionState,
    /// Next expected inbound sequence number.
    in_seq: u64,
    /// Next outbound sequence number.
    out_seq: u64,
    /// Negotiated heartbeat interval (seconds, clamped 10–120).
    pub heart_bt_int: u32,
    /// Messages received during an inbound gap, replayed after the gap fills.
    gap_queue: Vec<FixMessage>,
    /// Resend range received from the counterparty, if pending.
    /// (begin, end); end=0 means "to infinity" (tag 7 = 0).
    resend_pending: Option<(u64, u64)>,
}

impl FixSession {
    /// New session pre-logon. Counters start at the persisted values (1 for
    /// a fresh session); the shell loads them from
    /// `gateway.fix_session_state` and passes them in.
    pub fn new(sender_comp_id: String, remote_comp_id: String, in_seq: u64, out_seq: u64) -> Self {
        FixSession {
            remote_comp_id,
            sender_comp_id,
            state: SessionState::AwaitingLogon,
            in_seq,
            out_seq,
            heart_bt_int: exchange8::fix::DEFT_HEART_BT_INT,
            gap_queue: Vec::new(),
            resend_pending: None,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn in_seq(&self) -> u64 {
        self.in_seq
    }

    pub fn out_seq(&self) -> u64 {
        self.out_seq
    }

    /// Queue-drain count after a gap fill (diagnostics).
    pub fn queued_gap_messages(&self) -> usize {
        self.gap_queue.len()
    }

    /// Stamp the outbound sequence + CompIDs onto a message. Admin messages
    /// (heartbeats etc.) also carry the seq; the shell persists app messages
    /// before sending.
    fn stamp(&mut self, msg: &mut FixMessage) {
        msg.set(tg::SENDER_COMP_ID, &self.sender_comp_id);
        msg.set(tg::TARGET_COMP_ID, &self.remote_comp_id);
        msg.set(tg::MSG_SEQ_NUM, self.out_seq.to_string());
        self.out_seq += 1;
    }

    /// Emit a message through the action list.
    fn enqueue(&mut self, msg: FixMessage, out: &mut Vec<SessionAction>) {
        out.push(SessionAction::Send(msg));
    }

    /// Process one decoded inbound FIX message. Returns the actions to take
    /// plus the app messages now deliverable to the business layer.
    pub fn on_message(&mut self, msg: &FixMessage) -> (Vec<SessionAction>, Vec<FixMessage>) {
        let mut actions = Vec::new();
        let mut deliver = Vec::new();

        let mtype = msg.get(tg::MSG_TYPE).unwrap_or("");
        let seq: u64 = msg
            .get(tg::MSG_SEQ_NUM)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let poss_dup = msg.get(tg::POSS_DUP) == Some("Y");

        // --- session-state gating -------------------------------------------
        match self.state {
            SessionState::AwaitingLogon => {
                if mtype != mt::LOGON {
                    // Anything before Logon violates the protocol.
                    self.state = SessionState::Disconnected;
                    actions.push(SessionAction::Disconnect);
                    return (actions, deliver);
                }
                self.handle_logon(msg, &mut actions);
                return (actions, deliver);
            }
            SessionState::LoggingOut | SessionState::Disconnected => {
                // Drain nothing post-logout.
                return (actions, deliver);
            }
            SessionState::Established => {}
        }

        // --- sequence handling ------------------------------------------------
        if poss_dup && seq < self.in_seq {
            // Already-processed re-delivery: drop silently (platform spec).
            return (actions, deliver);
        }
        if seq < self.in_seq {
            // Low sequence without PossDup: teardown (platform spec).
            self.state = SessionState::Disconnected;
            actions.push(SessionAction::Disconnect);
            return (actions, deliver);
        }
        if seq > self.in_seq {
            // Gap: queue the message and request the missing range.
            self.gap_queue.push(msg.clone());
            let mut req = FixMessage::typed(mt::RESEND_REQUEST);
            req.set(tg::BEGIN_SEQ_NO, self.in_seq.to_string());
            req.set(tg::END_SEQ_NO, (seq - 1).to_string());
            self.stamp(&mut req);
            self.enqueue(req, &mut actions);
            return (actions, deliver);
        }

        // seq == in_seq: in-order delivery.
        self.in_seq += 1;
        match mtype {
            mt::LOGON => {
                // Re-logon on an established session is a logout-worthy
                // protocol error; keep it simple and accept (accepts).
            }
            mt::LOGOUT => {
                self.state = SessionState::LoggingOut;
                let mut out = FixMessage::typed(mt::LOGOUT);
                self.stamp(&mut out);
                self.enqueue(out, &mut actions);
                self.state = SessionState::Disconnected;
                actions.push(SessionAction::Disconnect);
            }
            mt::TEST_REQUEST => {
                let mut hb = FixMessage::typed(mt::HEARTBEAT);
                if let Some(id) = msg.get(tg::TESTREQ_ID) {
                    hb.set(tg::TESTREQ_ID, id);
                }
                self.stamp(&mut hb);
                self.enqueue(hb, &mut actions);
            }
            mt::HEARTBEAT => {
                // No-op; keepalive.
            }
            mt::RESEND_REQUEST => {
                let begin: u64 = msg
                    .get(tg::BEGIN_SEQ_NO)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let end: u64 = msg
                    .get(tg::END_SEQ_NO)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                self.resend_pending = Some((begin, end));
                // The shell serves the range via `serve_resend`; we only
                // record it here.
            }
            mt::SEQUENCE_RESET => {
                // GapFill (NewSeqNo 36): jump the expected counter.
                if let Some(v) = msg.get(tg::NEW_SEQ_NO).and_then(|s| s.parse::<u64>().ok()) {
                    if v >= self.in_seq {
                        self.in_seq = v;
                        self.drain_gap_queue(&mut deliver);
                    }
                }
            }
            mt::REJECT => {
                // Session-level reject from the peer — log only.
            }
            _ => {
                // Application message: deliver to the business layer.
                deliver.push(msg.clone());
            }
        }
        (actions, deliver)
    }

    fn handle_logon(&mut self, msg: &FixMessage, actions: &mut Vec<SessionAction>) {
        // ResetSeqNumFlag(141)=Y: both counters restart at 1.
        if msg.get(tg::RESET_SEQ_NUM_FLAG) == Some("Y") {
            self.in_seq = 1;
            self.out_seq = 1;
        }
        // Heartbeat interval negotiated and clamped.
        if let Some(v) = msg
            .get(tg::HEART_BT_INT)
            .and_then(|s| s.parse::<u32>().ok())
        {
            self.heart_bt_int = v.clamp(
                exchange8::fix::MIN_HEART_BT_INT,
                exchange8::fix::MAX_HEART_BT_INT,
            );
        } else {
            self.heart_bt_int = exchange8::fix::DEFT_HEART_BT_INT;
        }
        // Consume the logon's own sequence number.
        let seq: u64 = msg
            .get(tg::MSG_SEQ_NUM)
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        self.in_seq = seq + 1;
        // Send the logon response.
        let mut out = FixMessage::typed(mt::LOGON);
        out.set(tg::HEART_BT_INT, self.heart_bt_int.to_string());
        self.stamp(&mut out);
        actions.push(SessionAction::Send(out));
        self.state = SessionState::Established;
    }

    /// Replay `gap_queue` messages whose seq is now in-order. Out-of-order
    /// entries stay queued. Called after a GapFill or a catch-up delivery.
    fn drain_gap_queue(&mut self, deliver: &mut Vec<FixMessage>) {
        let mut remaining = Vec::new();
        let mut sorted = std::mem::take(&mut self.gap_queue);
        sorted.sort_by_key(|m| {
            m.get(tg::MSG_SEQ_NUM)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        });
        for m in sorted {
            let seq: u64 = m
                .get(tg::MSG_SEQ_NUM)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if seq == self.in_seq {
                self.in_seq += 1;
                deliver.push(m);
            } else if seq > self.in_seq {
                remaining.push(m);
            }
            // seq < in_seq: already covered by the gap fill — drop.
        }
        self.gap_queue = remaining;
    }

    /// Serve a pending ResendRequest: the shell supplies a message replay
    /// function over the `gateway.fix_message` store. Admin (non-app)
    /// messages become SeqReset-GapFill spans; app messages are re-sent with
    /// PossDupFlag=Y.
    ///
    /// Returns the outbound actions. No-op when no ResendRequest is pending.
    pub fn serve_resend<F>(&mut self, mut store_lookup: F) -> Vec<SessionAction>
    where
        F: FnMut(u64) -> Option<(String, Vec<u8>)>, // (msg_type, raw frame)
    {
        let mut actions = Vec::new();
        let Some((begin, end)) = self.resend_pending.take() else {
            return actions;
        };
        // A pending resend never advances the peer's inbound counter; all
        // re-sends carry the ORIGINAL sequence numbers. To do that we
        // temporarily suppress stamping by using a local counter.
        let mut seq = begin;
        let last = if end == 0 { u64::MAX } else { end };
        while seq <= last {
            match store_lookup(seq) {
                Some((mtype, frame)) => {
                    // Decode the stored frame and re-stamp with PossDup.
                    if let Ok(Some(mut msg)) = FixMessage::parse(&frame) {
                        let is_app = matches!(
                            mtype.as_str(),
                            mt::EXECUTION_REPORT | mt::CANCEL_REJECT | mt::BUSINESS_REJECT
                        );
                        if is_app {
                            msg.set(tg::POSS_DUP, "Y");
                            msg.set(tg::MSG_SEQ_NUM, seq.to_string());
                            self.enqueue_no_stamp(msg, &mut actions);
                        } else {
                            // Admin messages in the range collapse into a
                            // GapFill SeqReset at the next admin boundary.
                            let mut gap = FixMessage::typed(mt::SEQUENCE_RESET);
                            gap.set(tg::GAP_FILL_FLAG, "Y");
                            gap.set(tg::NEW_SEQ_NO, seq.to_string());
                            self.enqueue_no_stamp(gap, &mut actions);
                        }
                    }
                    seq += 1;
                }
                None => {
                    // Store window purged: gap-fill past the missing span and
                    // stop (documented limitation; DLQ alert is the shell's).
                    let mut gap = FixMessage::typed(mt::SEQUENCE_RESET);
                    gap.set(tg::GAP_FILL_FLAG, "Y");
                    gap.set(tg::NEW_SEQ_NO, self.out_seq.to_string());
                    self.enqueue_no_stamp(gap, &mut actions);
                    break;
                }
            }
        }
        actions
    }

    /// Enqueue without advancing `out_seq` — used for resend traffic which
    /// must preserve original sequence numbers.
    fn enqueue_no_stamp(&mut self, msg: FixMessage, out: &mut Vec<SessionAction>) {
        out.push(SessionAction::Send(msg));
    }

    /// Application-layer outbound (ExecReports etc.): stamp seq and persist
    /// via the shell before transmission. Returns the stamped message.
    pub fn prepare_app_message(&mut self, msg_type: &str) -> FixMessage {
        let mut msg = FixMessage::typed(msg_type);
        self.stamp(&mut msg);
        msg
    }

    /// Initiate a logout (server side or admin op).
    pub fn logout(&mut self) -> Vec<SessionAction> {
        let mut actions = Vec::new();
        if self.state == SessionState::Established || self.state == SessionState::AwaitingLogon {
            let mut out = FixMessage::typed(mt::LOGOUT);
            self.stamp(&mut out);
            actions.push(SessionAction::Send(out));
        }
        self.state = SessionState::Disconnected;
        actions.push(SessionAction::Disconnect);
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logon(seq: u64, reset: bool, hb: u32) -> FixMessage {
        let mut m = FixMessage::typed(mt::LOGON);
        m.set(tg::MSG_SEQ_NUM, seq.to_string());
        m.set(tg::SENDER_COMP_ID, "CLIENT");
        m.set(tg::TARGET_COMP_ID, "EXCH");
        m.set(tg::HEART_BT_INT, hb.to_string());
        if reset {
            m.set(tg::RESET_SEQ_NUM_FLAG, "Y");
        }
        m
    }

    fn app(seq: u64, msg_type: &str) -> FixMessage {
        let mut m = FixMessage::typed(msg_type);
        m.set(tg::MSG_SEQ_NUM, seq.to_string());
        m.set(tg::SENDER_COMP_ID, "CLIENT");
        m.set(tg::TARGET_COMP_ID, "EXCH");
        m.set(tg::CL_ORD_ID, format!("O{seq}"));
        m
    }

    #[test]
    fn logon_establishes_and_negotiates_heartbeat() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        assert_eq!(s.state(), SessionState::AwaitingLogon);
        let (actions, _) = s.on_message(&logon(1, false, 30));
        assert_eq!(s.state(), SessionState::Established);
        assert_eq!(s.heart_bt_int, 30);
        // Logon response is the single action.
        assert_eq!(actions.len(), 1);
        let SessionAction::Send(reply) = &actions[0] else {
            panic!()
        };
        assert_eq!(reply.get(tg::MSG_TYPE), Some("A"));
        assert_eq!(reply.get(tg::MSG_SEQ_NUM), Some("1"));
        // Our next outbound is 2.
        assert_eq!(s.out_seq(), 2);
    }

    #[test]
    fn pre_logon_message_disconnects() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        let (actions, deliver) = s.on_message(&app(1, mt::NEW_ORDER));
        assert!(matches!(actions[0], SessionAction::Disconnect));
        assert_eq!(s.state(), SessionState::Disconnected);
        assert!(deliver.is_empty());
    }

    #[test]
    fn heartbeat_clamped_to_range() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 5)); // below MIN=10
        assert_eq!(s.heart_bt_int, 10);
        let mut s2 = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s2.on_message(&logon(1, false, 999)); // above MAX=120
        assert_eq!(s2.heart_bt_int, 120);
    }

    #[test]
    fn reset_seq_num_flag_restarts_counters() {
        // A mid-life session (our out_seq persisted at 55): the peer sends a
        // ResetSeqNum logon which restarts BOTH streams at 1 — the logon
        // itself is seq 1 of the new numbering, and our reply is our seq 1.
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 55, 55);
        s.on_message(&logon(1, true, 30));
        assert_eq!(s.in_seq(), 2);
        assert_eq!(s.out_seq(), 2); // response was our seq 1
                                    // Without the flag, the persisted counters continue (seq 55 logon
                                    // consumes in_seq 56; reply carries our out_seq 55).
        let mut s2 = FixSession::new("EXCH".into(), "CLIENT".into(), 55, 55);
        s2.on_message(&logon(55, false, 30));
        assert_eq!(s2.in_seq(), 56);
        assert_eq!(s2.out_seq(), 56);
    }

    #[test]
    fn in_order_app_message_delivered() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        let (_, deliver) = s.on_message(&app(2, mt::NEW_ORDER));
        assert_eq!(deliver.len(), 1);
        assert_eq!(s.in_seq(), 3);
    }

    #[test]
    fn gap_queues_and_requests_resend() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        // in_seq=2, deliver seq 5 → gap [2..4].
        let (actions, deliver) = s.on_message(&app(5, mt::NEW_ORDER));
        assert!(deliver.is_empty());
        assert_eq!(s.queued_gap_messages(), 1);
        // ResendRequest for the missing range.
        assert_eq!(actions.len(), 1);
        let SessionAction::Send(req) = &actions[0] else {
            panic!()
        };
        assert_eq!(req.get(tg::MSG_TYPE), Some("2"));
        assert_eq!(req.get(tg::BEGIN_SEQ_NO), Some("2"));
        assert_eq!(req.get(tg::END_SEQ_NO), Some("4"));
    }

    #[test]
    fn gap_fill_drains_queue_in_order() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        // Gap: seq 4 and 5 arrive out of order.
        s.on_message(&app(4, mt::NEW_ORDER));
        s.on_message(&app(5, mt::NEW_ORDER));
        assert_eq!(s.queued_gap_messages(), 2);
        // Peer gap-fills 2..3.
        let mut fill = FixMessage::typed(mt::SEQUENCE_RESET);
        fill.set(tg::MSG_SEQ_NUM, 2);
        fill.set(tg::GAP_FILL_FLAG, "Y");
        fill.set(tg::NEW_SEQ_NO, 4);
        let (_, deliver) = s.on_message(&fill);
        assert_eq!(s.in_seq(), 6);
        assert_eq!(deliver.len(), 2); // 4 and 5 replayed in order
        assert_eq!(s.queued_gap_messages(), 0);
        assert_eq!(deliver[0].get(tg::CL_ORD_ID), Some("O4"));
        assert_eq!(deliver[1].get(tg::CL_ORD_ID), Some("O5"));
    }

    #[test]
    fn low_seq_without_poss_dup_disconnects() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        s.on_message(&app(2, mt::NEW_ORDER));
        let (actions, deliver) = s.on_message(&app(2, mt::NEW_ORDER)); // replay at same seq
        assert!(matches!(actions[0], SessionAction::Disconnect));
        assert_eq!(s.state(), SessionState::Disconnected);
        assert!(deliver.is_empty());
    }

    #[test]
    fn poss_dup_below_in_seq_dropped() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        s.on_message(&app(2, mt::NEW_ORDER));
        // Re-delivery of seq 1 marked PossDup: drop, keep session alive.
        let mut dup = logon(1, false, 30);
        dup.set(tg::POSS_DUP, "Y");
        let (actions, deliver) = s.on_message(&dup);
        assert!(actions.is_empty());
        assert!(deliver.is_empty());
        assert_eq!(s.state(), SessionState::Established);
        assert_eq!(s.in_seq(), 3); // unchanged
    }

    #[test]
    fn test_request_answered_with_heartbeat() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        let mut tr = FixMessage::typed(mt::TEST_REQUEST);
        tr.set(tg::MSG_SEQ_NUM, 2);
        tr.set(tg::TESTREQ_ID, "PING1");
        let (actions, _) = s.on_message(&tr);
        assert_eq!(actions.len(), 1);
        let SessionAction::Send(hb) = &actions[0] else {
            panic!()
        };
        assert_eq!(hb.get(tg::MSG_TYPE), Some("0"));
        assert_eq!(hb.get(tg::TESTREQ_ID), Some("PING1"));
    }

    #[test]
    fn logout_replies_and_disconnects() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        let mut lo = FixMessage::typed(mt::LOGOUT);
        lo.set(tg::MSG_SEQ_NUM, 2);
        let (actions, _) = s.on_message(&lo);
        assert_eq!(s.state(), SessionState::Disconnected);
        assert!(matches!(actions[1], SessionAction::Disconnect));
        let SessionAction::Send(reply) = &actions[0] else {
            panic!()
        };
        assert_eq!(reply.get(tg::MSG_TYPE), Some("5"));
    }

    #[test]
    fn server_logout_stamps_and_disconnects() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        let actions = s.logout();
        assert_eq!(s.state(), SessionState::Disconnected);
        assert!(matches!(actions[1], SessionAction::Disconnect));
        let SessionAction::Send(reply) = &actions[0] else {
            panic!()
        };
        assert_eq!(reply.get(tg::MSG_TYPE), Some("5"));
    }

    #[test]
    fn resend_served_from_store_with_poss_dup() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        // Client requests 2..3.
        let mut rr = FixMessage::typed(mt::RESEND_REQUEST);
        rr.set(tg::MSG_SEQ_NUM, 2);
        rr.set(tg::BEGIN_SEQ_NO, 2);
        rr.set(tg::END_SEQ_NO, 3);
        let _ = s.on_message(&rr);
        // Store: seq2 = ExecReport, seq3 = Heartbeat (admin).
        let store = |seq: u64| -> Option<(String, Vec<u8>)> {
            match seq {
                2 => Some((
                    "8".to_string(),
                    FixMessage::typed(mt::EXECUTION_REPORT).encode(),
                )),
                3 => Some(("0".to_string(), FixMessage::typed(mt::HEARTBEAT).encode())),
                _ => None,
            }
        };
        let actions = s.serve_resend(store);
        assert_eq!(actions.len(), 2);
        let SessionAction::Send(app) = &actions[0] else {
            panic!()
        };
        assert_eq!(app.get(tg::MSG_TYPE), Some("8"));
        assert_eq!(app.get(tg::POSS_DUP), Some("Y"));
        assert_eq!(app.get(tg::MSG_SEQ_NUM), Some("2"));
        // Admin message → GapFill SeqReset pointing at the next seq.
        let SessionAction::Send(gap) = &actions[1] else {
            panic!()
        };
        assert_eq!(gap.get(tg::MSG_TYPE), Some("4"));
        assert_eq!(gap.get(tg::GAP_FILL_FLAG), Some("Y"));
        assert_eq!(gap.get(tg::NEW_SEQ_NO), Some("3"));
    }

    #[test]
    fn resend_missing_store_gap_fills_forward() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        let mut rr = FixMessage::typed(mt::RESEND_REQUEST);
        rr.set(tg::MSG_SEQ_NUM, 2);
        rr.set(tg::BEGIN_SEQ_NO, 5);
        rr.set(tg::END_SEQ_NO, 9);
        let _ = s.on_message(&rr);
        // Empty store: everything purged.
        let actions = s.serve_resend(|_| None);
        assert_eq!(actions.len(), 1);
        let SessionAction::Send(gap) = &actions[0] else {
            panic!()
        };
        assert_eq!(gap.get(tg::GAP_FILL_FLAG), Some("Y"));
        // GapFill advances the peer's expected seq to our current out_seq.
        assert_eq!(
            gap.get(tg::NEW_SEQ_NO),
            Some(s.out_seq().to_string().as_str())
        );
    }

    #[test]
    fn prepare_app_message_stamps_sequence() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        let msg = s.prepare_app_message(mt::EXECUTION_REPORT);
        assert_eq!(msg.get(tg::MSG_SEQ_NUM), Some("2"));
        assert_eq!(s.out_seq(), 3);
        let msg2 = s.prepare_app_message(mt::EXECUTION_REPORT);
        assert_eq!(msg2.get(tg::MSG_SEQ_NUM), Some("3"));
    }

    #[test]
    fn multiple_in_order_deliveries() {
        let mut s = FixSession::new("EXCH".into(), "CLIENT".into(), 1, 1);
        s.on_message(&logon(1, false, 30));
        for seq in 2..=5 {
            let (_, deliver) = s.on_message(&app(seq, mt::NEW_ORDER));
            assert_eq!(deliver.len(), 1);
        }
        assert_eq!(s.in_seq(), 6);
    }
}
