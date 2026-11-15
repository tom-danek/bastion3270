//! Attn and `SysReq` routing per connection mode, checked against `x3270` `kybd.c`
//! (`Attn_action`, `SysReq_action`) and `telnet.c` (`net_bound`, `net_interrupt`, `net_abort`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::datastream::response::TEST_REQUEST_HEADER;
use bastion3270_core::telnet::{
    AttentionRoute, TelnetStateMachine, Tn3270eDataType, AO, BIND_RU, DO, EOR, IAC, IP, SB, SE,
    TELOPT_BINARY, TELOPT_EOR, TELOPT_TN3270E, TELOPT_TTYPE, TN3270E_FUNC_BIND_IMAGE,
    TN3270E_FUNC_RESPONSES, TN3270E_FUNC_SYSREQ, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_FUNCTIONS,
    TN3270E_OP_IS, TN3270E_OP_SEND, WILL,
};
use bastion3270_core::{
    AttentionKey, KeyboardError, KeyboardState, PresentationSpace, TerminalModel, VirtualKeyboard,
};

fn feed(sm: &mut TelnetStateMachine, bytes: &[u8]) {
    sm.process_inbound(bytes).expect("inbound bytes");
}

fn subneg(body: &[u8]) -> Vec<u8> {
    let mut v = vec![IAC, SB];
    v.extend_from_slice(body);
    v.extend_from_slice(&[IAC, SE]);
    v
}

/// TN3270E session with the given agreed functions.
fn tn3270e(functions: &[u8]) -> TelnetStateMachine {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, false, true, None);
    feed(&mut sm, &[IAC, DO, TELOPT_TN3270E]);
    feed(
        &mut sm,
        &subneg(&[TELOPT_TN3270E, TN3270E_OP_SEND, TN3270E_OP_DEVICE_TYPE]),
    );
    let mut is = vec![TELOPT_TN3270E, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_IS];
    is.extend_from_slice(b"IBM-3278-2-E");
    feed(&mut sm, &subneg(&is));
    let mut funcs = vec![TELOPT_TN3270E, TN3270E_OP_FUNCTIONS, TN3270E_OP_IS];
    funcs.extend_from_slice(functions);
    feed(&mut sm, &subneg(&funcs));
    assert!(sm.is_tn3270e());
    sm
}

fn bind(sm: &mut TelnetStateMachine) {
    let mut frame = vec![Tn3270eDataType::BindImage.as_u8(), 0, 0, 0, 1];
    let mut ru = vec![0x00; 35];
    ru[0] = BIND_RU;
    frame.extend_from_slice(&ru);
    frame.extend_from_slice(&[IAC, EOR]);
    feed(sm, &frame);
    assert!(sm.is_bound());
}

fn routes(sm: &TelnetStateMachine) -> (AttentionRoute, AttentionRoute) {
    (
        sm.attention_route(AttentionKey::Attn),
        sm.attention_route(AttentionKey::SysReq),
    )
}

const ALL: [u8; 3] = [
    TN3270E_FUNC_BIND_IMAGE,
    TN3270E_FUNC_RESPONSES,
    TN3270E_FUNC_SYSREQ,
];

#[test]
fn bound_tn3270e_sends_telnet_ip_and_ao() {
    let mut sm = tn3270e(&ALL);
    bind(&mut sm);
    assert_eq!(
        routes(&sm),
        (
            AttentionRoute::TelnetCommand(IP),
            AttentionRoute::TelnetCommand(AO)
        )
    );
}

#[test]
fn tn3270e_before_bind_has_no_attn_and_ignores_sysreq() {
    let sm = tn3270e(&ALL);
    assert_eq!(
        routes(&sm),
        (AttentionRoute::NotAvailable, AttentionRoute::Ignored)
    );
}

#[test]
fn tn3270e_without_bind_image_or_sysreq() {
    // x3270 `net_bound()` needs a BIND, which never comes without BIND-IMAGE; SysReq needs
    // the SYSREQ function.
    let sm = tn3270e(&[TN3270E_FUNC_RESPONSES]);
    assert_eq!(
        routes(&sm),
        (AttentionRoute::NotAvailable, AttentionRoute::Ignored)
    );
}

#[test]
fn plain_tn3270_uses_pa1_break_and_test_request() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, false, false, None);
    feed(
        &mut sm,
        &[
            IAC,
            DO,
            TELOPT_TTYPE,
            IAC,
            DO,
            TELOPT_EOR,
            IAC,
            WILL,
            TELOPT_EOR,
            IAC,
            DO,
            TELOPT_BINARY,
            IAC,
            WILL,
            TELOPT_BINARY,
        ],
    );
    assert_eq!(
        routes(&sm),
        (AttentionRoute::Pa1ThenBreak, AttentionRoute::TestRequest)
    );
}

#[test]
fn before_negotiation_both_keys_are_ignored() {
    let sm = TelnetStateMachine::new(TerminalModel::Model2, false, false, None);
    assert_eq!(
        routes(&sm),
        (AttentionRoute::Ignored, AttentionRoute::Ignored)
    );
}

#[test]
fn sysreq_test_request_locks_like_an_aid_key() {
    let ps = PresentationSpace::new(TerminalModel::Model2);
    let mut kb = VirtualKeyboard::new();
    assert_eq!(kb.press_sysreq(&ps), Ok(TEST_REQUEST_HEADER.to_vec()));
    assert_eq!(kb.state(), KeyboardState::TimeWait);
    assert_eq!(
        kb.press_sysreq(&ps),
        Err(KeyboardError::Locked(KeyboardState::TimeWait))
    );
}

#[test]
fn not_available_lock_is_cleared_by_reset() {
    let mut kb = VirtualKeyboard::new();
    kb.not_available();
    assert_eq!(KeyboardState::NotAvailable.oia_indicator(), "X -f");
    kb.reset();
    assert_eq!(kb.state(), KeyboardState::Unlocked);
}
