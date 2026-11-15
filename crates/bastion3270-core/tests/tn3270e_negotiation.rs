//! TN3270E / Telnet option negotiation, checked byte-for-byte against `x3270` `telnet.c`
//! (`telnet_fsm`, `tn3270e_negotiate`, `backoff_tn3270e`, `check_in3270`) and RFC 2355 §7.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::telnet::{
    SessionSubmode, TelnetError, TelnetEvent, TelnetStateMachine, Tn3270eBackoff, Tn3270eDataType,
    Tn3270eFunctions, DO, DONT, EOR, IAC, SB, SE, TELOPT_BINARY, TELOPT_ECHO, TELOPT_EOR,
    TELOPT_SGA, TELOPT_TN3270E, TELOPT_TTYPE, TELQUAL_SEND, TN3270E_FUNC_BIND_IMAGE,
    TN3270E_FUNC_RESPONSES, TN3270E_FUNC_SCS_CTL_CODES, TN3270E_FUNC_SYSREQ,
    TN3270E_OP_DEVICE_TYPE, TN3270E_OP_FUNCTIONS, TN3270E_OP_IS, TN3270E_OP_REASON,
    TN3270E_OP_REJECT, TN3270E_OP_REQUEST, TN3270E_OP_SEND, TN3270E_REASON_INV_DEVICE_TYPE, WILL,
    WONT,
};
use bastion3270_core::TerminalModel;

fn machine() -> TelnetStateMachine {
    TelnetStateMachine::new(TerminalModel::Model2, false, true, None)
}

fn feed(sm: &mut TelnetStateMachine, bytes: &[u8]) -> Vec<TelnetEvent> {
    sm.process_inbound(bytes).expect("inbound bytes")
}

fn subneg(body: &[u8]) -> Vec<u8> {
    let mut v = vec![IAC, SB];
    v.extend_from_slice(body);
    v.extend_from_slice(&[IAC, SE]);
    v
}

fn functions_msg(op: u8, funcs: &[u8]) -> Vec<u8> {
    let mut body = vec![TELOPT_TN3270E, TN3270E_OP_FUNCTIONS, op];
    body.extend_from_slice(funcs);
    subneg(&body)
}

/// Host side up to the client's FUNCTIONS REQUEST: DO TN3270E, SEND DEVICE-TYPE, DEVICE-TYPE IS.
fn negotiate_device_type(sm: &mut TelnetStateMachine) {
    assert_eq!(feed(sm, &[IAC, DO, TELOPT_TN3270E]), vec![]);
    assert_eq!(sm.take_outbound(), vec![IAC, WILL, TELOPT_TN3270E]);
    feed(
        sm,
        &subneg(&[TELOPT_TN3270E, TN3270E_OP_SEND, TN3270E_OP_DEVICE_TYPE]),
    );
    sm.take_outbound();
    let mut is = vec![TELOPT_TN3270E, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_IS];
    is.extend_from_slice(b"IBM-3278-2-E");
    assert_eq!(feed(sm, &subneg(&is)), vec![]);
    // The client asks for BIND-IMAGE, RESPONSES and SYSREQ, in code order.
    assert_eq!(
        sm.take_outbound(),
        functions_msg(
            TN3270E_OP_REQUEST,
            &[
                TN3270E_FUNC_BIND_IMAGE,
                TN3270E_FUNC_RESPONSES,
                TN3270E_FUNC_SYSREQ
            ]
        )
    );
}

fn tn3270e_complete(functions: Tn3270eFunctions) -> TelnetEvent {
    TelnetEvent::NegotiationComplete {
        tn3270e: true,
        functions,
        assigned_lu: None,
    }
}

fn tn3270_complete() -> TelnetEvent {
    TelnetEvent::NegotiationComplete {
        tn3270e: false,
        functions: Tn3270eFunctions::default(),
        assigned_lu: None,
    }
}

const RESPONSES_ONLY: Tn3270eFunctions = Tn3270eFunctions {
    bind_image: false,
    responses: true,
    sysreq: false,
};

/// Host side of plain TN3270 negotiation (DO TTYPE, SB TTYPE SEND, BINARY and EOR both ways).
fn negotiate_classic(sm: &mut TelnetStateMachine) -> Vec<TelnetEvent> {
    let mut events = feed(sm, &[IAC, DO, TELOPT_TTYPE]);
    events.extend(feed(sm, &subneg(&[TELOPT_TTYPE, TELQUAL_SEND])));
    events.extend(feed(
        sm,
        &[
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
    ));
    sm.take_outbound();
    events
}

#[test]
fn client_sends_nothing_before_the_host_asks() {
    let mut sm = machine();
    assert_eq!(feed(&mut sm, &[]), vec![]);
    assert_eq!(sm.take_outbound(), Vec::<u8>::new());
}

#[test]
fn host_functions_request_within_our_set_is_accepted() {
    let mut sm = machine();
    negotiate_device_type(&mut sm);

    // The host proposes a subset of what we asked for: we answer IS and are done.
    let events = feed(
        &mut sm,
        &functions_msg(TN3270E_OP_REQUEST, &[TN3270E_FUNC_RESPONSES]),
    );
    assert_eq!(events, vec![tn3270e_complete(RESPONSES_ONLY)]);
    assert_eq!(
        sm.take_outbound(),
        functions_msg(TN3270E_OP_IS, &[TN3270E_FUNC_RESPONSES])
    );
    assert!(sm.is_tn3270e());
    assert!(
        sm.is_bound(),
        "without BIND-IMAGE the session is in 3270 mode at once"
    );
}

#[test]
fn host_functions_request_beyond_our_set_gets_the_common_subset() {
    let mut sm = machine();
    negotiate_device_type(&mut sm);

    // The host wants SCS-CTL-CODES (which we cannot do) and RESPONSES.
    let events = feed(
        &mut sm,
        &functions_msg(
            TN3270E_OP_REQUEST,
            &[TN3270E_FUNC_RESPONSES, TN3270E_FUNC_SCS_CTL_CODES],
        ),
    );
    assert_eq!(events, vec![]);
    assert_eq!(
        sm.take_outbound(),
        functions_msg(TN3270E_OP_REQUEST, &[TN3270E_FUNC_RESPONSES])
    );
    assert!(!sm.is_tn3270e());

    // The host agrees to the subset.
    let events = feed(
        &mut sm,
        &functions_msg(TN3270E_OP_IS, &[TN3270E_FUNC_RESPONSES]),
    );
    assert_eq!(events, vec![tn3270e_complete(RESPONSES_ONLY)]);
    assert_eq!(sm.take_outbound(), Vec::<u8>::new());
}

#[test]
fn functions_is_with_an_added_function_abandons_tn3270e() {
    let mut sm = machine();
    negotiate_device_type(&mut sm);

    let events = feed(
        &mut sm,
        &functions_msg(
            TN3270E_OP_IS,
            &[TN3270E_FUNC_RESPONSES, TN3270E_FUNC_SCS_CTL_CODES],
        ),
    );
    assert_eq!(
        events,
        vec![TelnetEvent::Tn3270eBackoff(Tn3270eBackoff::FunctionsAdded)]
    );
    assert_eq!(sm.take_outbound(), vec![IAC, WONT, TELOPT_TN3270E]);
    assert!(!sm.is_tn3270e());
}

#[test]
fn device_type_reject_falls_back_to_plain_tn3270() {
    let mut sm = machine();
    feed(&mut sm, &[IAC, DO, TELOPT_TN3270E]);
    feed(
        &mut sm,
        &subneg(&[TELOPT_TN3270E, TN3270E_OP_SEND, TN3270E_OP_DEVICE_TYPE]),
    );
    sm.take_outbound();

    let events = feed(
        &mut sm,
        &subneg(&[
            TELOPT_TN3270E,
            TN3270E_OP_DEVICE_TYPE,
            TN3270E_OP_REJECT,
            TN3270E_OP_REASON,
            TN3270E_REASON_INV_DEVICE_TYPE,
        ]),
    );
    assert_eq!(
        events,
        vec![TelnetEvent::Tn3270eBackoff(
            Tn3270eBackoff::DeviceTypeRejected {
                reason: Some(TN3270E_REASON_INV_DEVICE_TYPE)
            }
        )]
    );
    // The host is told "no", so it can continue with plain TN3270.
    assert_eq!(sm.take_outbound(), vec![IAC, WONT, TELOPT_TN3270E]);

    // Plain TN3270 negotiation then completes and records carry no TN3270E header.
    assert_eq!(negotiate_classic(&mut sm), vec![tn3270_complete()]);
    assert_eq!(sm.submode(), SessionSubmode::Tn3270Active);
    assert_eq!(
        feed(&mut sm, &[0xF5, 0xC3, IAC, EOR]),
        vec![TelnetEvent::DataRecord(vec![0xF5, 0xC3])]
    );
}

#[test]
fn host_negotiating_tn3270e_off_clears_the_tn3270e_state() {
    for leave in [[IAC, DONT, TELOPT_TN3270E], [IAC, WONT, TELOPT_TN3270E]] {
        let mut sm = machine();
        negotiate_device_type(&mut sm);
        feed(
            &mut sm,
            &functions_msg(TN3270E_OP_IS, &[TN3270E_FUNC_RESPONSES]),
        );
        assert!(sm.is_tn3270e());

        // DONT TN3270E (or WONT, which some hosts send instead) turns TN3270E off.
        assert_eq!(feed(&mut sm, &leave), vec![]);
        assert_eq!(sm.take_outbound(), vec![IAC, WONT, TELOPT_TN3270E]);
        assert!(!sm.is_tn3270e());
        assert_eq!(sm.functions(), Tn3270eFunctions::REQUESTED);

        // A record that starts with what would be a TN3270E data type byte is plain 3270
        // data now; before the fix its first five bytes were stripped as a header.
        assert_eq!(negotiate_classic(&mut sm), vec![tn3270_complete()]);
        let record = [0x00, 0x00, 0x00, 0x00, 0x01, 0xF5, 0xC3];
        let mut wire = record.to_vec();
        wire.extend_from_slice(&[IAC, EOR]);
        assert_eq!(
            feed(&mut sm, &wire),
            vec![TelnetEvent::DataRecord(record.to_vec())]
        );
        // Outbound records carry no TN3270E header either.
        assert_eq!(
            sm.frame_outbound_3270(&[0x7D]).expect("frame"),
            vec![0x7D, IAC, EOR]
        );
    }
}

#[test]
fn tn3270e_subnegotiation_is_ignored_unless_the_client_performs_tn3270e() {
    let mut sm = machine();
    let events = feed(
        &mut sm,
        &subneg(&[TELOPT_TN3270E, TN3270E_OP_SEND, TN3270E_OP_DEVICE_TYPE]),
    );
    assert_eq!(events, vec![]);
    assert_eq!(sm.take_outbound(), Vec::<u8>::new());
}

#[test]
fn bind_and_unbind_without_bind_image_are_discarded() {
    let mut sm = machine();
    negotiate_device_type(&mut sm);
    feed(
        &mut sm,
        &functions_msg(TN3270E_OP_IS, &[TN3270E_FUNC_RESPONSES]),
    );

    for dt in [Tn3270eDataType::BindImage, Tn3270eDataType::Unbind] {
        let frame = [dt.as_u8(), 0x00, 0x00, 0x00, 0x01, 0x31, IAC, EOR];
        assert_eq!(
            feed(&mut sm, &frame),
            vec![TelnetEvent::RecordDiscarded(
                TelnetError::FunctionNotNegotiated(dt.as_u8())
            )]
        );
        assert!(sm.is_bound(), "{dt:?} must not change the session state");
    }
}

#[test]
fn sga_and_echo_are_negotiated_once_each_way() {
    let mut sm = machine();

    // WILL SGA / WILL ECHO are accepted once; a repeated WILL is not answered (no loop).
    feed(&mut sm, &[IAC, WILL, TELOPT_SGA, IAC, WILL, TELOPT_ECHO]);
    assert_eq!(
        sm.take_outbound(),
        vec![IAC, DO, TELOPT_SGA, IAC, DO, TELOPT_ECHO]
    );
    feed(&mut sm, &[IAC, WILL, TELOPT_SGA]);
    assert_eq!(sm.take_outbound(), Vec::<u8>::new());

    // WONT for an option the host performed is acknowledged with DONT, once.
    feed(&mut sm, &[IAC, WONT, TELOPT_ECHO, IAC, WONT, TELOPT_ECHO]);
    assert_eq!(sm.take_outbound(), vec![IAC, DONT, TELOPT_ECHO]);

    // DO SGA is accepted (x3270 performs SGA), not refused.
    feed(&mut sm, &[IAC, DO, TELOPT_SGA, IAC, DO, TELOPT_SGA]);
    assert_eq!(sm.take_outbound(), vec![IAC, WILL, TELOPT_SGA]);

    // DO ECHO is refused: the client never echoes.
    feed(&mut sm, &[IAC, DO, TELOPT_ECHO]);
    assert_eq!(sm.take_outbound(), vec![IAC, WONT, TELOPT_ECHO]);
}
