//! Integration tests for the Telnet & TN3270E (RFC 854 / RFC 2355) state machine.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use bastion3270_core::telnet::{
    format_do, format_dont, format_will, format_wont, BindImageInfo, SessionSubmode, TelnetError,
    TelnetEvent, TelnetOption, TelnetStateMachine, Tn3270eDataType, Tn3270eFunctions,
    Tn3270eHeader, BIND_RU, DO, DONT, EOR, IAC, SB, SE, TELOPT_BINARY, TELOPT_ECHO, TELOPT_EOR,
    TELOPT_SGA, TELOPT_TN3270E, TELOPT_TTYPE, TELQUAL_IS, TELQUAL_SEND, TN3270E_FUNC_BIND_IMAGE,
    TN3270E_FUNC_RESPONSES, TN3270E_FUNC_SYSREQ, TN3270E_NEG_COMMAND_REJECT, TN3270E_OP_CONNECT,
    TN3270E_OP_DEVICE_TYPE, TN3270E_OP_FUNCTIONS, TN3270E_OP_IS, TN3270E_OP_REQUEST,
    TN3270E_OP_SEND, TN3270E_POS_DEVICE_END, TN3270E_RSF_NEGATIVE_RESPONSE,
    TN3270E_RSF_NO_RESPONSE, TN3270E_RSF_POSITIVE_RESPONSE, WILL, WONT,
};
use bastion3270_core::TerminalModel;

/// A state machine in plain TN3270 mode: the host asked for TERMINAL-TYPE, EOR and BINARY
/// and offered EOR and BINARY. With `client_binary = false` the host's `DO BINARY` is still
/// missing, so the 3270 mode starts once the test sends it. Negotiation output is drained.
#[allow(clippy::expect_used)]
fn tn3270_session(client_binary: bool) -> TelnetStateMachine {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    let mut nego = vec![
        IAC,
        DO,
        TELOPT_TTYPE,
        IAC,
        WILL,
        TELOPT_BINARY,
        IAC,
        DO,
        TELOPT_EOR,
        IAC,
        WILL,
        TELOPT_EOR,
    ];
    if client_binary {
        nego.extend_from_slice(&[IAC, DO, TELOPT_BINARY]);
    }
    sm.process_inbound(&nego).expect("negotiation");
    let _ = sm.take_outbound();
    sm
}

#[test]
fn test_telnet_option_roundtrip() {
    assert_eq!(TelnetOption::from_u8(0), TelnetOption::Binary);
    assert_eq!(TelnetOption::from_u8(24), TelnetOption::TerminalType);
    assert_eq!(TelnetOption::from_u8(25), TelnetOption::EndOfRecord);
    assert_eq!(TelnetOption::from_u8(40), TelnetOption::Tn3270e);
    assert_eq!(TelnetOption::from_u8(99), TelnetOption::Other(99));

    assert_eq!(TelnetOption::Binary.as_u8(), 0);
    assert_eq!(TelnetOption::TerminalType.as_u8(), 24);
    assert_eq!(TelnetOption::EndOfRecord.as_u8(), 25);
    assert_eq!(TelnetOption::Tn3270e.as_u8(), 40);
}

#[test]
fn test_telnet_format_helpers() {
    assert_eq!(format_will(TELOPT_BINARY), [255, 251, 0]);
    assert_eq!(format_wont(TELOPT_BINARY), [255, 252, 0]);
    assert_eq!(format_do(TELOPT_EOR), [255, 253, 25]);
    assert_eq!(format_dont(TELOPT_TN3270E), [255, 254, 40]);
}

#[test]
fn test_iac_escaping_receive_and_transmit() {
    let mut sm = tn3270_session(true);

    // Inbound doubled IAC collapses into a single 0xFF byte
    let inbound = [0xC1, IAC, IAC, 0xC2, IAC, EOR];
    let events = sm.process_inbound(&inbound);
    assert_eq!(
        events,
        Ok(vec![TelnetEvent::DataRecord(vec![0xC1, 0xFF, 0xC2])])
    );

    // Outbound framing doubles any 0xFF in the payload and terminates with [IAC, EOR]
    let payload = [0x7D, 0xFF, 0x40];
    let outbound = sm.frame_outbound_3270(&payload);
    assert_eq!(outbound, Ok(vec![0x7D, 0xFF, 0xFF, 0x40, IAC, EOR]));
}

#[test]
fn test_packet_fragmentation_byte_by_byte() {
    let mut sm = tn3270_session(false);

    let stream = [
        IAC,
        DO,
        TELOPT_BINARY,
        0xC1,
        0xC2,
        0xC3,
        IAC,
        IAC,
        0xC4,
        IAC,
        EOR,
    ];

    let mut all_events = Vec::new();
    for &b in &stream {
        let chunk = [b];
        if let Ok(mut evs) = sm.process_inbound(&chunk) {
            all_events.append(&mut evs);
        }
    }

    // DO BINARY completes the 3270 mode, then the record arrives.
    assert_eq!(all_events.len(), 2);
    assert!(matches!(
        all_events[0],
        TelnetEvent::NegotiationComplete { tn3270e: false, .. }
    ));
    assert_eq!(
        all_events[1],
        TelnetEvent::DataRecord(vec![0xC1, 0xC2, 0xC3, 0xFF, 0xC4])
    );

    // Verify outbound handshake was queued for DO BINARY
    let outbound = sm.take_outbound();
    assert_eq!(outbound, format_will(TELOPT_BINARY));
}

#[test]
fn test_option_negotiation_full_matrix() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // Host sends DO for supported options
    assert!(sm.process_inbound(&[IAC, DO, TELOPT_BINARY]).is_ok());
    assert!(sm.process_inbound(&[IAC, DO, TELOPT_EOR]).is_ok());
    assert!(sm.process_inbound(&[IAC, DO, TELOPT_TTYPE]).is_ok());
    assert!(sm.process_inbound(&[IAC, DO, TELOPT_TN3270E]).is_ok());
    assert!(sm.process_inbound(&[IAC, DO, 99]).is_ok()); // Unsupported

    let out = sm.take_outbound();
    assert_eq!(
        out,
        [
            IAC,
            WILL,
            TELOPT_BINARY,
            IAC,
            WILL,
            TELOPT_EOR,
            IAC,
            WILL,
            TELOPT_TTYPE,
            IAC,
            WILL,
            TELOPT_TN3270E,
            IAC,
            WONT,
            99,
        ]
    );

    // Host sends WILL for supported options
    assert!(sm.process_inbound(&[IAC, WILL, TELOPT_BINARY]).is_ok());
    assert!(sm.process_inbound(&[IAC, WILL, TELOPT_EOR]).is_ok());
    assert!(sm.process_inbound(&[IAC, WILL, TELOPT_SGA]).is_ok());
    assert!(sm.process_inbound(&[IAC, WILL, TELOPT_ECHO]).is_ok());
    assert!(sm.process_inbound(&[IAC, WILL, 99]).is_ok()); // Unsupported

    let out2 = sm.take_outbound();
    assert_eq!(
        out2,
        [
            IAC,
            DO,
            TELOPT_BINARY,
            IAC,
            DO,
            TELOPT_EOR,
            // (WILL EOR was already sent above so not duplicated)
            IAC,
            DO,
            TELOPT_SGA,
            IAC,
            DO,
            TELOPT_ECHO,
            IAC,
            DONT,
            99,
        ]
    );
}

#[test]
fn test_ttype_subnegotiation_with_luname() {
    let mut sm = TelnetStateMachine::new(
        TerminalModel::Model2,
        false, // 3278 monochrome
        false, // non-extended
        Some("POOL01".to_string()),
    );

    // Host sends IAC SB TTYPE SEND IAC SE
    let req = [IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE];
    let events = sm.process_inbound(&req);
    assert_eq!(events, Ok(vec![]));
    assert_eq!(sm.submode(), SessionSubmode::TtypeNegotiated);

    let out = sm.take_outbound();
    let expected_name = b"IBM-3278-2@POOL01";
    let mut expected = vec![IAC, SB, TELOPT_TTYPE, TELQUAL_IS];
    expected.extend_from_slice(expected_name);
    expected.extend_from_slice(&[IAC, SE]);
    assert_eq!(out, expected);
}

#[test]
fn test_tn3270e_full_handshake_flow() {
    let mut sm =
        TelnetStateMachine::new(TerminalModel::Model2, true, true, Some("MYLU".to_string()));

    // 1. Host DO TN3270E -> client WILL TN3270E
    assert!(sm.process_inbound(&[IAC, DO, TELOPT_TN3270E]).is_ok());
    assert_eq!(sm.take_outbound(), format_will(TELOPT_TN3270E));

    // 2. Host requests Device-Type: IAC SB TN3270E OP_SEND OP_DEVICE_TYPE IAC SE
    let req_dt = [
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_SEND,
        TN3270E_OP_DEVICE_TYPE,
        IAC,
        SE,
    ];
    assert!(sm.process_inbound(&req_dt).is_ok());
    assert_eq!(sm.submode(), SessionSubmode::Tn3270eNegotiatingDeviceType);

    let out_dt = sm.take_outbound();
    // In TN3270E, device type is always 3278: IBM-3278-2-E CONNECT MYLU
    let mut exp_dt = vec![
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_DEVICE_TYPE,
        TN3270E_OP_REQUEST,
    ];
    exp_dt.extend_from_slice(b"IBM-3278-2-E");
    exp_dt.push(TN3270E_OP_CONNECT);
    exp_dt.extend_from_slice(b"MYLU");
    exp_dt.extend_from_slice(&[IAC, SE]);
    assert_eq!(out_dt, exp_dt);

    // 3. Host confirms Device-Type and assigns LU:
    // IAC SB TN3270E OP_DEVICE_TYPE OP_IS IBM-3278-2-E CONNECT ASGLU01 IAC SE
    let mut host_is = vec![
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_DEVICE_TYPE,
        TN3270E_OP_IS,
    ];
    host_is.extend_from_slice(b"IBM-3278-2-E");
    host_is.push(TN3270E_OP_CONNECT);
    host_is.extend_from_slice(b"ASGLU01");
    host_is.extend_from_slice(&[IAC, SE]);
    assert!(sm.process_inbound(&host_is).is_ok());
    assert_eq!(sm.assigned_lu(), Some("ASGLU01"));
    assert_eq!(sm.submode(), SessionSubmode::Tn3270eNegotiatingFunctions);

    // Client must have sent functions request
    let out_funcs = sm.take_outbound();
    assert_eq!(
        out_funcs,
        [
            IAC,
            SB,
            TELOPT_TN3270E,
            TN3270E_OP_FUNCTIONS,
            TN3270E_OP_REQUEST,
            TN3270E_FUNC_BIND_IMAGE,
            TN3270E_FUNC_RESPONSES,
            TN3270E_FUNC_SYSREQ,
            IAC,
            SE,
        ]
    );

    // 4. Host agrees to functions: BIND_IMAGE and RESPONSES
    let host_funcs = [
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_FUNCTIONS,
        TN3270E_OP_IS,
        TN3270E_FUNC_BIND_IMAGE,
        TN3270E_FUNC_RESPONSES,
        IAC,
        SE,
    ];
    let events = sm.process_inbound(&host_funcs);
    let expected_funcs = Tn3270eFunctions {
        bind_image: true,
        responses: true,
        sysreq: false,
    };
    assert_eq!(
        events,
        Ok(vec![TelnetEvent::NegotiationComplete {
            tn3270e: true,
            functions: expected_funcs,
            assigned_lu: Some("ASGLU01".to_string()),
        }])
    );
    assert!(sm.is_tn3270e());
    assert!(!sm.is_bound()); // Unbound awaiting BIND RU
    assert_eq!(sm.submode(), SessionSubmode::Tn3270eUnbound);
}

#[test]
fn test_tn3270e_bind_and_unbind_lifecycle() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model4, true, true, None);

    // Set TN3270E negotiated with BIND_IMAGE
    let host_handshake = [
        IAC,
        DO,
        TELOPT_TN3270E,
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_SEND,
        TN3270E_OP_DEVICE_TYPE,
        IAC,
        SE,
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_DEVICE_TYPE,
        TN3270E_OP_IS,
        0x00,
        IAC,
        SE,
        IAC,
        SB,
        TELOPT_TN3270E,
        TN3270E_OP_FUNCTIONS,
        TN3270E_OP_IS,
        TN3270E_FUNC_BIND_IMAGE,
        IAC,
        SE,
    ];
    assert!(sm.process_inbound(&host_handshake).is_ok());
    let _ = sm.take_outbound();
    assert!(sm.is_tn3270e());
    assert!(!sm.is_bound());

    // 3270 data while unbound is ignored
    let data_header = [
        Tn3270eDataType::Data3270.as_u8(),
        0x00,
        TN3270E_RSF_NO_RESPONSE,
        0x00,
        0x01,
        0xF5,
        0xC3, // 3270 command
        IAC,
        EOR,
    ];
    let evs = sm.process_inbound(&data_header);
    assert_eq!(evs, Ok(vec![]));

    // Host sends BIND-IMAGE RU (opcode 0x31, ssize 0x03, PLU name "IMS")
    let mut bind_payload = vec![0x00; 35];
    if let Some(first) = bind_payload.first_mut() {
        *first = BIND_RU;
    }
    if let Some(ssize) = bind_payload.get_mut(24) {
        *ssize = 0x03;
    }
    if let Some(nlen) = bind_payload.get_mut(27) {
        *nlen = 3;
    }
    if let Some(name_slice) = bind_payload.get_mut(28..31) {
        name_slice.copy_from_slice(&[0xC9, 0xD4, 0xE2]); // "IMS" in EBCDIC
    }

    let mut bind_frame = vec![
        Tn3270eDataType::BindImage.as_u8(),
        0x00,
        TN3270E_RSF_NO_RESPONSE,
        0x00,
        0x02,
    ];
    bind_frame.extend_from_slice(&bind_payload);
    bind_frame.push(IAC);
    bind_frame.push(EOR);

    let bind_evs = sm.process_inbound(&bind_frame);
    assert_eq!(
        bind_evs,
        Ok(vec![
            TelnetEvent::HostModeChanged(bastion3270_core::HostMode::Data3270),
            TelnetEvent::BindImage(BindImageInfo {
                sizes: Some(bastion3270_core::BindSizes {
                    default: bastion3270_core::ScreenSize::new(24, 80),
                    alternate: bastion3270_core::ScreenSize::new(43, 80),
                }),
                plu_name: Some("IMS".to_string()),
            })
        ])
    );
    assert!(sm.is_bound());
    assert_eq!(sm.submode(), SessionSubmode::Tn3270eActive);

    // Now 3270 data frame is accepted
    let data_evs = sm.process_inbound(&data_header);
    assert_eq!(
        data_evs,
        Ok(vec![TelnetEvent::Tn3270eRecord {
            header: Tn3270eHeader {
                data_type: Tn3270eDataType::Data3270,
                request_flag: 0x00,
                response_flag: TN3270E_RSF_NO_RESPONSE,
                seq_number: 1,
            },
            payload: vec![0xF5, 0xC3],
        }])
    );

    // Host sends UNBIND RU (reason 0x01)
    let unbind_frame = [
        Tn3270eDataType::Unbind.as_u8(),
        0x00,
        TN3270E_RSF_NO_RESPONSE,
        0x00,
        0x03,
        0x01, // reason
        IAC,
        EOR,
    ];
    let unbind_evs = sm.process_inbound(&unbind_frame);
    assert_eq!(
        unbind_evs,
        Ok(vec![
            TelnetEvent::HostModeChanged(bastion3270_core::HostMode::Unbound),
            TelnetEvent::Unbind(1),
        ])
    );
    assert!(!sm.is_bound());
}

#[test]
fn test_tn3270e_response_generation() {
    let sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // Positive response: [Response (0x02), 0x00, POSITIVE_RESPONSE (0x00), seq_hi, seq_lo, POS_DEVICE_END (0x00), IAC, EOR]
    let pos = sm.frame_positive_response(0x0102);
    assert_eq!(
        pos,
        Ok(vec![
            Tn3270eDataType::Response.as_u8(),
            0x00,
            TN3270E_RSF_POSITIVE_RESPONSE,
            0x01,
            0x02,
            TN3270E_POS_DEVICE_END,
            IAC,
            EOR,
        ])
    );

    // Negative response with Command Reject:
    let neg = sm.frame_negative_response(0x0506, TN3270E_NEG_COMMAND_REJECT);
    assert_eq!(
        neg,
        Ok(vec![
            Tn3270eDataType::Response.as_u8(),
            0x00,
            TN3270E_RSF_NEGATIVE_RESPONSE,
            0x05,
            0x06,
            TN3270E_NEG_COMMAND_REJECT,
            IAC,
            EOR,
        ])
    );
}

#[test]
fn test_header_validation_errors() {
    // Truncated header (< 5 bytes)
    assert_eq!(
        Tn3270eHeader::parse(&[0x00, 0x01, 0x02]),
        Err(TelnetError::TruncatedHeader {
            needed: 5,
            available: 3
        })
    );

    // Invalid data type byte
    assert_eq!(
        Tn3270eHeader::parse(&[0xFA, 0x00, 0x00, 0x00, 0x01]),
        Err(TelnetError::InvalidDataType(0xFA))
    );
}

#[test]
fn test_dos_resource_limits_protection() {
    let mut sm = tn3270_session(true);

    // Frame exceeding 64 KiB is discarded at its IAC EOR (bounded memory, session continues)
    let mut chunk = vec![0x40; 65_537];
    chunk.extend_from_slice(&[IAC, EOR]);
    let res = sm.process_inbound(&chunk);
    assert!(matches!(
        res.as_deref(),
        Ok([TelnetEvent::RecordDiscarded(
            TelnetError::FrameTooLarge { .. }
        )])
    ));

    // Subnegotiation exceeding 1 KiB triggers SubnegotiationTooLarge
    let mut sm2 = tn3270_session(true);
    assert!(sm2.process_inbound(&[IAC, SB, 99]).is_ok());
    let subneg_overflow = vec![0x00; 1_025];
    let res2 = sm2.process_inbound(&subneg_overflow);
    assert!(matches!(
        res2,
        Err(TelnetError::SubnegotiationTooLarge { .. })
    ));
}
