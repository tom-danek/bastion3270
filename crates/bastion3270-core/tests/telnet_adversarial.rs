//! Adversarial integration test suite for Telnet & TN3270E (RFC 854 / RFC 2355) state machine.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

use bastion3270_core::telnet::{
    escape_iac, BindImageInfo, HostMode, SessionSubmode, TelnetError, TelnetEvent,
    TelnetStateMachine, Tn3270eDataType, BIND_RU, DO, DONT, EOR, IAC, MAX_OUTBOUND_QUEUE_BYTES,
    MAX_RECORD_BYTES, MAX_SUBNEG_BYTES, SB, SE, TELOPT_BINARY, TELOPT_EOR, TELOPT_TN3270E,
    TELOPT_TTYPE, TN3270E_FUNC_BIND_IMAGE, TN3270E_FUNC_RESPONSES, TN3270E_NEG_COMMAND_REJECT,
    TN3270E_NEG_COMPONENT_DISCONNECTED, TN3270E_NEG_INTERVENTION_REQUIRED,
    TN3270E_NEG_OPERATION_CHECK, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_FUNCTIONS, TN3270E_OP_IS,
    TN3270E_OP_SEND, TN3270E_POS_DEVICE_END, TN3270E_RSF_NEGATIVE_RESPONSE,
    TN3270E_RSF_NO_RESPONSE, TN3270E_RSF_POSITIVE_RESPONSE, WILL, WONT,
};
use bastion3270_core::TerminalModel;

/// A state machine in plain TN3270 mode: the host asked for TERMINAL-TYPE, EOR and BINARY
/// and offered EOR and BINARY. With `client_binary = false` the host's `DO BINARY` is still
/// missing, so the 3270 mode starts once the test sends it. Negotiation output is drained.
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

/// Helper to negotiate TN3270E with BIND_IMAGE and RESPONSES functions.
fn helper_establish_tn3270e(sm: &mut TelnetStateMachine) {
    let handshake = [
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
        TN3270E_FUNC_RESPONSES,
        IAC,
        SE,
    ];
    let res = sm.process_inbound(&handshake);
    assert!(res.is_ok(), "TN3270E handshake failed: {res:?}");
    let _ = sm.take_outbound();
    assert!(sm.is_tn3270e());
    assert!(!sm.is_bound());
}

/// Helper to bind an active TN3270E session using Model 2 default dimensions.
fn helper_bind_session(sm: &mut TelnetStateMachine) {
    let mut bind_frame = vec![
        Tn3270eDataType::BindImage.as_u8(),
        0x00,
        TN3270E_RSF_NO_RESPONSE,
        0x00,
        0x01,
    ];
    let mut bind_payload = vec![0x00; 35];
    bind_payload[0] = BIND_RU;
    bind_payload[24] = 0x03; // Alternate model dimensions
    bind_frame.extend_from_slice(&bind_payload);
    bind_frame.push(IAC);
    bind_frame.push(EOR);

    let res = sm.process_inbound(&bind_frame);
    assert!(res.is_ok(), "Binding failed: {res:?}");
    assert!(sm.is_bound());
}

// ============================================================================
// 1. EXTREME NETWORK FRAGMENTATION
// ============================================================================

#[test]
fn test_fragmentation_byte_by_byte_stream() {
    let mut sm = tn3270_session(false);

    // Full sequence: DO BINARY, then 3270 data [0xF5, 0xC1, 0xFF, 0xC2], then IAC EOR
    // Note 0xFF is escaped as 0xFF 0xFF
    let stream = [IAC, DO, TELOPT_BINARY, 0xF5, 0xC1, IAC, IAC, 0xC2, IAC, EOR];

    let mut all_events = Vec::new();
    for &byte in &stream {
        let evs = sm
            .process_inbound(&[byte])
            .expect("Single byte processing failed");
        all_events.extend(evs);
    }

    // DO BINARY completes the 3270 mode, then the record arrives.
    assert_eq!(all_events.len(), 2);
    assert!(matches!(
        all_events[0],
        TelnetEvent::NegotiationComplete { tn3270e: false, .. }
    ));
    assert_eq!(
        all_events[1],
        TelnetEvent::DataRecord(vec![0xF5, 0xC1, 0xFF, 0xC2])
    );

    // Outbound should contain WILL BINARY
    assert_eq!(sm.take_outbound(), [IAC, WILL, TELOPT_BINARY]);
}

#[test]
fn test_fragmentation_split_iac_sequences() {
    let mut sm = tn3270_session(true);

    // Case A: Chunk 1 ends with IAC, Chunk 2 begins with EOR
    let c1 = [0xC1, 0xC2, IAC];
    let c2 = [EOR];
    assert_eq!(sm.process_inbound(&c1), Ok(vec![]));
    assert_eq!(
        sm.process_inbound(&c2),
        Ok(vec![TelnetEvent::DataRecord(vec![0xC1, 0xC2])])
    );

    // Case B: Chunk 1 ends with IAC, Chunk 2 begins with IAC (doubled IAC)
    let c3 = [0xC3, IAC];
    let c4 = [IAC, 0xC4, IAC, EOR];
    assert_eq!(sm.process_inbound(&c3), Ok(vec![]));
    assert_eq!(
        sm.process_inbound(&c4),
        Ok(vec![TelnetEvent::DataRecord(vec![0xC3, 0xFF, 0xC4])])
    );

    // Case C: Chunk 1 ends with IAC, Chunk 2 has DO, Chunk 3 has option (on a fresh
    // connection, where EOR is not yet negotiated)
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    let c5 = [IAC];
    let c6 = [DO];
    let c7 = [TELOPT_EOR];
    assert_eq!(sm.process_inbound(&c5), Ok(vec![]));
    assert_eq!(sm.process_inbound(&c6), Ok(vec![]));
    assert_eq!(sm.process_inbound(&c7), Ok(vec![]));
    assert_eq!(sm.take_outbound(), [IAC, WILL, TELOPT_EOR]);
}

#[test]
fn test_fragmentation_split_tn3270e_headers() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut sm);
    helper_bind_session(&mut sm);

    // 5-byte header: Data3270 (0x00), RQF 0x01, RSF 0x02, Seq 0x1234
    // Payload: [0xC1, 0xC2, 0xC3]
    // End: IAC EOR
    let header_bytes = [0x00, 0x01, 0x02, 0x12, 0x34];
    let payload = [0xC1, 0xC2, 0xC3];

    // Feed each header byte in its own single-byte slice
    for &hb in &header_bytes {
        let evs = sm.process_inbound(&[hb]).expect("Header byte failed");
        assert!(
            evs.is_empty(),
            "Should not produce event during header bytes"
        );
    }

    // Feed payload bytes across arbitrary 1-2 byte chunks
    assert_eq!(sm.process_inbound(&payload[0..1]), Ok(vec![]));
    assert_eq!(sm.process_inbound(&payload[1..3]), Ok(vec![]));

    // Split IAC and EOR across separate calls
    assert_eq!(sm.process_inbound(&[IAC]), Ok(vec![]));
    let evs = sm.process_inbound(&[EOR]).expect("EOR failed");

    assert_eq!(evs.len(), 1);
    match &evs[0] {
        TelnetEvent::Tn3270eRecord { header, payload: p } => {
            assert_eq!(header.data_type, Tn3270eDataType::Data3270);
            assert_eq!(header.request_flag, 0x01);
            assert_eq!(header.response_flag, 0x02);
            assert_eq!(header.seq_number, 0x1234);
            assert_eq!(p, &[0xC1, 0xC2, 0xC3]);
        }
        other => panic!("Unexpected event: {other:?}"),
    }
}

#[test]
fn test_fragmentation_subnegotiation_arbitrary_chunks() {
    let mut sm = TelnetStateMachine::new(
        TerminalModel::Model2,
        true,
        true,
        Some("POOL99".to_string()),
    );

    // Full subnegotiation: IAC SB TTYPE SEND IAC SE
    let subneg = [IAC, SB, TELOPT_TTYPE, 1, IAC, SE];

    // Partition subneg across chunk sizes [1, 2, 1, 2]
    let chunks: [&[u8]; 4] = [
        &subneg[0..1], // [IAC]
        &subneg[1..3], // [SB, TTYPE]
        &subneg[3..4], // [SEND]
        &subneg[4..6], // [IAC, SE]
    ];

    for chunk in chunks {
        assert_eq!(sm.process_inbound(chunk), Ok(vec![]));
    }

    assert_eq!(sm.submode(), SessionSubmode::TtypeNegotiated);
    let out = sm.take_outbound();
    let expected_str = b"IBM-3279-2-E@POOL99";
    let mut exp = vec![IAC, SB, TELOPT_TTYPE, 0];
    exp.extend_from_slice(expected_str);
    exp.extend_from_slice(&[IAC, SE]);
    assert_eq!(out, exp);
}

// ============================================================================
// 2. DOUBLE IAC ESCAPING ADVERSARIAL CASES
// ============================================================================

#[test]
fn test_double_iac_1000_consecutive_bytes_traditional() {
    let mut sm = tn3270_session(true);

    // 1000 consecutive 0xFF bytes
    let raw_1000 = vec![0xFF_u8; 1000];

    // Egress test: frame_outbound_3270 should escape each 0xFF to 0xFF 0xFF
    let outbound = sm.frame_outbound_3270(&raw_1000).expect("Framing failed");
    // Expected: 2000 0xFF bytes + 2 bytes [IAC, EOR] = 2002 bytes
    assert_eq!(outbound.len(), 2002);
    assert_eq!(&outbound[0..2000], &vec![0xFF_u8; 2000][..]);
    assert_eq!(&outbound[2000..2002], &[IAC, EOR]);

    // Ingress test: feed outbound into fresh receiver
    let mut receiver = tn3270_session(true);
    let events = receiver.process_inbound(&outbound).expect("Ingress failed");
    assert_eq!(events.len(), 1);
    match &events[0] {
        TelnetEvent::DataRecord(rec) => {
            assert_eq!(rec.len(), 1000, "Should unescape to exactly 1000 bytes");
            assert_eq!(rec, &raw_1000);
        }
        other => panic!("Expected DataRecord, got {other:?}"),
    }
}

#[test]
fn test_double_iac_1000_consecutive_bytes_tn3270e() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut sm);
    helper_bind_session(&mut sm);

    let raw_1000 = vec![0xFF_u8; 1000];
    let outbound = sm.frame_outbound_3270(&raw_1000).expect("Framing failed");

    // Feed to a receiver that is also in bound TN3270E mode
    let mut receiver = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut receiver);
    helper_bind_session(&mut receiver);

    let events = receiver.process_inbound(&outbound).expect("Ingress failed");
    assert_eq!(events.len(), 1);
    match &events[0] {
        TelnetEvent::Tn3270eRecord { header, payload } => {
            assert_eq!(header.data_type, Tn3270eDataType::Data3270);
            assert_eq!(payload.len(), 1000);
            assert_eq!(payload, &raw_1000);
        }
        other => panic!("Expected Tn3270eRecord, got {other:?}"),
    }
}

#[test]
fn test_double_iac_odd_count_ingress() {
    let mut sm = tn3270_session(true);

    // 1001 consecutive 0xFF bytes followed by 0xEF (EOR)
    // Ingress: 500 doubled IACs (1000 bytes) -> 500 literal 0xFF bytes
    // The 1001st 0xFF is an IAC, followed by 0xEF -> IAC EOR!
    let mut stream = vec![0xFF_u8; 1001];
    stream.push(EOR);

    let events = sm.process_inbound(&stream).expect("Ingress failed");
    assert_eq!(events.len(), 1);
    match &events[0] {
        TelnetEvent::DataRecord(rec) => {
            assert_eq!(rec.len(), 500);
            assert_eq!(rec, &vec![0xFF_u8; 500]);
        }
        other => panic!("Expected DataRecord, got {other:?}"),
    }
}

#[test]
fn test_double_iac_standalone_helper() {
    let raw = vec![0xFF_u8; 1000];
    let escaped = escape_iac(&raw);
    assert_eq!(escaped.len(), 2000);
    assert!(escaped.iter().all(|&b| b == 0xFF));

    // Mixed data: 500x [0x40, 0xFF]
    let mut mixed = Vec::with_capacity(1000);
    for _ in 0..500 {
        mixed.push(0x40);
        mixed.push(0xFF);
    }
    let escaped_mixed = escape_iac(&mixed);
    assert_eq!(escaped_mixed.len(), 1500); // 500x 0x40 + 500x (0xFF 0xFF)
}

#[test]
fn test_truncated_iac_commands_at_boundary() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // Test each Telnet command split across chunk boundary:
    // Chunk 1: [0xFF] (IAC), Chunk 2: command byte
    let commands = [
        241, // NOP
        242, // DM
        243, // BREAK
        244, // IP
        245, // AO
        246, // AYT
        247, // EC
        248, // EL
        249, // GA
    ];

    for &cmd in &commands {
        assert_eq!(sm.process_inbound(&[IAC]), Ok(vec![]));
        assert_eq!(sm.process_inbound(&[cmd]), Ok(vec![]));
        assert_eq!(sm.state(), bastion3270_core::telnet::TelnetState::Data);
    }
}

#[test]
fn test_responses_with_iac_escaped_sequences() {
    let sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // Test positive response with sequence numbers that contain 0xFF:
    // Seq 0x00FF has 0xFF in low byte
    let pos_ff = sm
        .frame_positive_response(0x00FF)
        .expect("Positive response framing");
    // Expected: [0x02, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xEF]
    assert_eq!(
        pos_ff,
        [
            Tn3270eDataType::Response.as_u8(),
            0x00,
            TN3270E_RSF_POSITIVE_RESPONSE,
            0x00,
            0xFF,
            0xFF, // escaped
            TN3270E_POS_DEVICE_END,
            IAC,
            EOR,
        ]
    );

    // Seq 0xFFFF has 0xFF in both bytes
    let pos_ffff = sm
        .frame_positive_response(0xFFFF)
        .expect("Positive response framing");
    assert_eq!(
        pos_ffff,
        [
            Tn3270eDataType::Response.as_u8(),
            0x00,
            TN3270E_RSF_POSITIVE_RESPONSE,
            0xFF,
            0xFF, // escaped hi byte
            0xFF,
            0xFF, // escaped lo byte
            TN3270E_POS_DEVICE_END,
            IAC,
            EOR,
        ]
    );

    // Negative responses with various reasons
    for reason in [
        TN3270E_NEG_COMMAND_REJECT,
        TN3270E_NEG_INTERVENTION_REQUIRED,
        TN3270E_NEG_OPERATION_CHECK,
        TN3270E_NEG_COMPONENT_DISCONNECTED,
    ] {
        let neg = sm
            .frame_negative_response(0x12FF, reason)
            .expect("Negative response framing");
        assert_eq!(
            neg,
            [
                Tn3270eDataType::Response.as_u8(),
                0x00,
                TN3270E_RSF_NEGATIVE_RESPONSE,
                0x12,
                0xFF,
                0xFF, // escaped
                reason,
                IAC,
                EOR,
            ]
        );
    }
}

// ============================================================================
// 3. BUFFER LIMITS & DOS RESISTANCE
// ============================================================================

#[test]
fn test_dos_record_buffer_exact_capacity_succeeds() {
    let mut sm = tn3270_session(true);

    // Exactly MAX_RECORD_BYTES (65,536) data bytes followed by IAC EOR
    let mut exact_stream = vec![0x40_u8; MAX_RECORD_BYTES];
    exact_stream.push(IAC);
    exact_stream.push(EOR);

    let events = sm
        .process_inbound(&exact_stream)
        .expect("64 KiB record failed");
    assert_eq!(events.len(), 1);
    match &events[0] {
        TelnetEvent::DataRecord(rec) => assert_eq!(rec.len(), MAX_RECORD_BYTES),
        other => panic!("Expected DataRecord, got {other:?}"),
    }
}

#[test]
fn test_dos_record_buffer_overflow_rejected() {
    let mut sm = tn3270_session(true);

    // 65,537 bytes then IAC EOR: the record is discarded (not fatal), memory stays bounded
    let mut overflow = vec![0x40_u8; MAX_RECORD_BYTES.saturating_add(1)];
    overflow.extend_from_slice(&[IAC, EOR]);
    assert_eq!(
        sm.process_inbound(&overflow),
        Ok(vec![TelnetEvent::RecordDiscarded(
            TelnetError::FrameTooLarge {
                size: MAX_RECORD_BYTES.saturating_add(1),
                max: MAX_RECORD_BYTES,
            }
        )])
    );

    // The state machine resynchronises: the next record is delivered normally
    assert_eq!(
        sm.process_inbound(&[0xF5, 0xC3, IAC, EOR]),
        Ok(vec![TelnetEvent::DataRecord(vec![0xF5, 0xC3])])
    );

    // Massive 100,000-byte chunk without EOR: no error, nothing delivered yet
    let mut sm2 = tn3270_session(true);
    let massive = vec![0x55_u8; 100_000];
    assert_eq!(sm2.process_inbound(&massive), Ok(vec![]));
    assert!(matches!(
        sm2.process_inbound(&[IAC, EOR]).as_deref(),
        Ok([TelnetEvent::RecordDiscarded(TelnetError::FrameTooLarge {
            size: 100_000,
            ..
        })])
    ));
}

#[test]
fn test_dos_record_buffer_doubled_iac_overflow() {
    let mut sm = tn3270_session(true);

    // Fill to 65,536 bytes
    let fill = vec![0x40_u8; MAX_RECORD_BYTES];
    assert_eq!(sm.process_inbound(&fill), Ok(vec![]));

    // Next byte is doubled IAC [IAC, IAC] (trying to insert 65,537th byte): the record is
    // discarded at its IAC EOR instead of ending the session
    assert_eq!(sm.process_inbound(&[IAC, IAC]), Ok(vec![]));
    assert_eq!(
        sm.process_inbound(&[IAC, EOR]),
        Ok(vec![TelnetEvent::RecordDiscarded(
            TelnetError::FrameTooLarge {
                size: MAX_RECORD_BYTES.saturating_add(1),
                max: MAX_RECORD_BYTES,
            }
        )])
    );
}

#[test]
fn test_dos_subnegotiation_exact_capacity_and_overflow() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // IAC SB <unsupported opt 99>
    assert_eq!(sm.process_inbound(&[IAC, SB, 99]), Ok(vec![]));

    // Buffer now has 1 byte (99). We can feed up to 1023 more bytes for total 1024.
    let fill = vec![0xAA_u8; MAX_SUBNEG_BYTES.saturating_sub(1)];
    assert_eq!(sm.process_inbound(&fill), Ok(vec![]));

    // The 1025th byte must fail with SubnegotiationTooLarge
    let res = sm.process_inbound(&[0xBB]);
    assert_eq!(
        res,
        Err(TelnetError::SubnegotiationTooLarge {
            size: MAX_SUBNEG_BYTES.saturating_add(1),
            max: MAX_SUBNEG_BYTES,
        })
    );
}

#[test]
fn test_dos_subnegotiation_doubled_iac_overflow() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    assert_eq!(sm.process_inbound(&[IAC, SB, 99]), Ok(vec![]));
    let fill = vec![0xAA_u8; MAX_SUBNEG_BYTES.saturating_sub(1)];
    assert_eq!(sm.process_inbound(&fill), Ok(vec![]));

    // Doubled IAC inside subneg [IAC, IAC] tries to push 1025th byte
    let res = sm.process_inbound(&[IAC, IAC]);
    assert_eq!(
        res,
        Err(TelnetError::SubnegotiationTooLarge {
            size: MAX_SUBNEG_BYTES.saturating_add(1),
            max: MAX_SUBNEG_BYTES,
        })
    );
}

#[test]
fn test_dos_outbound_queue_limit_enforced() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // Each unsupported DO request produces [IAC, WONT, opt] (3 bytes queued).
    // MAX_OUTBOUND_QUEUE_BYTES is 131,072.
    // 43,691 * 3 = 131,073 bytes, which exceeds 131,072.
    let req = [IAC, DO, 99];
    let iters = (MAX_OUTBOUND_QUEUE_BYTES / 3).saturating_add(1);

    let mut hit_limit = false;
    for _ in 0..iters {
        if sm.process_inbound(&req).is_err() {
            hit_limit = true;
            break;
        }
    }

    assert!(hit_limit, "Outbound queue limit should be enforced");
}

// ============================================================================
// 4. MALFORMED TN3270E HEADERS
// ============================================================================

#[test]
fn test_malformed_header_truncated_with_eor() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut sm);

    // 0 bytes: process_eor returns Ok(None) because buffer is empty
    let empty_frame = [IAC, EOR];
    assert_eq!(sm.process_inbound(&empty_frame), Ok(vec![]));

    // 1 to 4 bytes followed immediately by IAC EOR
    for len in 1..=4 {
        let mut truncated = vec![0x00_u8; len];
        truncated.push(IAC);
        truncated.push(EOR);

        let mut sm_sub = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
        helper_establish_tn3270e(&mut sm_sub);

        // A short TN3270E header discards the record; the session continues
        let res = sm_sub.process_inbound(&truncated);
        assert_eq!(
            res,
            Ok(vec![TelnetEvent::RecordDiscarded(
                TelnetError::TruncatedHeader {
                    needed: 5,
                    available: len,
                }
            )])
        );
    }
}

#[test]
fn test_malformed_header_invalid_data_types() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut sm);

    let invalid_types = [0x0A, 0x0B, 0x1F, 0x7F, 0x80, 0xFE, 0xFF];
    for &dt in &invalid_types {
        // Direct header parse
        assert_eq!(
            bastion3270_core::telnet::Tn3270eHeader::parse(&[dt, 0x00, 0x00, 0x00, 0x01]),
            Err(TelnetError::InvalidDataType(dt))
        );

        // Through wire process_inbound (0xFF must be escaped on wire as 0xFF 0xFF)
        let mut sm_sub = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
        helper_establish_tn3270e(&mut sm_sub);

        let mut frame = Vec::new();
        frame.push(dt);
        if dt == IAC {
            frame.push(IAC); // Wire escaping
        }
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, IAC, EOR]);

        // Unknown data type: the record is discarded (x3270 ignores it); session continues
        let res = sm_sub.process_inbound(&frame);
        assert_eq!(
            res,
            Ok(vec![TelnetEvent::RecordDiscarded(
                TelnetError::InvalidDataType(dt)
            )])
        );
    }
}

#[test]
fn test_malformed_header_corrupted_flags_and_seq() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut sm);
    helper_bind_session(&mut sm);

    // Arbitrary / reserved request flags (0xEE) and response flags (0xFE)
    // with sequence number 0xFFFF (escaped on wire as 0xFF 0xFF 0xFF 0xFF)
    let frame = [
        Tn3270eDataType::Data3270.as_u8(),
        0xEE,
        0xFE,
        0xFF,
        0xFF, // escaped seq hi
        0xFF,
        0xFF, // escaped seq lo
        0xC1,
        IAC,
        EOR,
    ];

    let events = sm
        .process_inbound(&frame)
        .expect("Corrupted flags should not fail parse");
    assert_eq!(events.len(), 1);
    match &events[0] {
        TelnetEvent::Tn3270eRecord { header, payload } => {
            assert_eq!(header.request_flag, 0xEE);
            assert_eq!(header.response_flag, 0xFE);
            assert_eq!(header.seq_number, 0xFFFF);
            assert_eq!(payload, &[0xC1]);
        }
        other => panic!("Expected Tn3270eRecord, got {other:?}"),
    }
}

#[test]
fn test_header_all_supported_data_types() {
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);
    helper_establish_tn3270e(&mut sm);
    helper_bind_session(&mut sm);

    let test_cases = [
        (Tn3270eDataType::ScsData, vec![0x01, 0x02]),
        (Tn3270eDataType::Response, vec![0x00]),
        (Tn3270eDataType::Request, vec![]),
        (Tn3270eDataType::PrintEoj, vec![]),
    ];

    for (dt, payload) in test_cases {
        let mut frame = vec![dt.as_u8(), 0x00, 0x00, 0x00, 0x01];
        frame.extend_from_slice(&payload);
        frame.push(IAC);
        frame.push(EOR);

        let events = sm.process_inbound(&frame).expect("Valid data type failed");
        assert_eq!(events.len(), 1);
        match &events[0] {
            TelnetEvent::Tn3270eRecord { header, payload: p } => {
                assert_eq!(header.data_type, dt);
                assert_eq!(p, &payload);
            }
            other => panic!("Expected Tn3270eRecord, got {other:?}"),
        }
    }

    // SSCP-LU data switches to SSCP-LU mode, reported before the data (x3270 `process_eor`).
    let sscp = [
        Tn3270eDataType::SscpLuData.as_u8(),
        0x00,
        0x00,
        0x00,
        0x01,
        0x11,
        0x22,
        IAC,
        EOR,
    ];
    assert_eq!(
        sm.process_inbound(&sscp).expect("SSCP-LU frame"),
        vec![
            TelnetEvent::HostModeChanged(HostMode::SscpLu),
            TelnetEvent::SscpLuData(vec![0x11, 0x22]),
        ]
    );

    // BID needs CONTENTION-RESOLUTION, which is never negotiated: dropped (x3270 `process_eor`).
    let bid = [
        Tn3270eDataType::Bid.as_u8(),
        0x00,
        0x00,
        0x00,
        0x01,
        IAC,
        EOR,
    ];
    assert_eq!(
        sm.process_inbound(&bid).expect("BID frame"),
        vec![TelnetEvent::RecordDiscarded(
            TelnetError::FunctionNotNegotiated(0x09)
        )]
    );

    // NVT data switches to NVT mode and generates TelnetEvent::NvtData
    let nvt_frame = [
        Tn3270eDataType::NvtData.as_u8(),
        0x00,
        0x00,
        0x00,
        0x01,
        b'H',
        b'i',
        IAC,
        EOR,
    ];
    let nvt_evs = sm.process_inbound(&nvt_frame).expect("NvtData failed");
    assert_eq!(
        nvt_evs,
        vec![
            TelnetEvent::HostModeChanged(HostMode::Nvt),
            TelnetEvent::NvtData {
                data: b"Hi".to_vec(),
                ack: None,
            },
        ]
    );
}

// ============================================================================
// 5. SNA BIND RU EDGE CASES
// ============================================================================

#[test]
fn test_sna_bind_ru_empty_and_invalid_opcode() {
    assert_eq!(
        BindImageInfo::parse(&[], TerminalModel::Model2),
        Err(TelnetError::InvalidBindRu("empty BIND RU"))
    );

    assert_eq!(
        BindImageInfo::parse(&[0x00], TerminalModel::Model2),
        Err(TelnetError::InvalidBindRu(
            "invalid BIND RU opcode (expected 0x31)"
        ))
    );

    assert_eq!(
        BindImageInfo::parse(&[0x32, 0x00], TerminalModel::Model2),
        Err(TelnetError::InvalidBindRu(
            "invalid BIND RU opcode (expected 0x31)"
        ))
    );
}

/// `(default rows, default cols, alternate rows, alternate cols)` of a parsed BIND.
fn sizes_of(info: &BindImageInfo) -> Option<(u16, u16, u16, u16)> {
    info.sizes.map(|s| {
        (
            s.default.rows,
            s.default.cols,
            s.alternate.rows,
            s.alternate.cols,
        )
    })
}

#[test]
fn test_sna_bind_ru_truncated_slices() {
    // A BIND RU with opcode 0x31 but truncated at all lengths from 1 to 24
    let full_ru = [
        BIND_RU, 0x01, 0x03, 0x03, 0xB1, 0x90, 0x30, 0x80, 0x00, 0x00, 0x87, 0xC7, 0x80, 0x00,
        0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x18, 0x50, 0x18, 0x50,
    ];

    for len in 1..=full_ru.len() {
        let truncated = &full_ru[..len];
        let info = BindImageInfo::parse(truncated, TerminalModel::Model4)
            .expect("Truncated RU parse should not fail");

        // No screen size byte: no sizes (the current ones stay), no panic
        assert_eq!(sizes_of(&info), None);
        assert_eq!(info.plu_name, None);
    }
}

#[test]
fn test_sna_bind_ru_model_byte_variations() {
    let mut ru = vec![0x00_u8; 35];
    ru[0] = BIND_RU;

    // ssize 0x00 / 0x02 -> 24x80 default and alternate
    for ssize in [0x00, 0x02] {
        ru[24] = ssize;
        let info = BindImageInfo::parse(&ru, TerminalModel::Model5).expect("ssize");
        assert_eq!(sizes_of(&info), Some((24, 80, 24, 80)));
    }

    // ssize 0x03 -> 24x80 default, the model size as alternate
    ru[24] = 0x03;
    let dyn_model = TerminalModel::new_dynamic(62, 160).expect("dyn model");
    for (model, alt) in [
        (TerminalModel::Model2, (24, 80)),
        (TerminalModel::Model3, (32, 80)),
        (TerminalModel::Model5, (27, 132)),
        (dyn_model, (62, 160)),
    ] {
        let info = BindImageInfo::parse(&ru, model).expect("0x03");
        assert_eq!(sizes_of(&info), Some((24, 80, alt.0, alt.1)));
    }

    // Unknown ssize values carry no sizes (x3270 `bind_state = 0`)
    for s in [0x01, 0x04, 0x10, 0x55, 0xAA, 0xFF] {
        ru[24] = s;
        let info_inv = BindImageInfo::parse(&ru, TerminalModel::Model4).expect("inv ssize");
        assert_eq!(sizes_of(&info_inv), None);
    }
}

#[test]
fn test_sna_bind_ru_dynamic_explicit_dimensions() {
    let mut ru = vec![0x00_u8; 35];
    ru[0] = BIND_RU;

    // ssize 0x7E: explicit default rows/cols at offsets 20, 21, used for both sizes
    ru[24] = 0x7E;
    ru[20] = 43; // RD
    ru[21] = 80; // CD
    let info = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("0x7E failed");
    assert_eq!(sizes_of(&info), Some((43, 80, 43, 80)));

    // Zero dimensions are reported as they are; the presentation space rejects them
    ru[20] = 0;
    ru[21] = 0;
    let info_zero = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("zero failed");
    assert_eq!(sizes_of(&info_zero), Some((0, 0, 0, 0)));

    // ssize 0x7F: explicit default (20,21) and explicit alternate (22,23)
    ru[24] = 0x7F;
    ru[20] = 24;
    ru[21] = 80;
    ru[22] = 62; // RA
    ru[23] = 160; // CA
    let info_7f = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("0x7F failed");
    assert_eq!(sizes_of(&info_7f), Some((24, 80, 62, 160)));
}

#[test]
fn test_sna_bind_ru_corrupted_plu_names() {
    let mut ru = vec![0x00_u8; 35];
    ru[0] = BIND_RU;

    // Case 1: namelen exceeds slice bounds (namelen = 255 with 35 byte buffer)
    ru[27] = 255;
    let info1 = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("parse failed");
    assert_eq!(info1.plu_name, None);

    // Case 2: namelen = 0
    ru[27] = 0;
    let info2 = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("parse failed");
    assert_eq!(info2.plu_name, None);

    // Case 3: all EBCDIC spaces (0x40) trimmed to None
    ru[27] = 4;
    ru[28..32].copy_from_slice(&[0x40, 0x40, 0x40, 0x40]);
    let info3 = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("parse failed");
    assert_eq!(info3.plu_name, None);

    // Case 4: valid EBCDIC name with trailing spaces: "TSO " -> "TSO"
    // "TSO" in EBCDIC CP037: [0xE3, 0xE2, 0xD6]
    ru[27] = 5;
    ru[28..33].copy_from_slice(&[0xE3, 0xE2, 0xD6, 0x40, 0x40]);
    let info4 = BindImageInfo::parse(&ru, TerminalModel::Model2).expect("parse failed");
    assert_eq!(info4.plu_name, Some("TSO".to_string()));
}

// ============================================================================
// 6. PSEUDO-RANDOM BYTE FUZZING & INVARIANT HARNESS
// ============================================================================

/// Deterministic 64-bit XorShift pseudo-random number generator.
struct SimpleRng(u64);

impl SimpleRng {
    fn next_u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u32() & 0xFF) as u8
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        let span = max.saturating_sub(min).saturating_add(1);
        min.saturating_add((self.next_u32() as usize) % span)
    }
}

#[test]
fn test_fuzz_random_byte_stream_never_panics() {
    let mut rng = SimpleRng(0xDEAD_BEEF_CAFE_BABE);
    let mut sm = TelnetStateMachine::new(TerminalModel::Model2, true, true, None);

    // Generate 50,000 arbitrary bytes in random chunk sizes (1..128)
    let total_bytes: usize = 50_000;
    let mut generated: usize = 0;

    while generated < total_bytes {
        let chunk_len = rng.next_range(1, 128);
        let mut chunk = Vec::with_capacity(chunk_len);
        for _ in 0..chunk_len {
            chunk.push(rng.next_byte());
        }

        // Must never panic! Result can be Ok or Err
        let _ = sm.process_inbound(&chunk);

        // Periodically drain outbound queue to simulate network transmission
        let _ = sm.take_outbound();

        generated = generated.saturating_add(chunk_len);
    }
}

#[test]
fn test_fuzz_interleaved_negotiation_torture() {
    let mut rng = SimpleRng(0x1234_5678_9ABC_DEF0);

    for model in [
        TerminalModel::Model2,
        TerminalModel::Model3,
        TerminalModel::Model4,
        TerminalModel::Model5,
    ] {
        let mut sm = TelnetStateMachine::new(model, false, false, None);

        for _ in 0..100 {
            let burst_type = rng.next_range(0, 4);
            match burst_type {
                0 => {
                    // Option negotiation bursts
                    let opt = rng.next_byte();
                    let cmd = match rng.next_range(0, 3) {
                        0 => DO,
                        1 => DONT,
                        2 => WILL,
                        _ => WONT,
                    };
                    let _ = sm.process_inbound(&[IAC, cmd, opt]);
                }
                1 => {
                    // Subnegotiation fragments
                    let opt = rng.next_byte();
                    let payload_len = rng.next_range(0, 32);
                    let mut subneg = vec![IAC, SB, opt];
                    for _ in 0..payload_len {
                        subneg.push(rng.next_byte());
                    }
                    if rng.next_range(0, 1) == 1 {
                        subneg.push(IAC);
                        subneg.push(SE);
                    }
                    let _ = sm.process_inbound(&subneg);
                }
                2 => {
                    // Data record bursts
                    let data_len = rng.next_range(0, 100);
                    let mut data = vec![rng.next_byte(); data_len];
                    if rng.next_range(0, 1) == 1 {
                        data.push(IAC);
                        data.push(EOR);
                    }
                    let _ = sm.process_inbound(&data);
                }
                _ => {
                    // Drain outbound queue
                    let _ = sm.take_outbound();
                }
            }
        }
    }
}
