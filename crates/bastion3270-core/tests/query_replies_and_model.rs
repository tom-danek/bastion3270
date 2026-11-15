//! Query replies, structured field validation and terminal model rules, checked against
//! `x3270` `sf.c` (`write_structured_field`, `sf_read_part`, `sf_erase_reset`,
//! `sf_create_partition`, `sf_outbound_ds`, `do_qr_summary`), `rpq.c` (`do_qr_rpqnames`),
//! `telnet.c` (`create_3270_termtype`) and `ctlr.c` (`oversize_init`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::datastream::{DataStreamParser, RejectKind};
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::wsf::{QueryReplyBuilder, QueryRequest, QR_RPQNAMES, QR_SUMMARY};
use bastion3270_core::{ModelError, PresentationSpace, TerminalModel};

/// The query replies of a Query All, as `(qcode, payload after the qcode)`.
fn replies() -> Vec<(u8, Vec<u8>)> {
    let reply = QueryReplyBuilder::new(TerminalModel::Model2, &CP037)
        .build_from_request(&QueryRequest::QueryAll);
    let mut out = Vec::new();
    let mut i = 1; // skip AID 0x88
    while i + 4 <= reply.len() {
        let len = (usize::from(reply[i]) << 8) | usize::from(reply[i + 1]);
        out.push((reply[i + 3], reply[i + 4..i + len].to_vec()));
        i += len;
    }
    out
}

/// Result of one WSF holding the given structured field payload (without length).
fn wsf(field: &[u8]) -> Option<RejectKind> {
    let len = u16::try_from(field.len() + 2).unwrap().to_be_bytes();
    let mut stream = vec![0xF3, len[0], len[1]];
    stream.extend_from_slice(field);
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    DataStreamParser::process(&stream, &mut ps)
        .rejected
        .map(|e| e.reject_kind())
}

#[test]
fn query_reply_includes_rpq_names_with_the_program_name() {
    let replies = replies();
    let summary = &replies.iter().find(|(q, _)| *q == QR_SUMMARY).unwrap().1;
    assert!(summary.contains(&QR_RPQNAMES));
    assert!(
        !summary.contains(&0x95),
        "no DDM without IND$FILE file transfer"
    );

    let rpq = &replies.iter().find(|(q, _)| *q == QR_RPQNAMES).unwrap().1;
    let name: Vec<u8> = "bastion3270"
        .chars()
        .map(|c| CP037.char_to_ebcdic(c).unwrap())
        .collect();
    // Device 0, model 0, length byte (1 + name), program name; no optional terms.
    let mut expected = vec![
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        u8::try_from(name.len() + 1).unwrap(),
    ];
    expected.extend_from_slice(&name);
    assert_eq!(rpq, &expected);
}

#[test]
fn invalid_structured_fields_are_rejected() {
    let reject = Some(RejectKind::CommandReject);
    // Unknown structured field (e.g. IND$FILE Transfer Data 0xD0).
    assert_eq!(wsf(&[0xD0, 0x00, 0x00]), reject);
    // Erase/Reset with an unknown type, or with extra bytes.
    assert_eq!(wsf(&[0x03, 0x40]), reject);
    assert_eq!(wsf(&[0x03, 0x00, 0x00]), reject);
    // Read Buffer for the query partition; Query for partition 0.
    assert_eq!(wsf(&[0x01, 0xFF, 0xF2]), reject);
    assert_eq!(wsf(&[0x01, 0x00, 0x02]), reject);
    // Query List with an unknown request type, or without one.
    assert_eq!(wsf(&[0x01, 0xFF, 0x03, 0x20]), reject);
    assert_eq!(wsf(&[0x01, 0xFF, 0x03]), reject);
    // Outbound 3270DS with a CCW command code (EW = 0x05) or for partition 1.
    assert_eq!(wsf(&[0x40, 0x00, 0x05, 0xC3]), reject);
    assert_eq!(wsf(&[0x40, 0x01, 0xF5, 0xC3]), reject);
    // Create Partition for partition 1, or with an invalid unit of measure.
    assert_eq!(wsf(&[0x0C, 0x01]), reject);
    assert_eq!(wsf(&[0x0C, 0x00, 0x10]), reject);
}

#[test]
fn valid_structured_fields_are_accepted() {
    assert_eq!(wsf(&[0x03, 0x80]), None); // Erase/Reset alternate
    assert_eq!(wsf(&[0x01, 0xFF, 0x03, 0x00, 0x81]), None); // Query List
    assert_eq!(wsf(&[0x40, 0x00, 0xF5, 0xC3]), None); // Outbound 3270DS EW
    assert_eq!(wsf(&[0x0C, 0x00, 0x00]), None); // Create Partition 0: accepted, no effect
}

#[test]
fn models_4_and_5_report_3278_even_in_colour() {
    assert_eq!(
        TerminalModel::Model2.terminal_type_name(true, true),
        "IBM-3279-2-E"
    );
    assert_eq!(
        TerminalModel::Model3.terminal_type_name(true, false),
        "IBM-3279-3"
    );
    assert_eq!(
        TerminalModel::Model4.terminal_type_name(true, true),
        "IBM-3278-4-E"
    );
    assert_eq!(
        TerminalModel::Model5.terminal_type_name(true, false),
        "IBM-3278-5"
    );
}

#[test]
fn a_dynamic_size_must_be_at_least_24x80() {
    assert_eq!(
        TerminalModel::new_dynamic(20, 80),
        Err(ModelError::BelowMinimum { rows: 20, cols: 80 })
    );
    assert_eq!(
        TerminalModel::new_dynamic(24, 40),
        Err(ModelError::BelowMinimum { rows: 24, cols: 40 })
    );
    assert!(TerminalModel::new_dynamic(24, 80).is_ok());
    assert!(TerminalModel::new_dynamic(62, 160)
        .unwrap()
        .requires_extended());
}
