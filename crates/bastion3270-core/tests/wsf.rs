//! Integration tests for the WSF (Write Structured Field) query reply engine.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

use bastion3270_core::ebcdic::{CP037, IBM870};
use bastion3270_core::model::TerminalModel;
use bastion3270_core::wsf::{
    parse_read_partition, QueryReplyBuilder, QueryRequest, WsfError, AID_SF, QR_CHARSETS, QR_COLOR,
    QR_HIGHLIGHTING, QR_IMP_PART, QR_NULL, QR_REPLY_MODES, QR_SUMMARY, QR_USABLE_AREA, SFID_QREPLY,
    SF_READ_PART, SF_RPQ_ALL, SF_RPQ_EQUIV, SF_RPQ_LIST, SF_RP_QLIST, SF_RP_QUERY,
    SUPPORTED_QUERY_CODES,
};

#[test]
fn test_parse_read_partition_valid_query() {
    let cp = &CP037;
    let _builder = QueryReplyBuilder::new(TerminalModel::Model2, cp);

    // Bare query command: [0x01, 0xFF, 0x02]
    let bare = [SF_READ_PART, 0xFF, SF_RP_QUERY];
    let req = parse_read_partition(&bare);
    assert_eq!(req, Ok(QueryRequest::QueryAll));

    // Framed with 2-byte length header: [0x00, 0x03, 0x01, 0xFF, 0x02]
    let framed = [0x00, 0x03, SF_READ_PART, 0xFF, SF_RP_QUERY];
    let req_framed = parse_read_partition(&framed);
    assert_eq!(req_framed, Ok(QueryRequest::QueryAll));
}

#[test]
fn test_parse_read_partition_valid_query_list() {
    // List request: [SF_READ_PART, 0xFF, SF_RP_QLIST, SF_RPQ_LIST, QR_USABLE_AREA, QR_COLOR]
    let list_req = [
        SF_READ_PART,
        0xFF,
        SF_RP_QLIST,
        SF_RPQ_LIST,
        QR_USABLE_AREA,
        QR_COLOR,
    ];
    let res = parse_read_partition(&list_req);
    assert_eq!(
        res,
        Ok(QueryRequest::QueryList(vec![QR_USABLE_AREA, QR_COLOR]))
    );

    // List Equivalent request
    let equiv_req = [SF_READ_PART, 0xFF, SF_RP_QLIST, SF_RPQ_EQUIV];
    let res_equiv = parse_read_partition(&equiv_req);
    assert_eq!(res_equiv, Ok(QueryRequest::QueryListEquivalent));

    // List All request
    let all_req = [SF_READ_PART, 0xFF, SF_RP_QLIST, SF_RPQ_ALL];
    let res_all = parse_read_partition(&all_req);
    assert_eq!(res_all, Ok(QueryRequest::QueryListAll));
}

#[test]
fn test_parse_read_partition_errors() {
    // Truncated empty slice
    assert_eq!(
        parse_read_partition(&[]),
        Err(WsfError::TruncatedField {
            expected: 3,
            available: 0
        })
    );

    // Truncated short slice
    assert_eq!(
        parse_read_partition(&[SF_READ_PART, 0xFF]),
        Err(WsfError::TruncatedField {
            expected: 3,
            available: 2
        })
    );

    // Invalid partition ID (expected 0xFF)
    assert_eq!(
        parse_read_partition(&[SF_READ_PART, 0x01, SF_RP_QUERY]),
        Err(WsfError::InvalidPartition {
            expected: 0xFF,
            actual: 0x01
        })
    );

    // Invalid query type
    assert_eq!(
        parse_read_partition(&[SF_READ_PART, 0xFF, 0x99]),
        Err(WsfError::InvalidQueryType(0x99))
    );

    // Truncated Query List (missing list type byte)
    assert_eq!(
        parse_read_partition(&[SF_READ_PART, 0xFF, SF_RP_QLIST]),
        Err(WsfError::TruncatedField {
            expected: 4,
            available: 3
        })
    );

    // Invalid Query List request type
    assert_eq!(
        parse_read_partition(&[SF_READ_PART, 0xFF, SF_RP_QLIST, 0x77]),
        Err(WsfError::InvalidRequestType(0x77))
    );
}

#[test]
fn test_query_reply_summary_structure() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);
    let reply = builder.build_list(&[QR_SUMMARY]);

    // Starts with AID_SF
    assert_eq!(reply.first(), Some(&AID_SF));

    // Length of Summary reply: 4 header bytes + SUPPORTED_QUERY_CODES.len()
    let expected_len = (4 + SUPPORTED_QUERY_CODES.len()) as u16;
    let len_hi = (expected_len >> 8) as u8;
    let len_lo = (expected_len & 0xFF) as u8;

    assert_eq!(reply.get(1), Some(&len_hi));
    assert_eq!(reply.get(2), Some(&len_lo));
    assert_eq!(reply.get(3), Some(&SFID_QREPLY));
    assert_eq!(reply.get(4), Some(&QR_SUMMARY));

    // Payload matches SUPPORTED_QUERY_CODES
    let payload = reply.get(5..).unwrap_or(&[]);
    assert_eq!(payload, &SUPPORTED_QUERY_CODES);
}

#[test]
fn test_query_reply_usable_area_dimensions() {
    // Test Model 2 (24x80)
    let b2 = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);
    let r2 = b2.build_list(&[QR_USABLE_AREA]);
    // Layout in envelope:
    // 0: AID_SF, 1-2: len, 3: SFID, 4: QR_USABLE_AREA
    // 5-6: flags (0x01, 0x00)
    // 7-8: width in cells (big endian)
    // 9-10: height in cells (big endian)
    assert_eq!(r2.get(7), Some(&0x00));
    assert_eq!(r2.get(8), Some(&80));
    assert_eq!(r2.get(9), Some(&0x00));
    assert_eq!(r2.get(10), Some(&24));

    // Test Model 4 (43x80)
    let b4 = QueryReplyBuilder::new(TerminalModel::Model4, &CP037);
    let r4 = b4.build_list(&[QR_USABLE_AREA]);
    assert_eq!(r4.get(7), Some(&0x00));
    assert_eq!(r4.get(8), Some(&80));
    assert_eq!(r4.get(9), Some(&0x00));
    assert_eq!(r4.get(10), Some(&43));

    // Test Model 5 (27x132)
    let b5 = QueryReplyBuilder::new(TerminalModel::Model5, &CP037);
    let r5 = b5.build_list(&[QR_USABLE_AREA]);
    assert_eq!(r5.get(7), Some(&0x00));
    assert_eq!(r5.get(8), Some(&132));
    assert_eq!(r5.get(9), Some(&0x00));
    assert_eq!(r5.get(10), Some(&27));

    // Test Dynamic (62x160)
    let bd = QueryReplyBuilder::new(
        TerminalModel::Dynamic {
            rows: 62,
            cols: 160,
        },
        &CP037,
    );
    let rd = bd.build_list(&[QR_USABLE_AREA]);
    assert_eq!(rd.get(7), Some(&0x00));
    assert_eq!(rd.get(8), Some(&160));
    assert_eq!(rd.get(9), Some(&0x00));
    assert_eq!(rd.get(10), Some(&62));
}

#[test]
fn test_query_reply_color_mode() {
    // Color 3279 (16 colors)
    let b_color = QueryReplyBuilder::new(TerminalModel::Model2, &CP037).with_color(true);
    let r_color = b_color.build_list(&[QR_COLOR]);
    assert_eq!(r_color.first(), Some(&AID_SF));
    assert_eq!(r_color.get(3), Some(&SFID_QREPLY));
    assert_eq!(r_color.get(4), Some(&QR_COLOR));
    // Number of color pairs at byte 6 is 16 (0x10)
    assert_eq!(r_color.get(6), Some(&16));
    // In color mode, color attribute 0xF1 maps to 0xF1
    assert_eq!(r_color.get(10), Some(&0xF1));

    // Monochrome 3278
    let b_mono = QueryReplyBuilder::new(TerminalModel::Model2, &CP037).with_color(false);
    let r_mono = b_mono.build_list(&[QR_COLOR]);
    assert_eq!(r_mono.first(), Some(&AID_SF));
    assert_eq!(r_mono.get(3), Some(&SFID_QREPLY));
    assert_eq!(r_mono.get(4), Some(&QR_COLOR));
    // In monochrome mode, color attribute 0xF1 maps to 0x00
    assert_eq!(r_mono.get(10), Some(&0x00));
}

#[test]
fn test_query_reply_character_sets_codepage() {
    let b_cp037 = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);
    let r_cp037 = b_cp037.build_list(&[QR_CHARSETS]);
    // Character Sets SF layout:
    // [AID_SF, len_hi, len_lo, 0x81, 0x85, flags (2), w, h, ..., cgcsgid (4)]
    // CGCSGID for CP037 is CPGID 37 (0x0025)
    let len_037 = r_cp037.len();
    assert!(len_037 >= 20);
    // CGCSGID CPGID is located at byte index 19..21 in the envelope
    let cpgid_037_hi = r_cp037.get(19).copied().unwrap_or(0);
    let cpgid_037_lo = r_cp037.get(20).copied().unwrap_or(0);
    let cpgid_037 = (u16::from(cpgid_037_hi) << 8) | u16::from(cpgid_037_lo);
    assert_eq!(cpgid_037, 37);

    // IBM870 (Latin 2)
    let b_cp870 = QueryReplyBuilder::new(TerminalModel::Model2, &IBM870);
    let r_cp870 = b_cp870.build_list(&[QR_CHARSETS]);
    let cpgid_870_hi = r_cp870.get(19).copied().unwrap_or(0);
    let cpgid_870_lo = r_cp870.get(20).copied().unwrap_or(0);
    let cpgid_870 = (u16::from(cpgid_870_hi) << 8) | u16::from(cpgid_870_lo);
    assert_eq!(cpgid_870, 870);
}

#[test]
fn test_query_reply_reply_modes_and_highlighting() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // Highlighting
    let r_hl = builder.build_list(&[QR_HIGHLIGHTING]);
    assert_eq!(r_hl.first(), Some(&AID_SF));
    assert_eq!(r_hl.get(3), Some(&SFID_QREPLY));
    assert_eq!(r_hl.get(4), Some(&QR_HIGHLIGHTING));
    // Highlighting pairs count at byte 5
    let hl_pairs = r_hl.get(5).copied().unwrap_or(0);
    assert!(hl_pairs >= 4);

    // Reply Modes
    let r_rm = builder.build_list(&[QR_REPLY_MODES]);
    assert_eq!(r_rm.first(), Some(&AID_SF));
    assert_eq!(r_rm.get(3), Some(&SFID_QREPLY));
    assert_eq!(r_rm.get(4), Some(&QR_REPLY_MODES));
    // Supported modes at byte 5..: Field (0x00), Extended Field (0x01), Character (0x02)
    let modes = r_rm.get(5..).unwrap_or(&[]);
    assert!(modes.contains(&0x00));
    assert!(modes.contains(&0x01));
    assert!(modes.contains(&0x02));
}

#[test]
fn test_query_reply_implicit_partition() {
    let b4 = QueryReplyBuilder::new(TerminalModel::Model4, &CP037);
    let r = b4.build_list(&[QR_IMP_PART]);
    assert_eq!(r.first(), Some(&AID_SF));
    assert_eq!(r.get(3), Some(&SFID_QREPLY));
    assert_eq!(r.get(4), Some(&QR_IMP_PART));

    // Implicit Partition SF payload contains:
    // [flags (2), len_spec (1), part_size (1), res (1), def_w (2), def_h (2), alt_w (2), alt_h (2)]
    // Envelope indices:
    // 0: AID_SF
    // 1-2: len
    // 3: SFID (0x81)
    // 4: QR_IMP_PART (0xA6)
    // 5-6: reserved (0x00, 0x00)
    // 7: 0x0B
    // 8: 0x01
    // 9: reserved (0x00)
    // 10-11: default width (80)
    // 12-13: default height (24)
    // 14-15: alternate width (80)
    // 16-17: alternate height (43 for Model 4)
    assert_eq!(r.get(10), Some(&0x00));
    assert_eq!(r.get(11), Some(&80));
    assert_eq!(r.get(12), Some(&0x00));
    assert_eq!(r.get(13), Some(&24));

    assert_eq!(r.get(14), Some(&0x00));
    assert_eq!(r.get(15), Some(&80));
    assert_eq!(r.get(16), Some(&0x00));
    assert_eq!(r.get(17), Some(&43));
}

#[test]
fn test_query_reply_canonical_ordering_and_deduplication() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // Request out of order and with duplicates: Color, Summary, Usable Area, Color
    let requested = [QR_COLOR, QR_SUMMARY, QR_USABLE_AREA, QR_COLOR];
    let reply = builder.build_list(&requested);

    // Parse structured fields out of the reply envelope
    let mut sf_codes = Vec::new();
    let mut idx = 1; // Skip AID_SF
    while idx + 4 <= reply.len() {
        let len_hi = reply.get(idx).copied().unwrap_or(0);
        let len_lo = reply.get(idx + 1).copied().unwrap_or(0);
        let sf_len = (usize::from(len_hi) << 8) | usize::from(len_lo);
        let qcode = reply.get(idx + 3).copied().unwrap_or(0);
        sf_codes.push(qcode);
        if sf_len == 0 {
            break;
        }
        idx = idx.saturating_add(sf_len);
    }

    // Must be in canonical order: QR_SUMMARY, QR_USABLE_AREA, QR_COLOR
    assert_eq!(sf_codes, vec![QR_SUMMARY, QR_USABLE_AREA, QR_COLOR]);
}

#[test]
fn test_query_reply_unsupported_or_empty_produces_null() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // Empty request list
    let r_empty = builder.build_list(&[]);
    assert_eq!(r_empty, vec![AID_SF, 0x00, 0x04, SFID_QREPLY, QR_NULL]);

    // Completely unknown/unsupported QCODE
    let r_unknown = builder.build_list(&[0x99]);
    assert_eq!(r_unknown, vec![AID_SF, 0x00, 0x04, SFID_QREPLY, QR_NULL]);
}

#[test]
fn test_handle_read_partition_end_to_end() {
    let builder = QueryReplyBuilder::new(TerminalModel::Model2, &CP037);

    // Inbound Query All: [0x01, 0xFF, 0x02]
    let query_wire = [SF_READ_PART, 0xFF, SF_RP_QUERY];
    let reply = builder.handle_read_partition(&query_wire);
    assert!(reply.is_ok());

    let payload = reply.unwrap_or_default();
    assert_eq!(payload.first(), Some(&AID_SF));

    // Verify all 8 supported structured fields are present
    let mut sf_count: usize = 0;
    let mut idx = 1;
    while idx + 4 <= payload.len() {
        let len_hi = payload.get(idx).copied().unwrap_or(0);
        let len_lo = payload.get(idx + 1).copied().unwrap_or(0);
        let sf_len = (usize::from(len_hi) << 8) | usize::from(len_lo);
        sf_count = sf_count.saturating_add(1);
        if sf_len == 0 {
            break;
        }
        idx = idx.saturating_add(sf_len);
    }
    assert_eq!(sf_count, SUPPORTED_QUERY_CODES.len());
}
