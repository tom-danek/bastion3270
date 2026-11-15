//! Fuzzes the 3270 data stream parser (`x3270` `process_ds`) and everything that reads the
//! resulting presentation space.
//!
//! Input layout: byte 0 selects the terminal model (bits 0-2, see `model_from_selector`) and
//! the code page (bit 3: CP037 or IBM870); the rest is a sequence of 3270 records, each with
//! a big-endian `u16` length prefix (`0` = the rest of the input). The records are applied in
//! order to one presentation space, as a host session would send them.
//!
//! After every record the target asserts:
//! * cursor and buffer address are inside the screen, and capacity is rows x cols;
//! * a Read Buffer reply starts with its AID and has at least AID + cursor address + one byte
//!   per buffer position (`x3270` `ctlr_read_buffer`);
//! * a Read Modified for a short-read AID (PA1-PA3, Clear) is the AID byte alone, a test
//!   request starts with the test request header (`x3270` `ctlr_read_modified`);
//! * structured field query replies for every Read Partition request are `AID_SF` followed
//!   by well-formed structured fields;
//! * an SSCP-LU write of the same bytes onto a copy of the screen succeeds and keeps the
//!   addresses in bounds (`x3270` `ctlr_write_sscp_lu`);
//! * the zero-trust projection (`SafeScreenView`) masks field attributes and every character
//!   in a non-display field, and the browser wire projection (`wire_screen`) keeps exactly
//!   one character per cell and covers every cell with style runs.
#![no_main]

use bastion3270_core::datastream::response::{
    build_read_buffer_with_aid, build_read_modified, build_sscp_read, build_test_request,
    is_short_read_aid, AID_CLEAR, AID_NO, AID_PA1, AID_SYSREQ, TEST_REQUEST_HEADER,
};
use bastion3270_core::datastream::sscp::write_sscp_lu;
use bastion3270_core::datastream::{ReadPartitionRequest, AID_READ_PARTITION};
use bastion3270_core::{
    CodePage, DataStreamParser, PresentationSpace, QueryReplyBuilder, AID_SF, CP037, IBM870,
    SFID_QREPLY,
};
use bastion3270_fuzz::{
    assert_addresses_in_bounds, assert_safe_view, model_from_selector, split_records,
};
use bastion3270_server::protocol::wire_screen;
use libfuzzer_sys::fuzz_target;

/// AID `0x7D` (Enter).
const AID_ENTER: u8 = 0x7D;

/// A query reply is `AID_SF` followed by complete structured fields `len_hi len_lo 0x81
/// qcode ...` whose lengths add up exactly to the rest of the record (3270 Data Stream
/// Programmer's Reference, Query Reply).
fn check_query_reply(reply: &[u8]) {
    let Some((&aid, mut fields)) = reply.split_first() else {
        panic!("empty query reply");
    };
    assert_eq!(aid, AID_SF);
    assert!(!fields.is_empty(), "query reply without structured fields");
    while let [hi, lo, ..] = fields {
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        assert!(
            len >= 4 && len <= fields.len(),
            "malformed query reply length {len}"
        );
        assert_eq!(fields.get(2), Some(&SFID_QREPLY));
        fields = fields.get(len..).unwrap_or_default();
    }
    assert!(
        fields.is_empty(),
        "trailing bytes after the last query reply"
    );
}

fn check_replies(ps: &PresentationSpace) {
    for aid in [AID_NO, AID_ENTER, AID_READ_PARTITION] {
        let rb = build_read_buffer_with_aid(ps, aid);
        assert_eq!(rb.first(), Some(&aid));
        assert!(
            rb.len() >= 3 + ps.capacity(),
            "read buffer shorter than the screen"
        );
    }
    for aid in [AID_ENTER, AID_PA1, AID_CLEAR, AID_NO] {
        let rm = build_read_modified(ps, aid, false);
        assert_eq!(rm.first(), Some(&aid));
        if is_short_read_aid(aid) {
            assert_eq!(rm, [aid], "short read must carry the AID only");
        }
        let rma = build_read_modified(ps, aid, true);
        assert_eq!(rma.first(), Some(&aid));
    }
    let test_request = build_test_request(ps);
    assert!(test_request.starts_with(&TEST_REQUEST_HEADER));
    assert_eq!(build_read_modified(ps, AID_SYSREQ, false), test_request);
    let _ = build_sscp_read(ps);
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let model = model_from_selector(selector);
    let codepage: &dyn CodePage = if selector & 0x08 == 0 {
        &CP037
    } else {
        &IBM870
    };
    let mut ps = PresentationSpace::new(model);
    let queries = QueryReplyBuilder::new(model, codepage).with_color(selector & 0x10 != 0);

    for record in split_records(rest) {
        // The SSCP-LU writer gets the same bytes on a copy of the screen as it was before.
        let mut sscp = ps.clone();
        assert!(
            write_sscp_lu(&mut sscp, record).is_ok(),
            "SSCP-LU write failed on a consistent screen"
        );
        assert_addresses_in_bounds(&sscp);

        // Rejections are expected for hostile records; `process` reports them in the result.
        let result = DataStreamParser::process(record, &mut ps);
        assert_addresses_in_bounds(&ps);

        for request in &result.read_partition {
            match request {
                ReadPartitionRequest::Query(query) => {
                    check_query_reply(&queries.build_from_request(query));
                }
                ReadPartitionRequest::ReadBuffer | ReadPartitionRequest::ReadModified { .. } => {}
            }
        }

        check_replies(&ps);
        check_projection(&ps, codepage);
    }
});

/// The zero-trust and browser wire projections of the screen.
fn check_projection(ps: &PresentationSpace, codepage: &dyn CodePage) {
    let view = assert_safe_view(ps, codepage);
    let wire = wire_screen(&view, false);
    assert_eq!(wire.text.len(), usize::from(ps.rows()));
    for row in &wire.text {
        assert_eq!(row.chars().count(), usize::from(ps.cols()));
    }
    let covered: u64 = wire.runs.iter().map(|r| u64::from(r.n)).sum();
    assert_eq!(
        covered,
        ps.capacity() as u64,
        "style runs must cover every cell"
    );
}
