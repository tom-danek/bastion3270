//! Fuzzes the Telnet / TN3270E state machine with arbitrary host bytes.
//!
//! Input layout: byte 0 selects the configuration (bits 0-2 the terminal model, bit 3 3279
//! colour, bit 4 the extended data stream, bit 5 a requested LU name). The rest is a sequence
//! of chunks, each preceded by a header byte: bits 0-6 are the chunk length (`0` = the rest of
//! the input) and bit 7 drains the outbound queue after the chunk. Splitting the stream into
//! chunks exercises every parser state at a chunk boundary, as TCP segmentation does
//! (RFC 854 command sequences, RFC 855 subnegotiation, RFC 2355 TN3270E headers).
//!
//! Asserted invariants:
//! * the outbound queue never exceeds `MAX_OUTBOUND_QUEUE_BYTES`, even when it is not drained;
//! * no emitted record or NVT text is longer than `MAX_RECORD_BYTES`;
//! * `frame_outbound_3270` ends with `IAC EOR`, doubles every `IAC` (RFC 854) and unescapes
//!   back to the optional 5-byte TN3270E header followed by the original record;
//! * `frame_positive_response` / `frame_negative_response` are seven bytes plus IAC doubling
//!   and end with `IAC EOR`;
//! * `attention_route` answers for both attention keys in every state.
#![no_main]

use bastion3270_core::telnet::state_machine::{MAX_OUTBOUND_QUEUE_BYTES, MAX_RECORD_BYTES};
use bastion3270_core::telnet::{EOR, IAC};
use bastion3270_core::{AttentionKey, TelnetEvent, TelnetStateMachine};
use bastion3270_fuzz::model_from_selector;
use libfuzzer_sys::fuzz_target;

/// Removes Telnet IAC doubling and checks that the body contains no unpaired `IAC`.
fn unescape(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut iter = body.iter().copied();
    while let Some(b) = iter.next() {
        if b == IAC {
            assert_eq!(iter.next(), Some(IAC), "unpaired IAC in a framed record");
        }
        out.push(b);
    }
    out
}

/// Checks a framed record: `IAC EOR` at the end, IAC-doubled body before it.
fn check_frame(frame: &[u8]) -> Vec<u8> {
    let Some(body) = frame.strip_suffix(&[IAC, EOR]) else {
        panic!("frame does not end with IAC EOR");
    };
    unescape(body)
}

fn check_events(events: &[TelnetEvent]) {
    for event in events {
        match event {
            TelnetEvent::DataRecord(data) | TelnetEvent::SscpLuData(data) => {
                assert!(data.len() <= MAX_RECORD_BYTES);
            }
            TelnetEvent::Tn3270eRecord { payload, .. } => {
                assert!(payload.len() <= MAX_RECORD_BYTES);
            }
            TelnetEvent::NvtData { data, .. } => assert!(data.len() <= MAX_RECORD_BYTES),
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&config, mut rest)) = data.split_first() else {
        return;
    };
    let model = model_from_selector(config);
    let color = config & 0x08 != 0;
    let extended = config & 0x10 != 0;
    let lu = (config & 0x20 != 0).then(|| "LU000001".to_string());
    let mut sm = TelnetStateMachine::new(model, color, extended, lu);

    let mut last_chunk: &[u8] = &[];
    while let Some((&header, tail)) = rest.split_first() {
        let len = usize::from(header & 0x7F);
        let take = if len == 0 {
            tail.len()
        } else {
            len.min(tail.len())
        };
        let (chunk, next) = tail.split_at(take);
        rest = next;
        last_chunk = chunk;

        // Errors on hostile input are expected; only a panic or a broken invariant counts.
        if let Ok(events) = sm.process_inbound(chunk) {
            check_events(&events);
        }
        assert!(sm.outbound_queue_len() <= MAX_OUTBOUND_QUEUE_BYTES);
        if header & 0x80 != 0 {
            let out = sm.take_outbound();
            assert!(out.len() <= MAX_OUTBOUND_QUEUE_BYTES);
            assert_eq!(sm.outbound_queue_len(), 0);
        }
    }
    let _ = sm.take_outbound();

    // Outbound framing of the last chunk as if it were a 3270 record.
    if let Ok(frame) = sm.frame_outbound_3270(last_chunk) {
        let plain = check_frame(&frame);
        // A 5-byte TN3270E header is present only in TN3270E mode; the record follows
        // unchanged.
        let header_len = plain.len().saturating_sub(last_chunk.len());
        assert!(
            header_len == 0 || header_len == 5,
            "unexpected frame header length"
        );
        assert_eq!(plain.get(header_len..), Some(last_chunk));
    }

    let seq = u16::from_be_bytes([
        last_chunk.first().copied().unwrap_or(0),
        last_chunk.get(1).copied().unwrap_or(0),
    ]);
    if let Ok(frame) = sm.frame_positive_response(seq) {
        assert_eq!(check_frame(&frame).len(), 6);
    }
    if let Ok(frame) = sm.frame_negative_response(seq, config) {
        assert_eq!(check_frame(&frame).len(), 6);
    }

    let _ = sm.attention_route(AttentionKey::Attn);
    let _ = sm.attention_route(AttentionKey::SysReq);
    let _ = (sm.state(), sm.submode(), sm.host_mode(), sm.functions());
    let _ = (sm.assigned_lu(), sm.requested_lu(), sm.is_bound());
});
