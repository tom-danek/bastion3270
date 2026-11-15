//! Property-based tests (`proptest`) for the untrusted-input surfaces of the core engine.
//!
//! Example-based tests pin down known host sequences; these properties check invariants that
//! must hold for *every* input a hostile or broken host (or a confused operator) can produce:
//!
//! 1. **Telnet fragmentation invariance** — TCP may split the byte stream anywhere, so the
//!    Telnet / TN3270E state machine must react identically whether a stream arrives in one
//!    read or byte by byte (RFC 854: Telnet is a byte stream, not a message protocol).
//! 2. **Data stream totality** — [`DataStreamParser::process`] and the inbound reply builders
//!    never panic and keep the cursor and buffer address on the screen.
//! 3. **Zero-Trust masking** — no character of a non-display field ever reaches a
//!    [`SafeScreenView`].
//! 4. **Keyboard robustness** — any interleaving of operator keys, pastes and host events
//!    keeps the cursor on the screen and the typeahead queue bounded.
//! 5. **Parser totality** — the TN3270E header, BIND image and Read Partition parsers never
//!    panic, and buffer addresses survive an encode / decode round trip.
//!
//! Input sizes are bounded so the default 256 cases per property run in a few seconds; set
//! `PROPTEST_CASES` for a longer soak.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::needless_pass_by_value
)]

use bastion3270_core::address::BufferAddress;
use bastion3270_core::datastream::response::{build_read_buffer_with_aid, build_sscp_read};
use bastion3270_core::datastream::sscp::write_sscp_lu;
use bastion3270_core::ebcdic::CP037;
use bastion3270_core::keyboard::MAX_TYPEAHEAD;
use bastion3270_core::telnet::{
    DO, DONT, EOR, IAC, MAX_OUTBOUND_QUEUE_BYTES, SB, SE, TELOPT_BINARY, TELOPT_EOR,
    TELOPT_TN3270E, TELOPT_TTYPE, TELQUAL_SEND, TN3270E_OP_CONNECT, TN3270E_OP_DEVICE_TYPE,
    TN3270E_OP_FUNCTIONS, TN3270E_OP_IS, TN3270E_OP_REASON, TN3270E_OP_REJECT, TN3270E_OP_REQUEST,
    TN3270E_OP_SEND, WILL, WONT,
};
use bastion3270_core::{
    build_read_modified, parse_read_partition, ActionKey, AidKey, BindImageInfo, DataStreamParser,
    HostMode, KeyInput, KeyboardOptions, PresentationSpace, SafeScreenView, TelnetError,
    TelnetEvent, TelnetStateMachine, TerminalModel, Tn3270eHeader, VirtualKeyboard,
};
use proptest::prelude::*;

// ============================================================================
// Shared strategies
// ============================================================================

/// Every terminal model the engine supports: the fixed 3278 models and an `IBM-DYNAMIC`
/// 62x160 screen (more than 4,096 cells, so 14-bit addressing is exercised).
fn model_strategy() -> impl Strategy<Value = TerminalModel> {
    prop_oneof![
        Just(TerminalModel::Model2),
        Just(TerminalModel::Model3),
        Just(TerminalModel::Model4),
        Just(TerminalModel::Model5),
        Just(TerminalModel::new_dynamic(62, 160).unwrap()),
    ]
}

// ============================================================================
// 1. Telnet fragmentation invariance
// ============================================================================

/// One syntactic unit of a host Telnet stream. The units are concatenated, so a random mix
/// reaches option negotiation, TERMINAL-TYPE, the TN3270E device-type / functions
/// subnegotiation (RFC 2355 §7) and TN3270E records (RFC 2355 §8) far more often than
/// uniformly random bytes would.
fn telnet_token() -> impl Strategy<Value = Vec<u8>> {
    let option = prop_oneof![
        Just(TELOPT_BINARY),
        Just(TELOPT_EOR),
        Just(TELOPT_TTYPE),
        Just(TELOPT_TN3270E),
        Just(1_u8), // ECHO
        Just(3_u8), // SGA
        any::<u8>(),
    ];
    let verb = prop_oneof![Just(DO), Just(DONT), Just(WILL), Just(WONT)];
    let function = prop_oneof![0_u8..=4, any::<u8>()];
    let lu = proptest::collection::vec(prop_oneof![b'A'..=b'Z', b'0'..=b'9', any::<u8>()], 0..9);

    prop_oneof![
        // Plain data byte (also any stray IAC command byte).
        3 => any::<u8>().prop_map(|b| vec![b]),
        // A short run of data bytes without IAC.
        2 => proptest::collection::vec(0_u8..0xFF, 1..16),
        // Escaped data IAC.
        1 => Just(vec![IAC, IAC]),
        // Option negotiation.
        6 => (verb, option).prop_map(|(v, o)| vec![IAC, v, o]),
        // End of record.
        4 => Just(vec![IAC, EOR]),
        // Other Telnet commands (NOP, DM, BREAK, IP, AO, AYT, EC, EL, GA, SE out of place).
        1 => (0xF0_u8..=0xF9).prop_map(|c| vec![IAC, c]),
        // TERMINAL-TYPE SEND.
        2 => Just(vec![IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE]),
        // TN3270E SEND DEVICE-TYPE.
        2 => Just(vec![IAC, SB, TELOPT_TN3270E, TN3270E_OP_SEND, TN3270E_OP_DEVICE_TYPE, IAC, SE]),
        // TN3270E DEVICE-TYPE IS <type> [CONNECT <lu>].
        2 => (any::<bool>(), lu).prop_map(|(connect, lu)| {
            let mut v = vec![IAC, SB, TELOPT_TN3270E, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_IS];
            v.extend_from_slice(b"IBM-3278-2-E");
            if connect {
                v.push(TN3270E_OP_CONNECT);
                v.extend(lu.into_iter().filter(|&b| b != IAC));
            }
            v.extend_from_slice(&[IAC, SE]);
            v
        }),
        // TN3270E DEVICE-TYPE REJECT REASON <code>.
        1 => any::<u8>().prop_map(|r| vec![
            IAC, SB, TELOPT_TN3270E, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_REJECT,
            TN3270E_OP_REASON, r, IAC, SE,
        ]),
        // TN3270E FUNCTIONS REQUEST / IS <functions>.
        3 => (
            prop_oneof![Just(TN3270E_OP_REQUEST), Just(TN3270E_OP_IS)],
            proptest::collection::vec(function, 0..5),
        )
            .prop_map(|(op, funcs)| {
                let mut v = vec![IAC, SB, TELOPT_TN3270E, TN3270E_OP_FUNCTIONS, op];
                for f in funcs {
                    v.push(f);
                    if f == IAC {
                        v.push(IAC);
                    }
                }
                v.extend_from_slice(&[IAC, SE]);
                v
            }),
        // Arbitrary subnegotiation body (may contain escaped and unescaped IACs).
        1 => proptest::collection::vec(any::<u8>(), 0..24).prop_map(|body| {
            let mut v = vec![IAC, SB];
            v.extend(body);
            v.extend_from_slice(&[IAC, SE]);
            v
        }),
        // TN3270E record: 5-byte header (data type 0..=9 or random), payload, IAC EOR.
        4 => (
            prop_oneof![0_u8..=9, any::<u8>()],
            any::<u8>(),
            prop_oneof![0_u8..=2, any::<u8>()],
            any::<u16>(),
            proptest::collection::vec(any::<u8>(), 0..32),
        )
            .prop_map(|(dt, rq, rs, seq, payload)| {
                let [s0, s1] = seq.to_be_bytes();
                let mut v = Vec::new();
                for b in [dt, rq, rs, s0, s1].into_iter().chain(payload) {
                    v.push(b);
                    if b == IAC {
                        v.push(IAC);
                    }
                }
                v.extend_from_slice(&[IAC, EOR]);
                v
            }),
        // BIND-IMAGE record with an RU that starts with the BIND opcode.
        1 => proptest::collection::vec(any::<u8>(), 0..40).prop_map(|ru| {
            let mut v = vec![0x03, 0x00, 0x00, 0x00, 0x00, 0x31];
            for b in ru {
                v.push(b);
                if b == IAC {
                    v.push(IAC);
                }
            }
            v.extend_from_slice(&[IAC, EOR]);
            v
        }),
    ]
}

/// A complete host handshake, so that most streams reach a 3270 mode before the random
/// units start: plain TN3270 (RFC 1576: TERMINAL-TYPE, EOR and BINARY both ways) or TN3270E
/// (RFC 2355 §7: DEVICE-TYPE then FUNCTIONS, with a random function list so acceptance,
/// counter-proposal and back-off all occur), optionally followed by a BIND-IMAGE record.
fn telnet_handshake() -> impl Strategy<Value = Vec<u8>> {
    let plain = Just(vec![
        IAC,
        DO,
        TELOPT_TTYPE,
        IAC,
        SB,
        TELOPT_TTYPE,
        TELQUAL_SEND,
        IAC,
        SE,
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
    ]);
    let tn3270e = (
        prop_oneof![Just(TN3270E_OP_IS), Just(TN3270E_OP_REQUEST)],
        proptest::collection::vec(prop_oneof![Just(0_u8), Just(2), Just(4), 0_u8..=4], 0..4),
        any::<bool>(),
    )
        .prop_map(|(op, funcs, bind)| {
            let mut v = vec![
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
            ];
            v.extend_from_slice(b"IBM-3278-2-E");
            v.push(TN3270E_OP_CONNECT);
            v.extend_from_slice(b"LU00001");
            v.extend_from_slice(&[IAC, SE, IAC, SB, TELOPT_TN3270E, TN3270E_OP_FUNCTIONS, op]);
            v.extend(funcs);
            v.extend_from_slice(&[IAC, SE]);
            if bind {
                // BIND-IMAGE header and a minimal BIND RU (opcode 0x31, screen size 0x00).
                v.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x31]);
                v.extend(std::iter::repeat_n(0x00, 26));
                v.extend_from_slice(&[IAC, EOR]);
            }
            v
        });
    prop_oneof![plain, tn3270e]
}

/// A host byte stream: uniformly random bytes, Telnet units with or without a leading
/// handshake, or units around a subnegotiation longer than `MAX_SUBNEG_BYTES` (the only
/// way to reach the error path of `process_inbound` with bounded input).
fn telnet_stream() -> impl Strategy<Value = Vec<u8>> {
    let tokens = || proptest::collection::vec(telnet_token(), 0..40).prop_map(|t| t.concat());
    prop_oneof![
        1 => proptest::collection::vec(any::<u8>(), 0..512),
        2 => tokens(),
        5 => (telnet_handshake(), tokens()).prop_map(|(h, t)| [h, t].concat()),
        1 => (tokens(), 1_020_usize..1_100, tokens()).prop_map(|(a, n, b)| {
            let mut v = a;
            v.extend_from_slice(&[IAC, SB, TELOPT_TTYPE]);
            v.extend(std::iter::repeat_n(b'x', n));
            v.extend_from_slice(&[IAC, SE]);
            v.extend(b);
            v
        }),
    ]
}

/// Merges adjacent `NvtData { ack: None }` events.
///
/// [`TelnetStateMachine::process_inbound`] collects the NVT text of one call and reports it
/// as one `NvtData { ack: None }` event before the next Telnet command and at the end of the
/// call (`flush_nvt`). The boundaries of these events therefore follow the read boundaries:
/// `"ab"` in one read is one event, in two reads it is `"a"`, `"b"`. Their concatenation is
/// the same, and that is the only property a consumer of NVT text may rely on. NVT records
/// of a TN3270E session (`ack: Some(seq)`) carry their own boundaries and are never merged.
/// No other event depends on the read boundaries.
fn normalise(events: Vec<TelnetEvent>) -> Vec<TelnetEvent> {
    let mut out: Vec<TelnetEvent> = Vec::with_capacity(events.len());
    for event in events {
        if let TelnetEvent::NvtData { data, ack: None } = &event {
            if let Some(TelnetEvent::NvtData {
                data: prev,
                ack: None,
            }) = out.last_mut()
            {
                prev.extend_from_slice(data);
                continue;
            }
        }
        out.push(event);
    }
    out
}

/// Outcome of feeding a stream to a fresh state machine: the (normalised) events, everything
/// it queued for the host, the error that ended processing (if any) and the final state.
#[derive(Debug, PartialEq)]
struct TelnetRun {
    events: Vec<TelnetEvent>,
    outbound: Vec<u8>,
    error: Option<TelnetError>,
    state: String,
}

fn telnet_config() -> impl Strategy<Value = (TerminalModel, bool, bool, Option<String>)> {
    (
        model_strategy(),
        any::<bool>(),
        any::<bool>(),
        prop_oneof![Just(None), Just(Some("LU00001".to_string()))],
    )
}

/// Feeds `chunks` in order to a fresh state machine, draining the outbound queue after
/// every call (as the network layer does). Stops at the first error, as the session does.
fn run_telnet(
    config: &(TerminalModel, bool, bool, Option<String>),
    chunks: &[&[u8]],
) -> Result<TelnetRun, TestCaseError> {
    let (model, color, extended, lu) = config.clone();
    let mut sm = TelnetStateMachine::new(model, color, extended, lu);
    let mut events = Vec::new();
    let mut outbound = Vec::new();
    let mut error = None;
    for chunk in chunks {
        let result = sm.process_inbound(chunk);
        prop_assert!(sm.outbound_queue_len() <= MAX_OUTBOUND_QUEUE_BYTES);
        outbound.extend(sm.take_outbound());
        match result {
            Ok(evs) => events.extend(evs),
            Err(err) => {
                error = Some(err);
                break;
            }
        }
    }
    Ok(TelnetRun {
        events: normalise(events),
        outbound,
        error,
        state: format!(
            "{:?} {:?} {:?} e={} bound={} funcs={:?} lu={:?}",
            sm.state(),
            sm.submode(),
            sm.host_mode(),
            sm.is_tn3270e(),
            sm.is_bound(),
            sm.functions(),
            sm.assigned_lu(),
        ),
    })
}

/// Splits `input` at the given cut points (sorted, deduplicated; empty chunks are kept on
/// purpose — an empty read must be a no-op).
fn split_at_cuts<'a>(input: &'a [u8], cuts: &[prop::sample::Index]) -> Vec<&'a [u8]> {
    let mut points: Vec<usize> = cuts.iter().map(|c| c.index(input.len() + 1)).collect();
    points.sort_unstable();
    let mut chunks = Vec::with_capacity(points.len() + 1);
    let mut start = 0;
    for p in points {
        chunks.push(&input[start..p]);
        start = p;
    }
    chunks.push(&input[start..]);
    chunks
}

proptest! {
    /// The state machine's reaction does not depend on how TCP fragments the stream.
    ///
    /// When the whole stream fails, the chunked run must fail with the same error after
    /// queueing the same bytes for the host. Events are only compared for successful runs:
    /// a failing `process_inbound` call returns the error instead of that call's events, so
    /// on failure the event lists legitimately differ by the events of the failing call.
    #[test]
    fn telnet_fragmentation_invariance(
        config in telnet_config(),
        input in telnet_stream(),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..16),
        byte_by_byte in any::<bool>(),
    ) {
        let whole = run_telnet(&config, &[&input])?;
        let chunks: Vec<&[u8]> = if byte_by_byte {
            input.chunks(1).collect()
        } else {
            split_at_cuts(&input, &cuts)
        };
        let chunked = run_telnet(&config, &chunks)?;

        prop_assert_eq!(&whole.error, &chunked.error);
        prop_assert_eq!(&whole.outbound, &chunked.outbound);
        prop_assert_eq!(&whole.state, &chunked.state);
        if whole.error.is_none() {
            prop_assert_eq!(&whole.events, &chunked.events);
        }
    }
}

// ============================================================================
// 2. Data stream totality and invariants
// ============================================================================

/// A buffer address as a host would send it: valid 12-bit or 14-bit encodings of addresses
/// on and just beyond the largest screen, plus arbitrary byte pairs.
fn address_bytes() -> impl Strategy<Value = [u8; 2]> {
    prop_oneof![
        3 => (0_usize..10_000).prop_map(|a| {
            let addr = BufferAddress::new(a, 16_384).unwrap();
            if a < 4_096 {
                addr.encode_12bit().unwrap()
            } else {
                addr.encode_14bit().unwrap()
            }
        }),
        1 => (0_usize..16_384).prop_map(|a| BufferAddress::new(a, 16_384)
            .unwrap()
            .encode_14bit()
            .unwrap()),
        1 => any::<[u8; 2]>(),
    ]
}

/// A field attribute byte, biased toward non-display (`0x0C` intensity bits) and protected
/// variants so password fields and auto-skip appear on most screens.
fn field_attr_byte() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x4C_u8), // unprotected, non-display
        Just(0x6C_u8), // protected, non-display
        Just(0x40_u8), // unprotected, normal
        Just(0x60_u8), // protected
        Just(0xF0_u8), // protected numeric (auto-skip)
        Just(0x50_u8), // numeric
        any::<u8>(),
    ]
}

/// One extended attribute (type, value) pair as carried by `SFE`, `SA` and `MF`.
fn attr_pair() -> impl Strategy<Value = [u8; 2]> {
    (
        prop_oneof![
            Just(0xC0_u8), // 3270 field attribute
            Just(0x41_u8), // highlighting
            Just(0x42_u8), // foreground
            Just(0x43_u8), // character set
            Just(0x45_u8), // background
            Just(0x00_u8), // reset all
            any::<u8>(),
        ],
        prop_oneof![field_attr_byte(), Just(0xF1_u8), Just(0xF2_u8), any::<u8>()],
    )
        .prop_map(|(t, v)| [t, v])
}

/// One order or text run of a 3270 write (3270 Data Stream Programmer's Reference ch. 4;
/// `x3270` `ctlr_write`).
fn ds_element() -> impl Strategy<Value = Vec<u8>> {
    let pairs = || proptest::collection::vec(attr_pair(), 0..4);
    prop_oneof![
        4 => proptest::collection::vec(any::<u8>(), 1..12),
        3 => address_bytes().prop_map(|a| vec![0x11, a[0], a[1]]),
        3 => field_attr_byte().prop_map(|fa| vec![0x1D, fa]),
        2 => (pairs(), any::<bool>()).prop_map(|(p, honest)| {
            let count = if honest { p.len() as u8 } else { (p.len() as u8).wrapping_add(1) };
            let mut v = vec![0x29, count];
            v.extend(p.into_iter().flatten());
            v
        }),
        2 => attr_pair().prop_map(|p| vec![0x28, p[0], p[1]]),
        1 => (pairs(), any::<bool>()).prop_map(|(p, honest)| {
            let count = if honest { p.len() as u8 } else { (p.len() as u8).wrapping_add(1) };
            let mut v = vec![0x2C, count];
            v.extend(p.into_iter().flatten());
            v
        }),
        1 => Just(vec![0x05]),
        2 => (address_bytes(), any::<bool>(), any::<u8>()).prop_map(|(a, ge, ch)| {
            let mut v = vec![0x3C, a[0], a[1]];
            if ge {
                v.push(0x08);
            }
            v.push(ch);
            v
        }),
        1 => address_bytes().prop_map(|a| vec![0x12, a[0], a[1]]),
        2 => Just(vec![0x13]),
        1 => any::<u8>().prop_map(|ch| vec![0x08, ch]),
        // Truncated order at the end of a record.
        1 => prop_oneof![Just(0x11_u8), Just(0x1D), Just(0x29), Just(0x28), Just(0x3C),
            Just(0x12), Just(0x08), Just(0x2C)].prop_map(|o| vec![o]),
    ]
}

/// One structured field of a Write Structured Field record: a 2-byte length (correct or
/// not), an SFID and a body. Covers Read Partition, Erase/Reset, Set Reply Mode and
/// Outbound 3270DS (which nests a write).
fn structured_field() -> impl Strategy<Value = Vec<u8>> {
    let body = prop_oneof![
        // Read Partition: partition 0xFF, query / query list, optional QCODE list.
        (
            prop_oneof![Just(0xFF_u8), any::<u8>()],
            prop_oneof![
                Just(0x02_u8),
                Just(0x03),
                Just(0x6E),
                Just(0xF2),
                Just(0xF6),
                any::<u8>()
            ],
            proptest::collection::vec(any::<u8>(), 0..6)
        )
            .prop_map(|(p, t, rest)| {
                let mut v = vec![0x01, p, t];
                v.extend(rest);
                v
            }),
        // Erase/Reset.
        any::<u8>().prop_map(|f| vec![0x03, f]),
        // Set Reply Mode with attribute types.
        (
            any::<u8>(),
            prop_oneof![0_u8..=2, any::<u8>()],
            proptest::collection::vec(
                prop_oneof![
                    Just(0x41_u8),
                    Just(0x42),
                    Just(0x43),
                    Just(0x45),
                    any::<u8>()
                ],
                0..4
            )
        )
            .prop_map(|(p, m, types)| {
                let mut v = vec![0x09, p, m];
                v.extend(types);
                v
            }),
        // Outbound 3270DS: partition, write command, WCC, orders.
        (
            any::<u8>(),
            prop_oneof![
                Just(0xF1_u8),
                Just(0xF5),
                Just(0x7E),
                Just(0x6F),
                any::<u8>()
            ],
            any::<u8>(),
            proptest::collection::vec(ds_element(), 0..6)
        )
            .prop_map(|(p, cmd, wcc, elems)| {
                let mut v = vec![0x40, p, cmd, wcc];
                v.extend(elems.concat());
                v
            }),
        proptest::collection::vec(any::<u8>(), 0..12),
    ];
    (
        body,
        prop_oneof![4 => Just(None), 1 => any::<u16>().prop_map(Some)],
    )
        .prop_map(|(body, len_override)| {
            let len = len_override.unwrap_or((body.len() + 2) as u16);
            let mut v = len.to_be_bytes().to_vec();
            v.extend(body);
            v
        })
}

/// A 3270 record as a host may send it: random bytes, a write command with WCC and orders,
/// a Write Structured Field, or a bare read / EAU / no-op command.
fn ds_record() -> impl Strategy<Value = Vec<u8>> {
    let write_cmd = prop_oneof![
        Just(0xF1_u8),
        Just(0xF5),
        Just(0x7E),
        Just(0x01),
        Just(0x05),
        Just(0x0D),
    ];
    prop_oneof![
        1 => proptest::collection::vec(any::<u8>(), 0..512),
        6 => (write_cmd, any::<u8>(), proptest::collection::vec(ds_element(), 0..48))
            .prop_map(|(cmd, wcc, elems)| {
                let mut v = vec![cmd, wcc];
                v.extend(elems.concat());
                v.truncate(512);
                v
            }),
        2 => (prop_oneof![Just(0xF3_u8), Just(0x11)],
            proptest::collection::vec(structured_field(), 0..4))
            .prop_map(|(cmd, sfs)| {
                let mut v = vec![cmd];
                v.extend(sfs.concat());
                v.truncate(512);
                v
            }),
        1 => prop_oneof![Just(0x6F_u8), Just(0xF2), Just(0xF6), Just(0x6E), Just(0x03),
            Just(0x0F), Just(0x02), Just(0x06), Just(0x0E)]
            .prop_map(|c| vec![c]),
    ]
}

/// A model and a sequence of host records applied to a fresh presentation space.
fn screen_strategy() -> impl Strategy<Value = (TerminalModel, Vec<Vec<u8>>)> {
    (
        model_strategy(),
        proptest::collection::vec(ds_record(), 0..6),
    )
}

fn build_screen(model: TerminalModel, records: &[Vec<u8>]) -> PresentationSpace {
    let mut ps = PresentationSpace::new(model);
    for record in records {
        let _ = DataStreamParser::process(record, &mut ps);
    }
    ps
}

/// The invariants every operation must keep: cursor and buffer address on the screen, a
/// screen no larger than the model allows, and the formatted state matching the cells (it is
/// tracked incrementally, so every path that adds or removes an attribute must update it).
fn check_addresses(ps: &PresentationSpace) -> Result<(), TestCaseError> {
    let cap = ps.capacity();
    prop_assert!(cap > 0);
    let has_attribute = (0..cap).any(|idx| {
        ps.cell(BufferAddress::new(idx, cap).unwrap())
            .is_some_and(bastion3270_core::Cell::is_field_attribute)
    });
    prop_assert_eq!(
        ps.is_formatted(),
        has_attribute,
        "formatted state disagrees with the cells"
    );
    prop_assert!(cap <= ps.model().max_size().capacity());
    prop_assert_eq!(cap, usize::from(ps.rows()) * usize::from(ps.cols()));
    prop_assert!(
        ps.cursor_addr().as_usize() < cap,
        "cursor {} outside screen of {} cells",
        ps.cursor_addr().as_usize(),
        cap
    );
    prop_assert!(
        ps.buffer_addr().as_usize() < cap,
        "buffer address {} outside screen of {} cells",
        ps.buffer_addr().as_usize(),
        cap
    );
    Ok(())
}

proptest! {
    /// Any record sequence is processed without panic, keeps the addresses on the screen,
    /// and every inbound reply builder and the SSCP-LU writer accept the resulting screen.
    #[test]
    fn datastream_totality((model, records) in screen_strategy(), aid in any::<u8>(),
                           sscp in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut ps = PresentationSpace::new(model);
        for record in &records {
            let _ = DataStreamParser::process(record, &mut ps);
            check_addresses(&ps)?;
        }

        let _ = build_read_modified(&ps, aid, false);
        let _ = build_read_modified(&ps, aid, true);
        let _ = build_read_buffer_with_aid(&ps, aid);
        let _ = build_sscp_read(&ps);

        let mut sscp_ps = ps.clone();
        prop_assert_eq!(write_sscp_lu(&mut sscp_ps, &sscp), Ok(()));
        check_addresses(&sscp_ps)?;
        let _ = build_sscp_read(&sscp_ps);

        let view = SafeScreenView::from_presentation_space(&ps, &CP037);
        prop_assert_eq!(view.capacity(), ps.capacity());
        prop_assert_eq!(view.cells().len(), ps.capacity());
        prop_assert!(view.cursor_row() < view.rows() && view.cursor_col() < view.cols());
    }
}

// ============================================================================
// 3. Zero-Trust masking
// ============================================================================

/// For every cell, the nearest field attribute at or before it (with wrap-around), found by
/// scanning the cells directly — an oracle independent of the cached `is_formatted` flag that
/// [`PresentationSpace::governing_field`] relies on (`x3270` `find_field_attribute`).
/// Linear: one pass finds the last attribute on the screen, a second carries it forward.
fn scan_governing_attrs(ps: &PresentationSpace) -> Vec<Option<usize>> {
    let cap = ps.capacity();
    let is_fa: Vec<bool> = (0..cap)
        .map(|i| {
            BufferAddress::new(i, cap)
                .ok()
                .and_then(|a| ps.cell(a))
                .is_some_and(bastion3270_core::Cell::is_field_attribute)
        })
        .collect();
    let mut current = is_fa.iter().rposition(|&f| f);
    is_fa
        .iter()
        .enumerate()
        .map(|(i, &f)| {
            if f {
                current = Some(i);
            }
            current
        })
        .collect()
}

proptest! {
    /// The documented guarantee of [`SafeCell`](bastion3270_core::SafeCell) /
    /// `PresentationSpace::safe_cell_at`:
    ///
    /// 1. a field attribute position projects to `' '` with `is_field_marker` and
    ///    `protected` set;
    /// 2. every other cell whose governing field is non-display projects to `' '`.
    ///
    /// The governing field is cross-checked against a direct scan of the cells, so a stale
    /// `is_formatted` cache cannot hide a password field from the mask.
    #[test]
    fn zero_trust_masking((model, records) in screen_strategy()) {
        let ps = build_screen(model, &records);
        let view = SafeScreenView::from_presentation_space(&ps, &CP037);
        let cap = ps.capacity();
        prop_assert_eq!(view.cells().len(), cap);
        let oracle = scan_governing_attrs(&ps);

        for idx in 0..cap {
            let addr = BufferAddress::new(idx, cap).unwrap();
            let cell = ps.cell(addr).unwrap();
            let safe = view.cells()[idx];

            if cell.is_field_attribute() {
                prop_assert_eq!(safe.ch, ' ', "field attribute at {} not blank", idx);
                prop_assert!(safe.is_field_marker && safe.protected);
                continue;
            }
            prop_assert!(!safe.is_field_marker);

            // `governing_field` walks back to the attribute, so calling it for every cell is
            // quadratic on a large screen with few fields; checking it at field boundaries
            // and on a stride is enough to catch a stale `is_formatted` cache, which would
            // make it disagree everywhere.
            let boundary = idx == 0
                || oracle[idx.wrapping_sub(1)] != oracle[idx]
                || oracle.get(idx + 1).is_none_or(|next| *next != oracle[idx]);
            if boundary || idx % 61 == 0 {
                prop_assert_eq!(
                    ps.governing_field(addr).map(|(a, _, _)| a.as_usize()),
                    oracle[idx],
                    "governing field of {} disagrees with the cells (is_formatted = {})",
                    idx,
                    ps.is_formatted()
                );
                // The one-pass projection of the whole screen agrees with the per-cell one.
                prop_assert_eq!(Some(safe), ps.safe_cell_at(addr, &CP037), "cell {}", idx);
            }
            let non_display = oracle[idx]
                .and_then(|fa_idx| ps.cell(BufferAddress::new(fa_idx, cap).unwrap()))
                .and_then(bastion3270_core::Cell::field_attribute)
                .is_some_and(bastion3270_core::FieldAttribute::is_non_display);
            if non_display {
                prop_assert_eq!(
                    safe.ch, ' ',
                    "non-display cell {} leaked {:?} (raw 0x{:02X})",
                    idx, safe.ch, cell.raw_ebcdic()
                );
            }
        }
    }
}

// ============================================================================
// 4. Keyboard robustness
// ============================================================================

/// One operator action or host event driving the keyboard.
#[derive(Debug, Clone)]
enum KbOp {
    Key(KeyInput),
    /// The same key many times in a row (a held key, or typing ahead while the keyboard is
    /// locked), enough to reach the typeahead limit.
    KeyBurst(KeyInput, usize),
    Paste(String),
    HostWrite(bool),
    HostReset,
    Reset,
    EnterInhibit,
    SetHostMode(HostMode),
    Disconnected,
    Connected,
    Entered3270(bool),
    /// Replays the typeahead queue through `submit`, as the session does after an unlock
    /// (`x3270` `run_ta`).
    ReplayTypeahead,
    /// A host record processed as the session does: parse, then the host-write keyboard
    /// rules when the screen was written.
    HostRecord(Vec<u8>),
    /// SSCP-LU output from the host.
    HostSscp(Vec<u8>),
}

fn action_key() -> impl Strategy<Value = ActionKey> {
    prop_oneof![
        Just(ActionKey::Tab),
        Just(ActionKey::BackTab),
        Just(ActionKey::Home),
        Just(ActionKey::Newline),
        Just(ActionKey::Left),
        Just(ActionKey::Right),
        Just(ActionKey::Up),
        Just(ActionKey::Down),
        Just(ActionKey::EraseEof),
        Just(ActionKey::FieldEnd),
        Just(ActionKey::ToggleInsert),
        Just(ActionKey::EraseInput),
        Just(ActionKey::Backspace),
        Just(ActionKey::Delete),
        Just(ActionKey::Reset),
        (
            prop_oneof![0_u16..70, any::<u16>()],
            prop_oneof![0_u16..170, any::<u16>()]
        )
            .prop_map(|(row, col)| ActionKey::MoveCursor { row, col }),
    ]
}

fn aid_key() -> impl Strategy<Value = AidKey> {
    prop_oneof![
        Just(AidKey::Enter),
        Just(AidKey::Clear),
        (1_u8..=24).prop_map(|n| AidKey::pf(n).unwrap()),
        (1_u8..=3).prop_map(|n| AidKey::pa(n).unwrap()),
    ]
}

fn host_mode() -> impl Strategy<Value = HostMode> {
    prop_oneof![
        Just(HostMode::Negotiating),
        Just(HostMode::Unbound),
        Just(HostMode::Data3270),
        Just(HostMode::SscpLu),
        Just(HostMode::Nvt),
    ]
}

/// Characters an operator types: printable ASCII and digits mostly (so numeric and protected
/// checks are hit), plus any Unicode scalar (unmappable in CP037).
fn typed_char() -> impl Strategy<Value = char> {
    prop_oneof![
        4 => proptest::char::range(' ', '~'),
        2 => proptest::char::range('0', '9'),
        1 => any::<char>(),
    ]
}

/// Pasted text: typed characters plus the control characters paste interprets.
fn paste_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            6 => typed_char(),
            1 => prop_oneof![Just('\n'), Just('\t'), Just('\r'), Just('\u{8}'), Just('\u{c}')],
        ],
        0..200,
    )
    .prop_map(String::from_iter)
}

fn kb_op() -> impl Strategy<Value = KbOp> {
    prop_oneof![
        8 => typed_char().prop_map(|c| KbOp::Key(KeyInput::Char(c))),
        6 => action_key().prop_map(|a| KbOp::Key(KeyInput::Action(a))),
        2 => aid_key().prop_map(|a| KbOp::Key(KeyInput::Aid(a))),
        1 => Just(KbOp::Key(KeyInput::SysReq)),
        1 => (typed_char(), 0..=2 * MAX_TYPEAHEAD)
            .prop_map(|(c, n)| KbOp::KeyBurst(KeyInput::Char(c), n)),
        1 => paste_text().prop_map(KbOp::Paste),
        2 => any::<bool>().prop_map(KbOp::HostWrite),
        1 => Just(KbOp::HostReset),
        1 => Just(KbOp::Reset),
        1 => Just(KbOp::EnterInhibit),
        1 => host_mode().prop_map(KbOp::SetHostMode),
        1 => Just(KbOp::Disconnected),
        1 => Just(KbOp::Connected),
        1 => any::<bool>().prop_map(KbOp::Entered3270),
        2 => Just(KbOp::ReplayTypeahead),
        1 => ds_record().prop_map(KbOp::HostRecord),
        1 => proptest::collection::vec(any::<u8>(), 0..64).prop_map(KbOp::HostSscp),
    ]
}

fn keyboard_strategy() -> impl Strategy<Value = VirtualKeyboard> {
    prop_oneof![
        Just(VirtualKeyboard::new()),
        (any::<bool>(), any::<bool>()).prop_map(|(numeric_lock, blank_fill)| {
            VirtualKeyboard::with_options(KeyboardOptions {
                numeric_lock,
                blank_fill,
            })
        }),
    ]
}

fn check_keyboard(ps: &PresentationSpace, kb: &VirtualKeyboard) -> Result<(), TestCaseError> {
    check_addresses(ps)?;
    prop_assert!(
        kb.typeahead_len() <= MAX_TYPEAHEAD,
        "typeahead {} exceeds {}",
        kb.typeahead_len(),
        MAX_TYPEAHEAD
    );
    Ok(())
}

proptest! {
    /// Any interleaving of operator input and host events keeps the cursor on the screen and
    /// the typeahead queue within [`MAX_TYPEAHEAD`].
    #[test]
    fn keyboard_robustness(
        (model, records) in screen_strategy(),
        mut kb in keyboard_strategy(),
        ops in proptest::collection::vec(kb_op(), 0..64),
    ) {
        let mut ps = build_screen(model, &records);
        check_keyboard(&ps, &kb)?;

        for op in ops {
            match op {
                KbOp::Key(input) => {
                    let _ = kb.submit(&mut ps, input, &CP037);
                }
                KbOp::KeyBurst(input, count) => {
                    for _ in 0..count {
                        let _ = kb.submit(&mut ps, input, &CP037);
                        check_keyboard(&ps, &kb)?;
                    }
                }
                KbOp::Paste(text) => {
                    let _ = kb.paste(&mut ps, &text, &CP037);
                }
                KbOp::HostWrite(restore) => kb.host_write(restore),
                KbOp::HostReset => kb.host_reset(),
                KbOp::Reset => kb.reset(),
                KbOp::EnterInhibit => kb.enter_inhibit(),
                KbOp::SetHostMode(mode) => kb.set_host_mode(mode),
                KbOp::Disconnected => kb.disconnected(),
                KbOp::Connected => kb.connected(),
                KbOp::Entered3270(e) => kb.entered_3270(e),
                KbOp::ReplayTypeahead => {
                    // Each replayed key leaves the queue, so the loop is bounded; the guard
                    // turns a key that re-queues itself into a failure instead of a hang.
                    let mut replayed = 0_usize;
                    while let Some(input) = kb.pop_typeahead() {
                        let _ = kb.submit(&mut ps, input, &CP037);
                        replayed += 1;
                        prop_assert!(replayed <= MAX_TYPEAHEAD, "typeahead replay does not end");
                        check_keyboard(&ps, &kb)?;
                    }
                }
                KbOp::HostRecord(record) => {
                    let result = DataStreamParser::process(&record, &mut ps);
                    if result.screen_written {
                        kb.host_write(result.restore_keyboard);
                    }
                }
                KbOp::HostSscp(data) => {
                    prop_assert_eq!(write_sscp_lu(&mut ps, &data), Ok(()));
                }
            }
            check_keyboard(&ps, &kb)?;
        }
    }
}

// ============================================================================
// 5. Parser totality and address round trip
// ============================================================================

proptest! {
    /// The TN3270E header parser accepts exactly the inputs of at least 5 bytes with a known
    /// data type, and re-encodes the header it parsed byte for byte (RFC 2355 §8).
    #[test]
    fn tn3270e_header_total(bytes in proptest::collection::vec(any::<u8>(), 0..16)) {
        if let Ok(header) = Tn3270eHeader::parse(&bytes) {
            prop_assert!(bytes.len() >= 5);
            prop_assert_eq!(&header.to_bytes()[..], &bytes[..5]);
        } else {
            prop_assert!(bytes.len() < 5 || bytes[0] > 0x09);
        }
    }

    /// The BIND image parser never panics, for random RUs and for RUs that start with the
    /// BIND opcode and use the screen size byte values `x3270` `process_bind` handles.
    #[test]
    fn bind_image_total(
        model in model_strategy(),
        random in proptest::collection::vec(any::<u8>(), 0..64),
        mut bind in proptest::collection::vec(any::<u8>(), 0..64),
        ssize in prop_oneof![Just(0x00_u8), Just(0x02), Just(0x03), Just(0x7E), Just(0x7F),
            any::<u8>()],
    ) {
        let _ = BindImageInfo::parse(&random, model);
        if let Some(first) = bind.first_mut() {
            *first = 0x31;
        }
        if let Some(b) = bind.get_mut(24) {
            *b = ssize;
        }
        let _ = BindImageInfo::parse(&bind, model);
    }

    /// The Read Partition parser never panics, with or without the 2-byte length prefix.
    #[test]
    fn read_partition_total(
        random in proptest::collection::vec(any::<u8>(), 0..32),
        partition in prop_oneof![Just(0xFF_u8), any::<u8>()],
        kind in prop_oneof![Just(0x02_u8), Just(0x03), Just(0x6E), Just(0xF2), Just(0xF6),
            any::<u8>()],
        rest in proptest::collection::vec(any::<u8>(), 0..16),
        prefixed in any::<bool>(),
    ) {
        let _ = parse_read_partition(&random);
        let mut field = Vec::new();
        if prefixed {
            field.extend(((rest.len() + 5) as u16).to_be_bytes());
        }
        field.extend([0x01, partition, kind]);
        field.extend(rest);
        let _ = parse_read_partition(&field);
    }

    /// Every valid address survives the encoding a screen of its capacity uses (`x3270`
    /// `ENCODE_BADDR` / `DECODE_BADDR`), and both explicit encodings within their limits.
    #[test]
    fn buffer_address_round_trip(model in model_strategy(), seed in any::<prop::sample::Index>()) {
        let cap = model.max_size().capacity();
        let a = seed.index(cap);
        let addr = BufferAddress::new(a, cap).unwrap();
        prop_assert_eq!(addr.as_usize(), a);

        let [c1, c2] = addr.encode_for_capacity(cap).unwrap();
        prop_assert_eq!(BufferAddress::decode(c1, c2, cap), Ok(addr));

        let [c1, c2] = addr.encode_14bit().unwrap();
        prop_assert_eq!(BufferAddress::decode(c1, c2, cap), Ok(addr));
        if a < 4_096 {
            let [c1, c2] = addr.encode_12bit().unwrap();
            prop_assert_eq!(BufferAddress::decode(c1, c2, cap), Ok(addr));
        } else {
            prop_assert!(addr.encode_12bit().is_err());
        }
        prop_assert!(BufferAddress::new(cap + seed.index(64), cap).is_err());
    }
}
