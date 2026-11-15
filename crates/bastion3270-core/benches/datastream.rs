//! Benchmarks of the inbound and outbound hot paths of the protocol engine.
//!
//! * `DataStreamParser::process` of a full-screen ISPF-like `Erase/Write` (24x80 and 62x160)
//!   and of a partial `Write` on an already formatted screen;
//! * `build_read_modified` (the inbound record of an AID key) on a screen with modified fields;
//! * `TelnetStateMachine::process_inbound` of a TN3270E 3270-DATA record split into TCP-sized
//!   chunks, including `IAC IAC` escapes.
//!
//! The streams are built here from the public API, so the benchmarks need no captured host
//! data. Run with `cargo bench -p bastion3270-core`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::hint::black_box;

use bastion3270_core::address::BufferAddress;
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::telnet::{
    TelnetEvent, TelnetStateMachine, DO, EOR, IAC, SB, SE, TELOPT_TN3270E, TN3270E_FUNC_RESPONSES,
    TN3270E_OP_DEVICE_TYPE, TN3270E_OP_FUNCTIONS, TN3270E_OP_IS, TN3270E_OP_REQUEST,
    TN3270E_OP_SEND,
};
use bastion3270_core::{build_read_modified, DataStreamParser, PresentationSpace, TerminalModel};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const CMD_W: u8 = 0xF1;
const CMD_EW: u8 = 0xF5;
const CMD_EWA: u8 = 0x7E;
/// WCC: reset, restore keyboard, reset MDT.
const WCC_FULL: u8 = 0xC3;
/// WCC: restore keyboard only (keeps the MDT bits).
const WCC_PARTIAL: u8 = 0xC2;
const SBA: u8 = 0x11;
const SF: u8 = 0x1D;
const SFE: u8 = 0x29;
const IC: u8 = 0x13;
const GE: u8 = 0x08;
const XA_3270: u8 = 0xC0;
const XA_HIGHLIGHTING: u8 = 0x41;
const XA_FOREGROUND: u8 = 0x42;
/// Protected, intensified field attribute.
const FA_PROT_HIGH: u8 = 0xE8;
/// Protected, normal intensity.
const FA_PROT: u8 = 0x60;
/// Unprotected, normal intensity.
const FA_UNPROT: u8 = 0x40;
/// Unprotected numeric with the modified data tag set.
const FA_UNPROT_NUM_MDT: u8 = 0x51;
/// Unprotected with the modified data tag set.
const FA_UNPROT_MDT: u8 = 0x41;
/// AID of the Enter key.
const AID_ENTER: u8 = 0x7D;
/// Maximum segment size of a typical Ethernet TCP connection.
const TCP_MSS: usize = 1460;

/// A screen geometry and the write command that formats it.
#[derive(Clone, Copy)]
struct Geometry {
    name: &'static str,
    model: TerminalModel,
    rows: usize,
    cols: usize,
    erase: u8,
}

fn geometries() -> [Geometry; 2] {
    [
        Geometry {
            name: "24x80",
            model: TerminalModel::Model2,
            rows: 24,
            cols: 80,
            erase: CMD_EW,
        },
        Geometry {
            name: "62x160",
            model: TerminalModel::new_dynamic(62, 160).unwrap(),
            rows: 62,
            cols: 160,
            erase: CMD_EWA,
        },
    ]
}

impl Geometry {
    fn capacity(self) -> usize {
        self.rows * self.cols
    }

    /// `SBA` to `(row, col)`, 12- or 14-bit depending on the screen size.
    fn sba(self, out: &mut Vec<u8>, row: usize, col: usize) {
        let cap = self.capacity();
        let bytes = BufferAddress::new(row * self.cols + col, cap)
            .unwrap()
            .encode_for_capacity(cap)
            .unwrap();
        out.extend([SBA, bytes[0], bytes[1]]);
    }
}

fn text(out: &mut Vec<u8>, s: &str) {
    out.extend(s.chars().map(|c| CP037.char_to_ebcdic(c).unwrap()));
}

/// `SFE` with a 3270 attribute, a highlighting and a foreground colour.
fn sfe(out: &mut Vec<u8>, fa: u8, highlight: u8, color: u8) {
    out.extend([
        SFE,
        3,
        XA_3270,
        fa,
        XA_HIGHLIGHTING,
        highlight,
        XA_FOREGROUND,
        color,
    ]);
}

/// An ISPF primary option menu style full-screen write: an action bar, a GE box-drawing
/// rule, a title, a command line, two columns of option rows with an input field each, a
/// message line and the PF key line. `mdt` sets the modified data tag on the input fields
/// (for the Read Modified benchmark).
fn ispf_screen(g: Geometry, mdt: bool) -> Vec<u8> {
    let (input, numeric) = if mdt {
        (FA_UNPROT_MDT, FA_UNPROT_NUM_MDT)
    } else {
        (FA_UNPROT, FA_UNPROT | 0x10)
    };
    let mut s = vec![g.erase, WCC_FULL];

    // Action bar (white, intensified) and a GE rule below it.
    g.sba(&mut s, 0, 0);
    sfe(&mut s, FA_PROT_HIGH, 0x00, 0xF7);
    text(&mut s, " Menu  Utilities  Compilers  Options  Status  Help");
    g.sba(&mut s, 1, 0);
    s.extend([SF, FA_PROT]);
    s.extend([GE, 0xC5]);
    for _ in 2..g.cols - 1 {
        s.extend([GE, 0xA2]);
    }
    s.extend([GE, 0xD5]);

    // Title and command line.
    g.sba(&mut s, 2, g.cols / 2 - 16);
    sfe(&mut s, FA_PROT_HIGH, 0x00, 0xF5);
    text(&mut s, "ISPF Primary Option Menu");
    g.sba(&mut s, 3, 0);
    sfe(&mut s, FA_PROT, 0x00, 0xF4);
    text(&mut s, "Option ===>");
    sfe(&mut s, input, 0xF4, 0xF4);
    let cmd_col = 13;
    g.sba(&mut s, 3, g.cols - 1);
    s.extend([SF, FA_PROT]);

    // Option rows: two columns per row on a wide screen, one on a narrow one.
    let panes = g.cols / 80;
    for row in 5..g.rows - 3 {
        for pane in 0..panes {
            let col = pane * 80;
            g.sba(&mut s, row, col);
            sfe(&mut s, FA_PROT_HIGH, 0x00, 0xF2);
            text(&mut s, &format!("{:>3}", row - 5));
            sfe(&mut s, FA_PROT, 0x00, 0xF5);
            text(&mut s, "Settings    Terminal and user parameters");
            sfe(&mut s, numeric, 0xF4, 0xF4);
            text(&mut s, "0042");
            g.sba(&mut s, row, col + 60);
            sfe(&mut s, input, 0xF4, 0xF6);
            text(&mut s, "USER.DATA");
            g.sba(&mut s, row, col + 79);
            s.extend([SF, FA_PROT]);
        }
    }

    // Message line (reverse video) and the PF key line.
    g.sba(&mut s, g.rows - 2, 0);
    sfe(&mut s, FA_PROT_HIGH, 0xF2, 0xF2);
    text(&mut s, "Enter X to terminate using log/list defaults");
    g.sba(&mut s, g.rows - 1, 0);
    sfe(&mut s, FA_PROT, 0x00, 0xF1);
    text(
        &mut s,
        " F1=Help  F2=Split  F3=Exit  F7=Backward  F8=Forward  F9=Swap  F10=Actions",
    );

    g.sba(&mut s, 3, cmd_col);
    s.push(IC);
    s
}

/// A partial `Write`: the message line, the clock in the action bar and three input fields
/// change, the cursor moves to the command line.
fn partial_write(g: Geometry) -> Vec<u8> {
    let mut s = vec![CMD_W, WCC_PARTIAL];
    g.sba(&mut s, 0, g.cols - 9);
    text(&mut s, "12:34:56");
    for row in [6, 9, 12] {
        g.sba(&mut s, row, 61);
        text(&mut s, "SYS1.PROCLIB");
    }
    g.sba(&mut s, g.rows - 2, 1);
    text(&mut s, "Data set not cataloged                      ");
    g.sba(&mut s, 3, 13);
    s.push(IC);
    s
}

fn formatted(g: Geometry, mdt: bool) -> PresentationSpace {
    let mut ps = PresentationSpace::new(g.model);
    let result = DataStreamParser::process(&ispf_screen(g, mdt), &mut ps);
    assert_eq!(result.rejected, None);
    ps
}

fn bench_full_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_erase_write");
    for g in geometries() {
        let stream = ispf_screen(g, false);
        let mut ps = PresentationSpace::new(g.model);
        assert_eq!(DataStreamParser::process(&stream, &mut ps).rejected, None);
        group.throughput(Throughput::Bytes(stream.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(g.name), &stream, |b, stream| {
            b.iter(|| black_box(DataStreamParser::process(black_box(stream), &mut ps)));
        });
    }
    group.finish();
}

fn bench_partial_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_partial_write");
    for g in geometries() {
        let stream = partial_write(g);
        let mut ps = formatted(g, false);
        assert_eq!(DataStreamParser::process(&stream, &mut ps).rejected, None);
        group.throughput(Throughput::Bytes(stream.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(g.name), &stream, |b, stream| {
            b.iter(|| black_box(DataStreamParser::process(black_box(stream), &mut ps)));
        });
    }
    group.finish();
}

fn bench_read_modified(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_read_modified");
    for g in geometries() {
        let ps = formatted(g, true);
        let reply = build_read_modified(&ps, AID_ENTER, false);
        assert!(reply.len() > 3, "the screen has modified fields");
        group.throughput(Throughput::Bytes(reply.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(g.name), &ps, |b, ps| {
            b.iter(|| black_box(build_read_modified(black_box(ps), AID_ENTER, false)));
        });
    }
    group.finish();
}

fn subneg(body: &[u8]) -> Vec<u8> {
    let mut v = vec![IAC, SB];
    v.extend_from_slice(body);
    v.extend_from_slice(&[IAC, SE]);
    v
}

/// A state machine in TN3270E 3270 mode (functions: RESPONSES), as after a host's
/// `DO TN3270E`, `SEND DEVICE-TYPE`, `DEVICE-TYPE IS` and `FUNCTIONS REQUEST`.
fn tn3270e_machine(model: TerminalModel) -> TelnetStateMachine {
    let mut sm = TelnetStateMachine::new(model, true, true, None);
    sm.process_inbound(&[IAC, DO, TELOPT_TN3270E]).unwrap();
    sm.process_inbound(&subneg(&[
        TELOPT_TN3270E,
        TN3270E_OP_SEND,
        TN3270E_OP_DEVICE_TYPE,
    ]))
    .unwrap();
    let mut is = vec![TELOPT_TN3270E, TN3270E_OP_DEVICE_TYPE, TN3270E_OP_IS];
    is.extend_from_slice(b"IBM-DYNAMIC");
    sm.process_inbound(&subneg(&is)).unwrap();
    let events = sm
        .process_inbound(&subneg(&[
            TELOPT_TN3270E,
            TN3270E_OP_FUNCTIONS,
            TN3270E_OP_REQUEST,
            TN3270E_FUNC_RESPONSES,
        ]))
        .unwrap();
    assert!(matches!(
        events.as_slice(),
        [TelnetEvent::NegotiationComplete { tn3270e: true, .. }]
    ));
    sm.take_outbound();
    sm
}

/// The wire form of a TN3270E 3270-DATA record: header, payload with `0xFF` doubled,
/// `IAC EOR`.
fn tn3270e_wire(payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x00, 0x00, 0x00, 0x00, 0x01];
    for &b in payload {
        wire.push(b);
        if b == IAC {
            wire.push(IAC);
        }
    }
    wire.extend([IAC, EOR]);
    wire
}

fn bench_telnet(c: &mut Criterion) {
    let mut group = c.benchmark_group("telnet_tn3270e_record");
    for g in geometries() {
        let mut payload = ispf_screen(g, false);
        // `0xFF` (EO) bytes inside a field: each one is sent as `IAC IAC`.
        g.sba(&mut payload, g.rows - 3, 0);
        payload.extend([SF, FA_PROT]);
        payload.extend(std::iter::repeat_n(0xFF, 64));
        let wire = tn3270e_wire(&payload);
        let chunks: Vec<&[u8]> = wire.chunks(TCP_MSS).collect();
        let mut sm = tn3270e_machine(g.model);
        let check: Vec<TelnetEvent> = chunks
            .iter()
            .flat_map(|chunk| sm.process_inbound(chunk).unwrap())
            .collect();
        assert!(matches!(
            check.as_slice(),
            [TelnetEvent::Tn3270eRecord { payload: p, .. }] if *p == payload
        ));
        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(g.name), &chunks, |b, chunks| {
            b.iter(|| {
                for chunk in chunks {
                    black_box(sm.process_inbound(black_box(chunk)).unwrap());
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_full_write,
    bench_partial_write,
    bench_read_modified,
    bench_telnet
);
criterion_main!(benches);
