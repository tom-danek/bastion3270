//! Benchmarks of the per-frame work of the gateway for one screen update:
//!
//! * `PresentationSpace::to_safe_view` — the masking projection (hidden fields blanked);
//! * `protocol::wire_screen` — row texts and run-length encoded style runs;
//! * `serde_json::to_string` of a `ServerMessage::Frame` — the WebSocket text frame;
//! * all three together, as the gateway does for each changed screen.
//!
//! Run with `cargo bench -p bastion3270-server`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::hint::black_box;

use bastion3270_core::address::BufferAddress;
use bastion3270_core::ebcdic::{CodePage, CP037};
use bastion3270_core::{
    DataStreamParser, HostMode, KeyboardState, PresentationSpace, TerminalModel,
};
use bastion3270_net::SessionState;
use bastion3270_server::gateway::Snapshot;
use bastion3270_server::protocol::{wire_screen, wire_status, ServerMessage};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const SBA: u8 = 0x11;
const SF: u8 = 0x1D;
const SFE: u8 = 0x29;
const IC: u8 = 0x13;
/// Protected, intensified.
const FA_PROT_HIGH: u8 = 0xE8;
/// Protected, normal intensity.
const FA_PROT: u8 = 0x60;
/// Unprotected, normal intensity.
const FA_UNPROT: u8 = 0x40;
/// Unprotected, non-display (a password field).
const FA_HIDDEN: u8 = 0x4C;

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
            erase: 0xF5,
        },
        Geometry {
            name: "62x160",
            model: TerminalModel::new_dynamic(62, 160).unwrap(),
            rows: 62,
            cols: 160,
            erase: 0x7E,
        },
    ]
}

impl Geometry {
    fn sba(&self, out: &mut Vec<u8>, row: usize, col: usize) {
        let cap = self.rows * self.cols;
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

/// `SFE` with a 3270 attribute, highlighting and foreground colour.
fn sfe(out: &mut Vec<u8>, fa: u8, highlight: u8, color: u8) {
    out.extend([SFE, 3, 0xC0, fa, 0x41, highlight, 0x42, color]);
}

/// A formatted ISPF-like screen: a title, a hidden password field, and on every row a
/// coloured label, a description and an underscored input field per 80 columns.
fn formatted(g: &Geometry) -> PresentationSpace {
    let mut s = vec![g.erase, 0xC3];
    g.sba(&mut s, 0, 0);
    sfe(&mut s, FA_PROT_HIGH, 0x00, 0xF7);
    text(&mut s, " Menu  Utilities  Compilers  Options  Status  Help");
    g.sba(&mut s, 2, 0);
    sfe(&mut s, FA_PROT, 0x00, 0xF4);
    text(&mut s, "Password ===>");
    s.extend([SF, FA_HIDDEN]);
    text(&mut s, "SECRET42");
    g.sba(&mut s, 2, 30);
    s.extend([SF, FA_PROT]);
    for row in 4..g.rows - 1 {
        for pane in 0..g.cols / 80 {
            let col = pane * 80;
            g.sba(&mut s, row, col);
            sfe(&mut s, FA_PROT_HIGH, 0x00, 0xF2);
            text(&mut s, &format!("{:>3}", row - 4));
            sfe(&mut s, FA_PROT, 0x00, 0xF5);
            text(&mut s, "Settings    Terminal and user parameters");
            sfe(&mut s, FA_UNPROT, 0xF4, 0xF4);
            text(&mut s, "USER.DATA");
            g.sba(&mut s, row, col + 79);
            s.extend([SF, FA_PROT]);
        }
    }
    g.sba(&mut s, g.rows - 1, 0);
    sfe(&mut s, FA_PROT, 0xF2, 0xF1);
    text(&mut s, " F1=Help  F3=Exit  F7=Backward  F8=Forward");
    g.sba(&mut s, 2, 14);
    s.push(IC);

    let mut ps = PresentationSpace::new(g.model);
    assert_eq!(DataStreamParser::process(&s, &mut ps).rejected, None);
    ps
}

fn snapshot(ps: &PresentationSpace) -> Snapshot {
    Snapshot {
        seq: 7,
        view: ps.to_safe_view(&CP037),
        state: SessionState::Connected3270,
        keyboard: KeyboardState::Unlocked,
        is_tls: true,
        is_tn3270e: true,
        lu: Some("LU000001".to_owned()),
        alarm_seq: 0,
        last_error: None,
        host_mode: HostMode::Data3270,
        insert_mode: false,
        banner: None,
    }
}

fn frame(snap: &Snapshot) -> ServerMessage {
    ServerMessage::Frame {
        seq: snap.seq,
        screen: Some(wire_screen(&snap.view, true)),
        status: wire_status(snap, &bastion3270_net::ConnectionProfile::default()),
        alarm: false,
    }
}

fn bench_frame(c: &mut Criterion) {
    for g in geometries() {
        let ps = formatted(&g);
        let snap = snapshot(&ps);
        assert!(
            !serde_json::to_string(&frame(&snap))
                .unwrap()
                .contains("SECRET42"),
            "the hidden field must not reach the frame"
        );

        let mut group = c.benchmark_group(format!("frame/{}", g.name));
        group.bench_with_input(BenchmarkId::from_parameter("to_safe_view"), &ps, |b, ps| {
            b.iter(|| black_box(black_box(ps).to_safe_view(&CP037)));
        });
        group.bench_with_input(
            BenchmarkId::from_parameter("wire_screen"),
            &snap.view,
            |b, view| b.iter(|| black_box(wire_screen(black_box(view), true))),
        );
        let msg = frame(&snap);
        group.bench_with_input(BenchmarkId::from_parameter("to_json"), &msg, |b, msg| {
            b.iter(|| black_box(serde_json::to_string(black_box(msg)).unwrap()));
        });
        group.bench_with_input(BenchmarkId::from_parameter("end_to_end"), &ps, |b, ps| {
            b.iter(|| {
                let snap = snapshot(black_box(ps));
                black_box(serde_json::to_string(&frame(&snap)).unwrap())
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench_frame);
criterion_main!(benches);
