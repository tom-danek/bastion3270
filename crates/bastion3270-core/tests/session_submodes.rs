//! TN3270E session submodes: BIND screen sizes and UNBIND, checked against `x3270`
//! `telnet.c` (`process_bind`, `process_eor`) and `ctlr.c` (`ctlr_erase`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use bastion3270_core::telnet::BindImageInfo;
use bastion3270_core::{
    BindSizeError, BindSizes, DataStreamParser, PresentationSpace, ScreenSize, TerminalModel,
};

/// A BIND RU with screen size byte `ssize` and the RD/CD/RA/CA bytes.
fn bind_ru(ssize: u8, rd: u8, cd: u8, ra: u8, ca: u8) -> Vec<u8> {
    let mut ru = vec![0x00; 35];
    ru[0] = 0x31;
    ru[20] = rd;
    ru[21] = cd;
    ru[22] = ra;
    ru[23] = ca;
    ru[24] = ssize;
    ru
}

fn bind(ps: &mut PresentationSpace, ru: &[u8]) -> Result<(), BindSizeError> {
    let info = BindImageInfo::parse(ru, ps.model()).unwrap();
    ps.apply_bind(info.sizes)
}

fn size(ps: &PresentationSpace) -> (u16, u16) {
    (ps.rows(), ps.cols())
}

#[test]
fn bind_sizes_are_used_by_later_erase_writes() {
    // Model 5 (27x132); the BIND asks for 27x132 as default and alternate.
    let mut ps = PresentationSpace::new(TerminalModel::Model5);
    bind(&mut ps, &bind_ru(0x7E, 27, 132, 0, 0)).unwrap();
    assert_eq!(size(&ps), (27, 132), "the BIND erases to the default size");

    DataStreamParser::process(&[0xF5, 0x00], &mut ps); // EW
    assert_eq!(size(&ps), (27, 132));
    DataStreamParser::process(&[0x7E, 0x00], &mut ps); // EWA
    assert_eq!(size(&ps), (27, 132));
}

#[test]
fn bind_with_explicit_alternate_size() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4);
    bind(&mut ps, &bind_ru(0x7F, 24, 80, 32, 80)).unwrap();
    DataStreamParser::process(&[0x7E, 0x00], &mut ps);
    assert_eq!(size(&ps), (32, 80));
    DataStreamParser::process(&[0xF5, 0x00], &mut ps);
    assert_eq!(size(&ps), (24, 80));
}

#[test]
fn bind_size_beyond_the_model_or_below_24x80_is_ignored() {
    let mut ps = PresentationSpace::new(TerminalModel::Model2);
    // Larger than Model 2.
    let err = bind(&mut ps, &bind_ru(0x7F, 24, 80, 62, 160)).unwrap_err();
    assert_eq!(err.requested, ScreenSize::new(62, 160));
    assert_eq!(err.max, ScreenSize::new(24, 80));
    // Smaller than 24x80 (also zero, as a truncated BIND would give).
    let mut ps4 = PresentationSpace::new(TerminalModel::Model4);
    assert!(bind(&mut ps4, &bind_ru(0x7E, 12, 40, 0, 0)).is_err());
    assert!(bind(&mut ps4, &bind_ru(0x7E, 0, 0, 0, 0)).is_err());
    // The previous sizes stay in effect.
    assert_eq!(
        ps4.screen_sizes(),
        BindSizes {
            default: ScreenSize::new(24, 80),
            alternate: ScreenSize::new(43, 80),
        }
    );
}

#[test]
fn bind_erases_the_screen_even_without_sizes() {
    let mut ps = PresentationSpace::new(TerminalModel::Model4);
    DataStreamParser::process(&[0x7E, 0x00, 0x1D, 0x40, 0xC1], &mut ps); // EWA + field
    assert!(ps.is_formatted());
    // Unknown screen size byte: no sizes, but the screen is erased to the default size.
    bind(&mut ps, &bind_ru(0x55, 0, 0, 0, 0)).unwrap();
    assert!(!ps.is_formatted());
    assert_eq!(size(&ps), (24, 80));
}

#[test]
fn unbind_restores_the_model_sizes_and_erases() {
    let mut ps = PresentationSpace::new(TerminalModel::Model5);
    bind(&mut ps, &bind_ru(0x7E, 27, 132, 0, 0)).unwrap();
    DataStreamParser::process(&[0xF5, 0x00, 0x1D, 0x40], &mut ps);
    ps.unbind();
    assert!(!ps.is_formatted());
    assert_eq!(size(&ps), (24, 80));
    DataStreamParser::process(&[0x7E, 0x00], &mut ps);
    assert_eq!(size(&ps), (27, 132), "alternate is the model size again");
}

// ── SSCP-LU mode (`x3270` `ctlr_write_sscp_lu`, `ctlr_read_modified`, `key_AID`) ──────────

mod sscp_lu {
    use bastion3270_core::datastream::response::build_sscp_read;
    use bastion3270_core::datastream::sscp::write_sscp_lu;
    use bastion3270_core::ebcdic::CP037;
    use bastion3270_core::{
        AidKey, BufferAddress, CharacterSet, HostMode, KeyInput, KeyOutcome, KeyboardError,
        KeyboardState, PresentationSpace, TerminalModel, VirtualKeyboard,
    };

    fn ebcdic(text: &str) -> Vec<u8> {
        text.chars()
            .map(|c| bastion3270_core::CodePage::char_to_ebcdic(&CP037, c).unwrap())
            .collect()
    }

    fn row_text(ps: &PresentationSpace, row: usize) -> String {
        let cols = usize::from(ps.cols());
        (0..cols)
            .map(|c| {
                let b = ps
                    .cell(BufferAddress::new(row * cols + c, ps.capacity()).unwrap())
                    .unwrap()
                    .raw_ebcdic();
                if b == 0 {
                    ' '
                } else {
                    bastion3270_core::CodePage::ebcdic_to_char(&CP037, b).unwrap_or('?')
                }
            })
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    /// A keyboard of a TN3270E session in SSCP-LU mode.
    fn sscp_keyboard() -> VirtualKeyboard {
        let mut kb = VirtualKeyboard::new();
        kb.disconnected();
        kb.connected();
        kb.entered_3270(true);
        kb.set_host_mode(HostMode::Data3270);
        kb.set_host_mode(HostMode::SscpLu);
        assert_eq!(kb.state(), KeyboardState::Unlocked);
        kb
    }

    #[test]
    fn sscp_lu_text_is_written_unformatted() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        // "USS", NL, SF+attr (space), "A", SBA (ignored), IC (ignored), GE 0xC5, "B".
        let mut data = ebcdic("USS");
        data.push(0x15);
        data.extend_from_slice(&[0x1D, 0x60]);
        data.extend(ebcdic("A"));
        data.extend_from_slice(&[0x11, 0x40, 0x40, 0x13, 0x08, 0xC5]);
        data.extend(ebcdic("B"));
        write_sscp_lu(&mut ps, &data).unwrap();

        assert!(!ps.is_formatted());
        assert_eq!(row_text(&ps, 0), "USS");
        // Row 1: space (for SF), 'A', APL 0xC5, 'B'.
        let at = |a: usize| *ps.cell(BufferAddress::new(a, 1920).unwrap()).unwrap();
        assert_eq!(at(80).raw_ebcdic(), 0x40);
        assert_eq!(at(81).raw_ebcdic(), 0xC1);
        assert_eq!(at(82).raw_ebcdic(), 0xC5);
        assert_eq!(at(82).extended().charset, CharacterSet::Apl);
        assert_eq!(at(83).raw_ebcdic(), 0xC2);
        assert_eq!(ps.cursor_addr().as_usize(), 84);
        assert_eq!(ps.sscp_start().as_usize(), 84);
    }

    #[test]
    fn sscp_lu_output_past_the_end_scrolls() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let mut data = ebcdic("FIRST");
        // 23 newlines: now at the start of the last row.
        data.extend(std::iter::repeat_n(0x15, 23));
        data.extend(ebcdic("LAST"));
        data.push(0x15); // past the end: scroll
        data.extend(ebcdic("NEW"));
        write_sscp_lu(&mut ps, &data).unwrap();
        assert_eq!(row_text(&ps, 0), "", "FIRST scrolled off");
        assert_eq!(row_text(&ps, 22), "LAST");
        assert_eq!(row_text(&ps, 23), "NEW");
        assert_eq!(ps.cursor_addr().as_usize(), 23 * 80 + 3);
    }

    #[test]
    fn enter_sends_the_typed_text_without_aid_and_keeps_the_keyboard_unlocked() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        write_sscp_lu(&mut ps, &ebcdic("ENTER COMMAND:")).unwrap();
        let mut kb = sscp_keyboard();
        for ch in "LOGON".chars() {
            kb.submit(&mut ps, KeyInput::Char(ch), &CP037).unwrap();
        }
        let out = kb
            .submit(&mut ps, KeyInput::Aid(AidKey::Enter), &CP037)
            .unwrap();
        assert_eq!(out, KeyOutcome::Transmit(ebcdic("LOGON")));
        assert_eq!(kb.state(), KeyboardState::Unlocked);
        assert_eq!(ps.cursor_addr().as_usize(), 80, "cursor on the next row");
    }

    #[test]
    fn sscp_read_is_limited_to_255_characters() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        write_sscp_lu(&mut ps, &[]).unwrap(); // input starts at 0
        let mut kb = sscp_keyboard();
        for _ in 0..300 {
            kb.submit(&mut ps, KeyInput::Char('X'), &CP037).unwrap();
        }
        assert_eq!(build_sscp_read(&ps).len(), 255);
    }

    #[test]
    fn other_aids_are_not_available_and_clear_is_local() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        write_sscp_lu(&mut ps, &ebcdic("TEXT")).unwrap();
        let mut kb = sscp_keyboard();
        assert_eq!(
            kb.submit(&mut ps, KeyInput::Aid(AidKey::PF3), &CP037),
            Err(KeyboardError::Locked(KeyboardState::NotAvailable))
        );
        kb.reset();
        assert_eq!(
            kb.submit(&mut ps, KeyInput::Aid(AidKey::Clear), &CP037),
            Ok(KeyOutcome::Applied)
        );
        assert_eq!(row_text(&ps, 0), "");
        assert_eq!(kb.state(), KeyboardState::Unlocked);
    }

    #[test]
    fn nvt_mode_has_no_input() {
        let mut ps = PresentationSpace::new(TerminalModel::Model2);
        let mut kb = sscp_keyboard();
        kb.set_host_mode(HostMode::Nvt);
        assert_eq!(kb.state(), KeyboardState::NotAvailable);
        kb.reset();
        assert_eq!(
            kb.submit(&mut ps, KeyInput::Char('A'), &CP037),
            Err(KeyboardError::Locked(KeyboardState::NotAvailable))
        );
        assert_eq!(row_text(&ps, 0), "");
    }
}
