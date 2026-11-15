//! The built-in EBCDIC code pages (generated from the x3270 tables by `tools/gen-codepages.py`):
//! name lookup as x3270 resolves `codePage`, round trips through every table, and spot checks
//! against independent sources (IBM layouts, Python's `codecs` for cp037 / cp273 / cp500 /
//! cp1140).

#![allow(clippy::unwrap_used, clippy::panic)]

use bastion3270_core::{CodePage, CodePageId};

#[test]
fn every_single_byte_code_page_of_the_reference_is_built_in() {
    let names: Vec<&str> = CodePageId::ALL.iter().map(|id| id.name()).collect();
    for expected in [
        "cp037", "cp273", "cp275", "cp277", "cp278", "cp280", "cp284", "cp285", "cp297", "cp424",
        "cp500", "cp803", "cp870", "cp871", "cp875", "cp880", "cp924", "cp1025", "cp1026",
        "cp1047", "cp1123", "cp1140", "cp1141", "cp1142", "cp1143", "cp1144", "cp1145", "cp1146",
        "cp1147", "cp1148", "cp1149", "cp1154", "cp1158", "cp1160", "bracket",
    ] {
        assert!(names.contains(&expected), "{expected} missing");
    }
    assert_eq!(names.len(), 35);
    assert_eq!(CodePageId::default(), CodePageId::Cp037);
}

#[test]
fn names_numbers_and_aliases_resolve_like_x3270() {
    let cases = [
        ("cp1047", CodePageId::Cp1047),
        ("CP1047", CodePageId::Cp1047),
        ("1047", CodePageId::Cp1047),
        ("ibm1140", CodePageId::Cp1140),
        ("IBM-1140", CodePageId::Cp1140),
        ("cp37", CodePageId::Cp037),
        ("037", CodePageId::Cp037),
        ("us", CodePageId::Cp037),
        ("us-euro", CodePageId::Cp1140),
        ("german", CodePageId::Cp273),
        ("german-euro", CodePageId::Cp1141),
        ("uk-euro", CodePageId::Cp1146),
        ("latin-9", CodePageId::Cp924),
        ("bracket", CodePageId::Bracket),
        ("oldibm", CodePageId::Bracket),
        ("ibm870", CodePageId::Cp870),
        ("czech", CodePageId::Cp870),
        (" Polish ", CodePageId::Cp870),
    ];
    for (name, id) in cases {
        let found = CodePageId::from_name(name);
        // `IBM-1140` is not an x3270 spelling: only the plain prefixes are accepted.
        if name == "IBM-1140" {
            assert_eq!(found, None, "{name}");
        } else {
            assert_eq!(found, Some(id), "{name}");
        }
    }
    for unknown in ["", "cp", "cp9999", "1388", "japanese-kana", "latin", "-37"] {
        assert_eq!(CodePageId::from_name(unknown), None, "{unknown:?}");
    }
}

/// Every character a table can show is typed back to a byte that shows the same character;
/// every byte comes back as itself, except where x3270's table maps two bytes to one
/// character (`cp1160`, Thai tone marks): then the first byte is used, as in x3270.
#[test]
fn every_table_round_trips() {
    let mut not_byte_exact = Vec::new();
    for &id in CodePageId::ALL {
        let cp = id.codepage();
        for byte in 0x41..=0xFE_u8 {
            let Some(ch) = cp.ebcdic_to_char(byte) else {
                continue;
            };
            let back = cp
                .char_to_ebcdic(ch)
                .unwrap_or_else(|| panic!("{}: U+{:04X} not encodable", id.name(), u32::from(ch)));
            assert_eq!(
                cp.ebcdic_to_char(back),
                Some(ch),
                "{} {byte:02X}",
                id.name()
            );
            if back != byte {
                not_byte_exact.push(format!("{}:{byte:02X}", id.name()));
            }
            assert_eq!(
                cp.ebcdic_to_display_char(byte),
                ch,
                "{} {byte:02X}",
                id.name()
            );
        }
        assert_eq!(cp.char_to_ebcdic(' '), Some(0x40));
        assert_eq!(cp.ebcdic_to_char(0x40), Some(' '));
    }
    assert_eq!(
        not_byte_exact,
        ["cp1160:ED", "cp1160:EE", "cp1160:EF", "cp1160:FD"]
    );
}

#[test]
fn spot_checks_against_independent_sources() {
    let at = |id: CodePageId, byte: u8| id.codepage().ebcdic_to_char(byte).unwrap();
    // The euro sign of the euro variants: X'9F', except Danish / Norwegian (1142) and
    // Swedish / Finnish (1143), where X'9F' keeps a national letter and the euro is X'5A'.
    for id in [
        CodePageId::Cp1140,
        CodePageId::Cp1141,
        CodePageId::Cp1144,
        CodePageId::Cp1145,
        CodePageId::Cp1146,
        CodePageId::Cp1147,
        CodePageId::Cp1148,
        CodePageId::Cp1149,
    ] {
        assert_eq!(at(id, 0x9F), '€', "{}", id.name());
    }
    assert_eq!(at(CodePageId::Cp1142, 0x5A), '€');
    assert_eq!(at(CodePageId::Cp1143, 0x5A), '€');
    // Brackets: cp037 X'BA' / X'BB', cp1047 (z/OS UNIX) X'AD' / X'BD', cp500 X'4A' / X'5A'.
    assert_eq!(
        (at(CodePageId::Cp037, 0xBA), at(CodePageId::Cp037, 0xBB)),
        ('[', ']')
    );
    assert_eq!(
        (at(CodePageId::Cp1047, 0xAD), at(CodePageId::Cp1047, 0xBD)),
        ('[', ']')
    );
    assert_eq!(
        (at(CodePageId::Cp500, 0x4A), at(CodePageId::Cp500, 0x5A)),
        ('[', ']')
    );
    // National characters.
    assert_eq!(at(CodePageId::Cp273, 0x4A), 'Ä');
    assert_eq!(at(CodePageId::Cp273, 0xC0), 'ä');
    assert_eq!(at(CodePageId::Cp285, 0x5B), '£');
    assert_eq!(at(CodePageId::Cp297, 0x7B), '£');
    assert_eq!(at(CodePageId::Cp297, 0x44), '@');
    assert_eq!(at(CodePageId::Cp870, 0xCB), 'ô');
    // Character set / code page identifiers for the Character Sets query reply.
    let cgcsgid = |id: CodePageId| id.codepage().cgcsgid();
    assert_eq!(cgcsgid(CodePageId::Cp037), 0x02B9_0025);
    assert_eq!(cgcsgid(CodePageId::Cp1047), 0x02B9_0417);
    assert_eq!(cgcsgid(CodePageId::Cp1140), 0x02B7_0474);
    assert_eq!(cgcsgid(CodePageId::Cp870), 0x03BF_0366);
    assert_eq!(CodePageId::Cp1141.codepage().host_codepage_id(), "1141");
}

#[test]
fn labels_name_the_code_page_and_its_aliases() {
    assert_eq!(CodePageId::Cp1141.label(), "CP1141 (german-euro)");
    assert_eq!(CodePageId::Cp870.label(), "CP870 (polish, slovenian)");
    assert!(CodePageId::Cp1047.label().starts_with("CP1047"));
}
