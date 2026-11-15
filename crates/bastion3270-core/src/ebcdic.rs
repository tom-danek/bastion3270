//! Modular EBCDIC ↔ Unicode translation engine.
//!
//! Reference: `x3270` (`Common/unicode.c`, `Common/tables.c`, `include/3270ds.h`).
//!
//! Designed with a modular [`CodePage`] trait so additional global single-byte or multi-byte
//! host code pages can be registered without modifying the core 3270 engine.
//! Built-in: every single-byte host code page of x3270 ([`CodePageId::ALL`]: US `cp037`,
//! `cp1047`, the euro variants `cp1140`–`cp1149`, German, UK, French, Nordic, Central European
//! `cp870`, Cyrillic, Greek, Hebrew, Turkish, Thai, ...), generated from the x3270 tables.

use core::fmt;

/// EBCDIC Null (`X'00'`). Displayed as a blank space on a 3270 screen, but not transmitted on `Read Modified`.
pub const EBC_NULL: u8 = 0x00;
/// EBCDIC Form Feed (`X'0C'`).
pub const EBC_FF: u8 = 0x0C;
/// EBCDIC Carriage Return (`X'0D'`).
pub const EBC_CR: u8 = 0x0D;
/// EBCDIC Shift Out (`X'0E'`) — starts a DBCS subfield.
pub const EBC_SO: u8 = 0x0E;
/// EBCDIC Shift In (`X'0F'`) — ends a DBCS subfield.
pub const EBC_SI: u8 = 0x0F;
/// EBCDIC New Line (`X'15'`).
pub const EBC_NL: u8 = 0x15;
/// EBCDIC End of Medium (`X'19'`).
pub const EBC_EM: u8 = 0x19;
/// EBCDIC Duplicate (`X'1C'`). Displayed as `'*'` (with overscore on 3270 hardware).
pub const EBC_DUP: u8 = 0x1C;
/// EBCDIC Field Mark (`X'1E'`). Displayed as `';'` (with overscore on 3270 hardware).
pub const EBC_FM: u8 = 0x1E;
/// EBCDIC Substitute (`X'3F'`).
pub const EBC_SUB: u8 = 0x3F;
/// EBCDIC Blank Space (`X'40'`).
pub const EBC_SPACE: u8 = 0x40;
/// EBCDIC Eight Ones (`X'FF'`).
pub const EBC_EO: u8 = 0xFF;

/// Offset of the first printable graphic character in the 190-entry `x3270` Unicode table (`X'41'`).
pub const UT_OFFSET: u8 = 0x41;
/// Number of entries in the `x3270` graphic character table (`X'41'` through `X'FE'` inclusive = 190).
pub const UT_SIZE: usize = 190;

/// Returns `true` if the EBCDIC byte is treated as blank (`EBC_NULL` or `EBC_SPACE`), matching `IsBlank(c)` in `x3270`.
pub const fn is_ebcdic_blank(byte: u8) -> bool {
    byte == EBC_NULL || byte == EBC_SPACE
}

/// Errors returned when encoding Unicode text into EBCDIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    /// The Unicode character has no representation in the active host [`CodePage`].
    UnmappableChar { ch: char, codepage: &'static str },
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The character itself stays out of the text: it may be part of a password, and
            // error texts end up in logs. It is still available in the typed error.
            Self::UnmappableChar { codepage, .. } => write!(
                f,
                "a typed character cannot be encoded in EBCDIC code page {codepage}"
            ),
        }
    }
}

/// Modular trait representing an EBCDIC host code page.
///
/// Implementations must be thread-safe (`Send + Sync`) so they can be shared across thousands of
/// concurrent sessions in `bastion3270-server`.
pub trait CodePage: fmt::Debug + Send + Sync {
    /// Canonical identifier of the code page (e.g. `"cp037"`, `"cp870"`).
    fn name(&self) -> &'static str;

    /// IBM host code page number string (e.g. `"37"`, `"870"`).
    fn host_codepage_id(&self) -> &'static str;

    /// IBM Coded Graphic Character Set Global Identifier (`CGCSGID`) reported in `Query Reply (Character Sets)`.
    fn cgcsgid(&self) -> u32;

    /// Converts an EBCDIC byte into its **displayable** Unicode `char` for rendering on the 3270 grid.
    ///
    /// - `EBC_NULL (0x00)` and `EBC_SPACE (0x40)` map to `' '` (`U+0020`).
    /// - `EBC_DUP (0x1C)` maps to `'*'`.
    /// - `EBC_FM (0x1E)` maps to `';'`.
    /// - Control characters (`0x01..=0x3F`, `0xFF`) never emit raw terminal control codes; they map to `' '`.
    fn ebcdic_to_display_char(&self, byte: u8) -> char;

    /// Converts an EBCDIC byte into its exact semantic Unicode `char`, if defined.
    ///
    /// Returns `Some('\0')` for `EBC_NULL`, `Some(' ')` for `EBC_SPACE`, `Some('*')` for `EBC_DUP`,
    /// `Some(';')` for `EBC_FM`, mapped characters for `0x41..=0xFE`, and `None` for unmapped control codes.
    fn ebcdic_to_char(&self, byte: u8) -> Option<char>;

    /// Converts a Unicode `char` into its corresponding EBCDIC byte in this code page.
    ///
    /// Returns `None` if the character is not present in this code page.
    fn char_to_ebcdic(&self, ch: char) -> Option<u8>;

    /// Decodes a slice of EBCDIC bytes into a displayable UTF-8 [`String`].
    fn decode_display_slice(&self, bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            out.push(self.ebcdic_to_display_char(b));
        }
        out
    }

    /// Encodes a UTF-8 string (`&str`) into a vector of EBCDIC bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::UnmappableChar`] on the first character not present in this code page.
    fn encode_str(&self, text: &str) -> Result<Vec<u8>, EncodingError> {
        let mut out = Vec::with_capacity(text.len());
        for ch in text.chars() {
            let b = self
                .char_to_ebcdic(ch)
                .ok_or(EncodingError::UnmappableChar {
                    ch,
                    codepage: self.name(),
                })?;
            out.push(b);
        }
        Ok(out)
    }
}

// The tables, `CodePageId` and its `ALL` / `codepage` / `name` / `aliases` are generated from
// the x3270 reference by `tools/gen-codepages.py`.
mod tables;
/// `cp870` under the name the code used before the tables were generated.
pub use tables::CP870 as IBM870;
pub use tables::*;

/// Names accepted besides the x3270 ones, kept for existing profiles.
const EXTRA_ALIASES: &[(&str, CodePageId)] = &[
    ("czech", CodePageId::Cp870),
    ("latin2", CodePageId::Cp870),
    ("central-europe", CodePageId::Cp870),
];

impl CodePageId {
    /// Looks up a built-in code page by name, case-insensitively: the canonical name
    /// (`cp1047`), the number with an optional `cp` / `ibm` prefix (`1047`, `ibm1047`,
    /// `cp37` = `cp037`), or an x3270 alias (`german-euro`, `us`, ...), as x3270's
    /// `set_uni` resolves `codePage`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        if let Some(id) = Self::ALL
            .iter()
            .copied()
            .find(|id| id.name() == name || id.aliases().contains(&name.as_str()))
        {
            return Some(id);
        }
        if let Some(&(_, id)) = EXTRA_ALIASES.iter().find(|(alias, _)| *alias == name) {
            return Some(id);
        }
        // A number: the host code page (the first table wins, i.e. `cp037` before `bracket`).
        let digits = name
            .strip_prefix("cp")
            .or_else(|| name.strip_prefix("ibm"))
            .unwrap_or(&name);
        let number: u32 = digits.parse().ok()?;
        Self::ALL
            .iter()
            .copied()
            .find(|id| id.codepage().host_codepage_id.parse() == Ok(number))
    }

    /// A label for selection lists: `CP1141 (german-euro)`.
    #[must_use]
    pub fn label(self) -> String {
        let name = self.name().to_ascii_uppercase();
        match self.aliases() {
            [] => name,
            aliases => format!("{name} ({})", aliases.join(", ")),
        }
    }
}

/// A compile-time table-driven single-byte EBCDIC [`CodePage`].
///
/// Stores a precomputed 256-entry display lookup table for $O(1)$ branchless rendering, plus
/// the 190-entry UCS-2 graphic table (`0x41..=0xFE`) matching `x3270` (`Common/unicode.c`).
#[derive(Debug, Clone)]
pub struct StaticCodePage {
    name: &'static str,
    host_codepage_id: &'static str,
    cgcsgid: u32,
    ut_table: [u16; UT_SIZE],
    display_table: [char; 256],
}

impl StaticCodePage {
    /// Constructs a [`StaticCodePage`] at compile time from a 190-entry `x3270` UCS-2 table (`X'41'..=X'FE'`).
    // Index and counter arithmetic is bounded by `i < UT_SIZE` (`0x41 + 189 = 0xFE`). The
    // tables are built in `static` initialisers, where any overflow would be a compile error.
    #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    pub const fn from_ut_table(
        name: &'static str,
        host_codepage_id: &'static str,
        cgcsgid: u32,
        ut_table: [u16; UT_SIZE],
    ) -> Self {
        let mut display_table = [' '; 256];
        display_table[EBC_DUP as usize] = '*';
        display_table[EBC_FM as usize] = ';';

        let mut i = 0;
        while i < UT_SIZE {
            let code = ut_table[i];
            if code != 0 {
                if let Some(ch) = char::from_u32(code as u32) {
                    display_table[(UT_OFFSET as usize) + i] = ch;
                }
            }
            i += 1;
        }

        Self {
            name,
            host_codepage_id,
            cgcsgid,
            ut_table,
            display_table,
        }
    }

    /// Fast `const` $O(1)$ lookup of the display character for `byte`.
    #[allow(clippy::indexing_slicing)]
    pub const fn display_char(&self, byte: u8) -> char {
        // `byte as usize` is always in `0..=255`, matching `[char; 256]`.
        self.display_table[byte as usize]
    }
}

impl CodePage for StaticCodePage {
    fn name(&self) -> &'static str {
        self.name
    }

    fn host_codepage_id(&self) -> &'static str {
        self.host_codepage_id
    }

    fn cgcsgid(&self) -> u32 {
        self.cgcsgid
    }

    fn ebcdic_to_display_char(&self, byte: u8) -> char {
        self.display_char(byte)
    }

    fn ebcdic_to_char(&self, byte: u8) -> Option<char> {
        match byte {
            EBC_NULL => Some('\0'),
            EBC_SPACE => Some(' '),
            EBC_DUP => Some('*'),
            EBC_FM => Some(';'),
            0x41..=0xFE => {
                let idx = usize::from(byte.checked_sub(UT_OFFSET)?);
                let ucs2 = self.ut_table.get(idx).copied().unwrap_or(0);
                if ucs2 == 0 {
                    None
                } else {
                    char::from_u32(u32::from(ucs2))
                }
            }
            _ => None,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn char_to_ebcdic(&self, ch: char) -> Option<u8> {
        if ch == ' ' {
            return Some(EBC_SPACE);
        }
        if ch == '\0' {
            return Some(EBC_NULL);
        }
        let code = u32::from(ch);
        if code > u32::from(u16::MAX) {
            return None;
        }
        let target = code as u16;
        for (idx, &entry) in self.ut_table.iter().enumerate() {
            if entry == target && entry != 0 {
                return UT_OFFSET.checked_add(u8::try_from(idx).ok()?);
            }
        }
        None
    }
}

// ── APL / Graphic Escape character set (CP310) ─────────────────────────────────────────────

/// EBCDIC (CP310, APL / Graphic Escape) → Unicode, generated from `apl2uc[]` in `x3270`
/// `Common/unicode.c`. `0x0000` means "no APL glyph" (see [`apl_to_char`] for the fallback).
///
/// This is the set ISPF and other z/OS applications use, via the `GE` order or the
/// `XA_CHARSET = 0xF1` attribute, for box drawing (`┌ ─ ┐ │ └ ┘ ├ ┤ ┬ ┴ ┼`) and APL symbols.
#[rustfmt::skip]
const APL_TO_UNICODE: [u16; 256] = [
    /* 00 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 08 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 10 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 18 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 20 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 40 */ 0x0020, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 48 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 60 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 68 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 70 */ 0x22C4, 0x2227, 0x00A8, 0x233B, 0x2378, 0x2377, 0x22A2, 0x22A3,
    /* 78 */ 0x2228, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 80 */ 0x223C, 0x0000, 0x0000, 0x23B8, 0x23B9, 0x2502, 0x0000, 0x0000,
    /* 88 */ 0x0000, 0x0000, 0x2191, 0x2193, 0x2264, 0x2308, 0x230A, 0x2192,
    /* 90 */ 0x2395, 0x258C, 0x2590, 0x2580, 0x2584, 0x25A0, 0x0000, 0x0000,
    /* 98 */ 0x0000, 0x0000, 0x2283, 0x2282, 0x00A4, 0x25CB, 0x00B1, 0x2190,
    /* A0 */ 0x00AF, 0x00B0, 0x2500, 0x2022, 0x0000, 0x0000, 0x0000, 0x0000,
    /* A8 */ 0x0000, 0x0000, 0x2229, 0x222A, 0x22A5, 0x005B, 0x2265, 0x2218,
    /* B0 */ 0x237A, 0x220A, 0x2373, 0x2374, 0x2375, 0x0000, 0x00D7, 0x005C,
    /* B8 */ 0x00F7, 0x0000, 0x2207, 0x2206, 0x22A4, 0x005D, 0x2260, 0x2223,
    /* C0 */ 0x007B, 0x207C, 0x002B, 0x220E, 0x2514, 0x250C, 0x251C, 0x2534,
    /* C8 */ 0x00A7, 0x0000, 0x2372, 0x2371, 0x2337, 0x233D, 0x2342, 0x2349,
    /* D0 */ 0x007D, 0x207E, 0x002D, 0x253C, 0x2518, 0x2510, 0x2524, 0x252C,
    /* D8 */ 0x00B6, 0x0000, 0x2336, 0x0021, 0x2352, 0x234B, 0x235E, 0x235D,
    /* E0 */ 0x2261, 0x2081, 0x0282, 0x0283, 0x2364, 0x2365, 0x236A, 0x20AC,
    /* E8 */ 0x0000, 0x0000, 0x233F, 0x2340, 0x2235, 0x2296, 0x2339, 0x2355,
    /* F0 */ 0x2070, 0x00B9, 0x00B2, 0x00B3, 0x2074, 0x2075, 0x2076, 0x2077,
    /* F8 */ 0x2078, 0x2079, 0x0000, 0x236B, 0x2359, 0x235F, 0x234E, 0x0000,
];

/// APL "underscored A–Z" positions, rendered as plain letters (`x3270` `undera[]`).
const APL_UNDERSCORED_LETTERS: [u8; 26] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
];

/// Translates a byte of the APL / Graphic Escape character set (CP310) to a Unicode `char`.
///
/// Returns `None` for `0x00` and for positions without an APL glyph; the caller then falls back
/// to the base code page, like `x3270` does.
pub fn apl_to_char(byte: u8) -> Option<char> {
    if byte == EBC_NULL {
        return None;
    }
    let code = APL_TO_UNICODE.get(usize::from(byte)).copied().unwrap_or(0);
    if code != 0 {
        return char::from_u32(u32::from(code));
    }
    // Underscored letters: index into the 26-letter table gives the offset from 'A'.
    let pos = APL_UNDERSCORED_LETTERS.iter().position(|&b| b == byte)?;
    let offset = u8::try_from(pos).ok()?;
    Some(char::from(b'A'.saturating_add(offset)))
}

#[cfg(test)]
mod tests {
    /// Error texts go to logs; a character typed into a password field must not.
    #[test]
    fn test_encoding_error_text_does_not_contain_the_character() {
        let err = super::EncodingError::UnmappableChar {
            ch: '\u{20AC}',
            codepage: "cp037",
        };
        let text = err.to_string();
        assert!(
            !text.contains('\u{20AC}') && !text.contains("20AC"),
            "{text}"
        );
        assert!(text.contains("cp037"));
    }

    #[test]
    fn test_apl_box_drawing_characters() {
        // ISPF pop-up frame (CP310): corners, horizontal and vertical lines.
        assert_eq!(super::apl_to_char(0xC5), Some('┌'));
        assert_eq!(super::apl_to_char(0xD5), Some('┐'));
        assert_eq!(super::apl_to_char(0xC4), Some('└'));
        assert_eq!(super::apl_to_char(0xD4), Some('┘'));
        assert_eq!(super::apl_to_char(0xA2), Some('─'));
        assert_eq!(super::apl_to_char(0x85), Some('│'));
        assert_eq!(super::apl_to_char(0xD3), Some('┼'));
        // Underscored A and Z positions fall back to letters; null and gaps give None.
        assert_eq!(super::apl_to_char(0x41), Some('A'));
        assert_eq!(super::apl_to_char(0x69), Some('Z'));
        assert_eq!(super::apl_to_char(0x00), None);
        assert_eq!(super::apl_to_char(0x99), None);
    }

    use super::*;

    #[test]
    fn test_cp037_ascii_and_mainframe_symbols() {
        assert_eq!(CP037.ebcdic_to_display_char(EBC_NULL), ' ');
        assert_eq!(CP037.ebcdic_to_display_char(EBC_SPACE), ' ');
        assert_eq!(CP037.ebcdic_to_display_char(EBC_DUP), '*');
        assert_eq!(CP037.ebcdic_to_display_char(EBC_FM), ';');
        assert_eq!(CP037.ebcdic_to_display_char(0xC1), 'A');
        assert_eq!(CP037.ebcdic_to_display_char(0xF0), '0');
        assert_eq!(CP037.ebcdic_to_display_char(0xF9), '9');
        assert_eq!(CP037.ebcdic_to_display_char(0x4A), '¢');

        let encoded = CP037.encode_str("HERC01 / SYS1.PARMLIB(IEFSSN00)");
        assert!(encoded.is_ok());
        if let Ok(bytes) = encoded {
            assert_eq!(
                CP037.decode_display_slice(&bytes),
                "HERC01 / SYS1.PARMLIB(IEFSSN00)"
            );
        }
    }

    #[test]
    fn test_ibm870_czech_diacritics_roundtrip() {
        let czech_phrase = "Příliš žluťoučký kůň úpěl ďábelské ódy ÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ";
        let encoded = IBM870.encode_str(czech_phrase);
        assert!(encoded.is_ok());
        if let Ok(bytes) = encoded {
            let decoded = IBM870.decode_display_slice(&bytes);
            assert_eq!(decoded, czech_phrase);
        }

        // Verify unmappable character (e.g. Emoji) returns structured EncodingError
        assert_eq!(
            IBM870.encode_str("🦀"),
            Err(EncodingError::UnmappableChar {
                ch: '🦀',
                codepage: "cp870"
            })
        );
    }

    #[test]
    fn test_codepage_lookup() {
        assert_eq!(CodePageId::from_name("cp037"), Some(CodePageId::Cp037));
        assert_eq!(CodePageId::from_name("IBM870"), Some(CodePageId::Cp870));
        assert_eq!(CodePageId::from_name("czech"), Some(CodePageId::Cp870));
        assert_eq!(CodePageId::from_name("unknown"), None);
    }
}
