//! IBM 3270 Field Attributes (`SF`) and Extended Attributes (`SFE`, `SA`, `MF`).
//!
//! Reference: `x3270` (`include/3270ds.h`, `include/globals.h`, `Common/ctlr.c`).

use crate::address::encode_six_bit;

/// Field attribute bit: Protected (`1`) vs Unprotected (`0`).
pub const FA_PROTECT: u8 = 0x20;
/// Field attribute bit: Numeric (`1`) vs Alphanumeric (`0`).
pub const FA_NUMERIC: u8 = 0x10;
/// Field attribute mask for display intensity and selector-pen detectability.
pub const FA_INTENSITY: u8 = 0x0C;
/// Intensity value `00`: Normal display, non-detectable by light pen.
pub const FA_INT_NORM_NSEL: u8 = 0x00;
/// Intensity value `01`: Normal display, detectable by light pen.
pub const FA_INT_NORM_SEL: u8 = 0x04;
/// Intensity value `10`: High intensity (bright), detectable by light pen.
pub const FA_INT_HIGH_SEL: u8 = 0x08;
/// Intensity value `11`: Non-display (dark/hidden, used for passwords), non-detectable.
pub const FA_INT_ZERO_NSEL: u8 = 0x0C;
/// Reserved bit in 3270 field attribute (`0x02`, always 0).
pub const FA_RESERVED: u8 = 0x02;
/// Field attribute bit: Modified Data Tag (`MDT`) — `1` if modified by user or host.
pub const FA_MODIFY: u8 = 0x01;
/// Mask of active bits stored in a 3270 field attribute (`0x3D`).
pub const FA_MASK: u8 = FA_PROTECT | FA_NUMERIC | FA_INTENSITY | FA_MODIFY;

/// Extended attribute type code: Reset all attributes (`X'00'`).
pub const XA_ALL: u8 = 0x00;
/// Extended attribute type code: Basic 3270 field attribute (`X'C0'`).
pub const XA_3270: u8 = 0xC0;
/// Extended attribute type code: Field validation (`X'C1'`).
pub const XA_VALIDATION: u8 = 0xC1;
/// Extended attribute type code: Field outlining (`X'C2'`).
pub const XA_OUTLINING: u8 = 0xC2;
/// Extended attribute type code: Extended highlighting (`X'41'`).
pub const XA_HIGHLIGHTING: u8 = 0x41;
/// Extended attribute type code: Foreground color (`X'42'`).
pub const XA_FOREGROUND: u8 = 0x42;
/// Extended attribute type code: Character set (`X'43'`).
pub const XA_CHARSET: u8 = 0x43;
/// Extended attribute type code: Background color (`X'45'`).
pub const XA_BACKGROUND: u8 = 0x45;
/// Extended attribute type code: Transparency (`X'46'`).
pub const XA_TRANSPARENCY: u8 = 0x46;
/// Extended attribute type code: Input control (`X'FE'`).
pub const XA_INPUT_CONTROL: u8 = 0xFE;

/// Display intensity and light-pen detectability of a 3270 field.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldIntensity {
    /// `00` (`0x00`): Normal intensity, not light-pen detectable.
    #[default]
    NormalNonDetectable,
    /// `01` (`0x04`): Normal intensity, light-pen detectable.
    NormalDetectable,
    /// `10` (`0x08`): High intensity (intensified / bright), light-pen detectable.
    HighDetectable,
    /// `11` (`0x0C`): Non-display (dark / hidden — used for password fields), not detectable.
    NonDisplay,
}

impl FieldIntensity {
    /// Extracts the [`FieldIntensity`] from raw attribute bits.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & FA_INTENSITY {
            FA_INT_NORM_NSEL => Self::NormalNonDetectable,
            FA_INT_NORM_SEL => Self::NormalDetectable,
            FA_INT_HIGH_SEL => Self::HighDetectable,
            _ => Self::NonDisplay,
        }
    }

    /// Converts this [`FieldIntensity`] into its 2-bit mask (`0x00`, `0x04`, `0x08`, `0x0C`).
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NormalNonDetectable => FA_INT_NORM_NSEL,
            Self::NormalDetectable => FA_INT_NORM_SEL,
            Self::HighDetectable => FA_INT_HIGH_SEL,
            Self::NonDisplay => FA_INT_ZERO_NSEL,
        }
    }
}

/// Basic 3270 Field Attribute (`SF` order or `XA_3270` in `SFE`).
///
/// Stored normalized with [`FA_MASK`] (`0x3D`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldAttribute(u8);

impl FieldAttribute {
    /// Default unprotected, alphanumeric, normal-display, unmodified attribute.
    pub const UNPROTECTED_NORMAL: Self = Self(0x00);

    /// Default protected, alphanumeric, normal-display, unmodified attribute.
    pub const PROTECTED_NORMAL: Self = Self(FA_PROTECT);

    /// Protected auto-skip (`Protected | Numeric`), normal-display attribute.
    pub const PROTECTED_SKIP: Self = Self(FA_PROTECT | FA_NUMERIC);

    /// Constructs a [`FieldAttribute`] from a raw byte in the 3270 data stream, masking to [`FA_MASK`].
    pub const fn from_wire_byte(byte: u8) -> Self {
        Self(byte & FA_MASK)
    }

    /// Constructs a [`FieldAttribute`] from structured properties.
    pub const fn new(
        protected: bool,
        numeric: bool,
        intensity: FieldIntensity,
        modified: bool,
    ) -> Self {
        let mut bits = intensity.to_bits();
        if protected {
            bits |= FA_PROTECT;
        }
        if numeric {
            bits |= FA_NUMERIC;
        }
        if modified {
            bits |= FA_MODIFY;
        }
        Self(bits)
    }

    /// Returns the raw masked attribute bits (`0..=0x3D`).
    pub const fn raw_bits(self) -> u8 {
        self.0
    }

    /// Encodes this field attribute into its printable 3270 wire byte using [`encode_six_bit`].
    pub const fn to_wire_byte(self) -> u8 {
        encode_six_bit(self.0)
    }

    /// Returns `true` if the field is **protected** against user input (`FA_IS_PROTECTED`).
    pub const fn is_protected(self) -> bool {
        (self.0 & FA_PROTECT) != 0
    }

    /// Returns `true` if the field has the **numeric** bit set (`FA_IS_NUMERIC`).
    pub const fn is_numeric(self) -> bool {
        (self.0 & FA_NUMERIC) != 0
    }

    /// Returns `true` if the field is an **auto-skip** field (`Protected && Numeric`, `FA_IS_SKIP` in `x3270`).
    ///
    /// When the cursor reaches the end of an unprotected field followed by an auto-skip field,
    /// it automatically jumps to the next unprotected field on the screen.
    pub const fn is_skip(self) -> bool {
        self.is_protected() && self.is_numeric()
    }

    /// Returns the [`FieldIntensity`] of the field.
    pub const fn intensity(self) -> FieldIntensity {
        FieldIntensity::from_bits(self.0)
    }

    /// Returns `true` if the field is **Non-display** (hidden/dark, e.g. password field, `FA_IS_ZERO`).
    ///
    /// **Zero-Trust Security Invariant:** Cells governed by a field where `is_non_display()` is `true`
    /// must never be exported in cleartext to `SafeScreenView` or diagnostic logs.
    pub const fn is_non_display(self) -> bool {
        matches!(self.intensity(), FieldIntensity::NonDisplay)
    }

    /// Returns `true` if the field is **high-intensity** (bright, `FA_IS_HIGH`).
    pub const fn is_intensified(self) -> bool {
        matches!(self.intensity(), FieldIntensity::HighDetectable)
    }

    /// Returns `true` if the field is **normal-intensity** (`FA_IS_NORMAL`).
    pub const fn is_normal(self) -> bool {
        matches!(
            self.intensity(),
            FieldIntensity::NormalNonDetectable | FieldIntensity::NormalDetectable
        )
    }

    /// Returns `true` if the field is light-pen **selectable** (`FA_IS_SELECTABLE`).
    pub const fn is_selectable(self) -> bool {
        matches!(
            self.intensity(),
            FieldIntensity::NormalDetectable | FieldIntensity::HighDetectable
        )
    }

    /// Returns `true` if the **Modified Data Tag (`MDT`)** is set (`FA_IS_MODIFIED`).
    pub const fn is_modified(self) -> bool {
        (self.0 & FA_MODIFY) != 0
    }

    /// Returns a copy of this [`FieldAttribute`] with the `MDT` bit set to `modified`.
    #[must_use]
    pub const fn with_modified(self, modified: bool) -> Self {
        if modified {
            Self(self.0 | FA_MODIFY)
        } else {
            Self(self.0 & !FA_MODIFY)
        }
    }

    /// Mutates the `MDT` bit in place.
    pub fn set_modified(&mut self, modified: bool) {
        *self = self.with_modified(modified);
    }
}

/// IBM 3279 Extended Color values (`XA_FOREGROUND` / `XA_BACKGROUND`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Color3270 {
    /// Device default color (`X'00'`) — determined by base 3270 field attribute intensity/protection.
    #[default]
    Default,
    /// `X'F0'`: Neutral Black (Background default).
    NeutralBlack,
    /// `X'F1'`: Blue.
    Blue,
    /// `X'F2'`: Red.
    Red,
    /// `X'F3'`: Pink (Magenta).
    Pink,
    /// `X'F4'`: Green.
    Green,
    /// `X'F5'`: Turquoise (Cyan).
    Turquoise,
    /// `X'F6'`: Yellow.
    Yellow,
    /// `X'F7'`: Neutral White (Foreground intensified default).
    NeutralWhite,
    /// `X'F8'`: Black.
    Black,
    /// `X'F9'`: Deep Blue.
    DeepBlue,
    /// `X'FA'`: Orange.
    Orange,
    /// `X'FB'`: Purple.
    Purple,
    /// `X'FC'`: Pale Green.
    PaleGreen,
    /// `X'FD'`: Pale Turquoise.
    PaleTurquoise,
    /// `X'FE'`: Grey.
    Grey,
    /// `X'FF'`: White.
    White,
}

impl Color3270 {
    /// Parses an extended color attribute byte (`X'00'` or `X'F0'..=X'FF'`).
    ///
    /// Unrecognized values fall back safely to [`Color3270::Default`].
    pub const fn from_xa_byte(byte: u8) -> Self {
        match byte {
            0xF0 => Self::NeutralBlack,
            0xF1 => Self::Blue,
            0xF2 => Self::Red,
            0xF3 => Self::Pink,
            0xF4 => Self::Green,
            0xF5 => Self::Turquoise,
            0xF6 => Self::Yellow,
            0xF7 => Self::NeutralWhite,
            0xF8 => Self::Black,
            0xF9 => Self::DeepBlue,
            0xFA => Self::Orange,
            0xFB => Self::Purple,
            0xFC => Self::PaleGreen,
            0xFD => Self::PaleTurquoise,
            0xFE => Self::Grey,
            0xFF => Self::White,
            _ => Self::Default,
        }
    }

    /// Converts this [`Color3270`] back into its 3270 extended attribute wire byte.
    pub const fn to_xa_byte(self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::NeutralBlack => 0xF0,
            Self::Blue => 0xF1,
            Self::Red => 0xF2,
            Self::Pink => 0xF3,
            Self::Green => 0xF4,
            Self::Turquoise => 0xF5,
            Self::Yellow => 0xF6,
            Self::NeutralWhite => 0xF7,
            Self::Black => 0xF8,
            Self::DeepBlue => 0xF9,
            Self::Orange => 0xFA,
            Self::Purple => 0xFB,
            Self::PaleGreen => 0xFC,
            Self::PaleTurquoise => 0xFD,
            Self::Grey => 0xFE,
            Self::White => 0xFF,
        }
    }
}

/// IBM 3270 Extended Highlighting (`XA_HIGHLIGHTING`) as a set of flags.
///
/// Stored like the `gr` byte of an `x3270` buffer cell (`include/globals.h` `GR_*`): blink,
/// reverse video, underscore and intensify may be combined (wire `X'F6'` = reverse video and
/// underscore). The wire value is `X'F0' | flags`; both `X'00'` and `X'F0'` ("normal") store as
/// [`Highlight3270::DEFAULT`], which on a character means "inherit the field highlighting".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Highlight3270(u8);

impl Highlight3270 {
    /// No highlighting of its own (`X'00'` or `X'F0'`).
    pub const DEFAULT: Self = Self(0x00);
    /// Blink (`X'F1'`, `GR_BLINK`).
    pub const BLINK: Self = Self(0x01);
    /// Reverse video (`X'F2'`, `GR_REVERSE`).
    pub const REVERSE_VIDEO: Self = Self(0x02);
    /// Underscore (`X'F4'`, `GR_UNDERLINE`).
    pub const UNDERSCORE: Self = Self(0x04);
    /// Intensify (`X'F8'`, `GR_INTENSIFY`).
    pub const INTENSIFY: Self = Self(0x08);

    /// Parses the highlighting value of an `SA` or `MF` order: the low four bits are the
    /// flags (`x3270` `ctlr_write()`: `*cp & 0x0f`).
    pub const fn from_xa_byte(byte: u8) -> Self {
        Self(byte & 0x0F)
    }

    /// Parses the highlighting value of an `SFE` order. `x3270` keeps only blink, reverse
    /// video and underscore for a field (`ctlr_write()`: `efa_gr = *cp & 0x07`); field
    /// intensity comes from the base field attribute.
    pub const fn from_sfe_byte(byte: u8) -> Self {
        Self(byte & 0x07)
    }

    /// The wire value reported to the host: `X'00'` for no highlighting, otherwise
    /// `X'F0' | flags` (`x3270` `ctlr_read_buffer()`: `gr | 0xf0`).
    pub const fn to_xa_byte(self) -> u8 {
        if self.0 == 0 {
            0x00
        } else {
            self.0 | 0xF0
        }
    }

    /// The flag bits (`GR_*`): blink `0x01`, reverse `0x02`, underscore `0x04`,
    /// intensify `0x08`.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// `true` if no flag is set.
    pub const fn is_default(self) -> bool {
        self.0 == 0
    }

    /// `true` if every flag of `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        other.0 != 0 && self.0 & other.0 == other.0
    }

    /// The union of both flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Character set selection (`XA_CHARSET` or `GE` Graphic Escape).
///
/// On the wire only `X'F1'` (APL) and `X'F8'` (DBCS) are special; every other value selects
/// the base set (`x3270` `ctlr_write()`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharacterSet {
    /// Base host code page (`CS_BASE`).
    #[default]
    Base,
    /// APL / Graphic Escape box-drawing and symbol set (`CS_APL` / `CS_GE`).
    Apl,
    /// Double-Byte Character Set (`CS_DBCS`).
    Dbcs,
}

impl CharacterSet {
    /// Parses the character set value of an `SA` or `MF` order: `X'F1'` APL, `X'F8'` DBCS,
    /// anything else the base set.
    pub const fn from_xa_byte(byte: u8) -> Self {
        match byte {
            0xF1 => Self::Apl,
            0xF8 => Self::Dbcs,
            _ => Self::Base,
        }
    }

    /// Parses the character set value of an `SFE` order. A DBCS field needs a DBCS terminal
    /// (`x3270` `ctlr_write()`: `dbcs && *cp == 0xf8`); this terminal does not report DBCS
    /// support, so only `X'F1'` (APL) is special.
    pub const fn from_sfe_byte(byte: u8) -> Self {
        match byte {
            0xF1 => Self::Apl,
            _ => Self::Base,
        }
    }

    /// The `XA_CHARSET` value reported to the host (`x3270` `host_cs`): `0x00` for the base
    /// set, `0xF1` APL, `0xF8` DBCS.
    pub const fn to_xa_byte(self) -> u8 {
        match self {
            Self::Base => 0x00,
            Self::Apl => 0xF1,
            Self::Dbcs => 0xF8,
        }
    }
}

/// The order an extended attribute pair arrives in. The three orders interpret the same
/// pair slightly differently (`x3270` `ctlr_write()`, cases `ORDER_SFE`, `ORDER_MF`,
/// `ORDER_SA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeOrder {
    /// Start Field Extended: attributes of a new field.
    StartFieldExtended,
    /// Modify Field: changes the listed attributes of an existing field.
    ModifyField,
    /// Set Attribute: the attributes of the following characters.
    SetAttribute,
}

/// Combined extended attributes (`SFE`, `MF`, or character-level `SA`) associated with a field or cell.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedAttributes {
    /// Foreground color (`XA_FOREGROUND`).
    pub foreground: Color3270,
    /// Background color (`XA_BACKGROUND`).
    pub background: Color3270,
    /// Highlighting mode (`XA_HIGHLIGHTING`).
    pub highlight: Highlight3270,
    /// Character set (`XA_CHARSET`).
    pub charset: CharacterSet,
}

impl ExtendedAttributes {
    /// Default (empty) extended attributes.
    pub const DEFAULT: Self = Self {
        foreground: Color3270::Default,
        background: Color3270::Default,
        highlight: Highlight3270::DEFAULT,
        charset: CharacterSet::Base,
    };

    /// Resets all extended attributes to default (`SA 0x00 0x00`).
    pub fn reset(&mut self) {
        *self = Self::DEFAULT;
    }

    /// Applies a single `(attr_type, attr_value)` pair of an `SFE`, `MF` or `SA` order.
    ///
    /// `XA_ALL` resets every attribute only in `SA`; `SFE` and `MF` ignore it (`x3270`
    /// `ctlr_write()`). The base field attribute (`XA_3270`) and unsupported types are
    /// handled by the caller or ignored.
    pub fn apply_pair(&mut self, order: AttributeOrder, attr_type: u8, attr_value: u8) {
        let sfe = order == AttributeOrder::StartFieldExtended;
        match attr_type {
            XA_ALL if order == AttributeOrder::SetAttribute => self.reset(),
            XA_FOREGROUND => self.foreground = Color3270::from_xa_byte(attr_value),
            XA_BACKGROUND => self.background = Color3270::from_xa_byte(attr_value),
            XA_HIGHLIGHTING if sfe => self.highlight = Highlight3270::from_sfe_byte(attr_value),
            XA_HIGHLIGHTING => self.highlight = Highlight3270::from_xa_byte(attr_value),
            XA_CHARSET if sfe => self.charset = CharacterSet::from_sfe_byte(attr_value),
            XA_CHARSET => self.charset = CharacterSet::from_xa_byte(attr_value),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_attribute_flags_and_wire_encoding() {
        // Protected + Numeric = Auto-Skip
        let skip = FieldAttribute::new(true, true, FieldIntensity::NormalNonDetectable, false);
        assert!(skip.is_protected());
        assert!(skip.is_numeric());
        assert!(skip.is_skip());
        assert!(skip.is_normal());
        assert!(!skip.is_non_display());
        assert!(!skip.is_modified());
        // 0x20 | 0x10 = 0x30 -> CODE_TABLE[0x30 (48)] = 0xF0
        assert_eq!(skip.to_wire_byte(), 0xF0);

        // Password field: Unprotected + NonDisplay (0x0C)
        let mut passwd = FieldAttribute::from_wire_byte(0x4C); // 0x4C & 0x3D = 0x0C
        assert!(!passwd.is_protected());
        assert!(passwd.is_non_display());
        assert!(!passwd.is_selectable());
        assert!(!passwd.is_modified());

        passwd.set_modified(true);
        assert!(passwd.is_modified());
        assert_eq!(
            FieldAttribute::from_wire_byte(passwd.to_wire_byte()),
            passwd
        );
    }

    #[test]
    fn test_extended_attributes_apply() {
        use AttributeOrder::{ModifyField, SetAttribute, StartFieldExtended};
        let mut xa = ExtendedAttributes::DEFAULT;
        xa.apply_pair(SetAttribute, XA_FOREGROUND, 0xF5); // Turquoise
        xa.apply_pair(SetAttribute, XA_HIGHLIGHTING, 0xF4); // Underscore
        assert_eq!(xa.foreground, Color3270::Turquoise);
        assert_eq!(xa.highlight, Highlight3270::UNDERSCORE);

        // XA_ALL is ignored in SFE and MF ...
        xa.apply_pair(StartFieldExtended, XA_ALL, 0x00);
        xa.apply_pair(ModifyField, XA_ALL, 0x00);
        assert_eq!(xa.foreground, Color3270::Turquoise);
        // ... and resets everything in SA.
        xa.apply_pair(SetAttribute, XA_ALL, 0x00);
        assert_eq!(xa, ExtendedAttributes::DEFAULT);
    }
}
