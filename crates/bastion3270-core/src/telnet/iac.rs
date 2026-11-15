//! Telnet protocol constants, commands, options, and byte escaping helpers (RFC 854, 855, 885, 1091).

// Telnet Commands (RFC 854)
/// Interpret As Command (255 / `0xFF`).
pub const IAC: u8 = 255;
/// Don't use option (254 / `0xFE`).
pub const DONT: u8 = 254;
/// Do use option (253 / `0xFD`).
pub const DO: u8 = 253;
/// Won't use option (252 / `0xFC`).
pub const WONT: u8 = 252;
/// Will use option (251 / `0xFB`).
pub const WILL: u8 = 251;
/// Subnegotiation Begin (250 / `0xFA`).
pub const SB: u8 = 250;
/// Go Ahead (249 / `0xF9`).
pub const GA: u8 = 249;
/// Erase Line (248 / `0xF8`).
pub const EL: u8 = 248;
/// Erase Character (247 / `0xF7`).
pub const EC: u8 = 247;
/// Are You There (246 / `0xF6`).
pub const AYT: u8 = 246;
/// Abort Output (245 / `0xF5`).
pub const AO: u8 = 245;
/// Interrupt Process (244 / `0xF4`).
pub const IP: u8 = 244;
/// Break (243 / `0xF3`).
pub const BREAK: u8 = 243;
/// Data Mark (242 / `0xF2`).
pub const DM: u8 = 242;
/// No Operation (241 / `0xF1`).
pub const NOP: u8 = 241;
/// Subnegotiation End (240 / `0xF0`).
pub const SE: u8 = 240;
/// End of Record (239 / `0xEF`, RFC 885).
pub const EOR: u8 = 239;

// Telnet Options
/// RFC 856: 8-bit Binary Transmission (Option 0).
pub const TELOPT_BINARY: u8 = 0;
/// RFC 857: Echo (Option 1).
pub const TELOPT_ECHO: u8 = 1;
/// RFC 858: Suppress Go Ahead (Option 3).
pub const TELOPT_SGA: u8 = 3;
/// RFC 860: Timing Mark (Option 6).
pub const TELOPT_TM: u8 = 6;
/// RFC 1091: Terminal Type (Option 24).
pub const TELOPT_TTYPE: u8 = 24;
/// RFC 885: End of Record (Option 25).
pub const TELOPT_EOR: u8 = 25;
/// RFC 2355: TN3270 Enhancements (Option 40).
pub const TELOPT_TN3270E: u8 = 40;

// Telnet Subnegotiation Qualifiers
/// Subnegotiation qualifier: IS (0).
pub const TELQUAL_IS: u8 = 0;
/// Subnegotiation qualifier: SEND (1).
pub const TELQUAL_SEND: u8 = 1;

/// Represents standard Telnet options negotiated during session establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TelnetOption {
    /// 8-bit Binary Transmission (RFC 856).
    Binary,
    /// Echo (RFC 857).
    Echo,
    /// Suppress Go Ahead (RFC 858).
    SuppressGoAhead,
    /// Timing Mark (RFC 860).
    TimingMark,
    /// Terminal Type (RFC 1091).
    TerminalType,
    /// End of Record (RFC 885).
    EndOfRecord,
    /// TN3270 Enhancements (RFC 2355).
    Tn3270e,
    /// Any other Telnet option code.
    Other(u8),
}

impl TelnetOption {
    /// Maps a raw byte code to a [`TelnetOption`].
    #[must_use]
    pub const fn from_u8(opt: u8) -> Self {
        match opt {
            TELOPT_BINARY => Self::Binary,
            TELOPT_ECHO => Self::Echo,
            TELOPT_SGA => Self::SuppressGoAhead,
            TELOPT_TM => Self::TimingMark,
            TELOPT_TTYPE => Self::TerminalType,
            TELOPT_EOR => Self::EndOfRecord,
            TELOPT_TN3270E => Self::Tn3270e,
            other => Self::Other(other),
        }
    }

    /// Converts this [`TelnetOption`] to its raw byte code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Binary => TELOPT_BINARY,
            Self::Echo => TELOPT_ECHO,
            Self::SuppressGoAhead => TELOPT_SGA,
            Self::TimingMark => TELOPT_TM,
            Self::TerminalType => TELOPT_TTYPE,
            Self::EndOfRecord => TELOPT_EOR,
            Self::Tn3270e => TELOPT_TN3270E,
            Self::Other(other) => other,
        }
    }
}

/// Formats a 3-byte negotiation sequence `[IAC, WILL, opt]`.
#[inline]
#[must_use]
pub const fn format_will(opt: u8) -> [u8; 3] {
    [IAC, WILL, opt]
}

/// Formats a 3-byte negotiation sequence `[IAC, WONT, opt]`.
#[inline]
#[must_use]
pub const fn format_wont(opt: u8) -> [u8; 3] {
    [IAC, WONT, opt]
}

/// Formats a 3-byte negotiation sequence `[IAC, DO, opt]`.
#[inline]
#[must_use]
pub const fn format_do(opt: u8) -> [u8; 3] {
    [IAC, DO, opt]
}

/// Formats a 3-byte negotiation sequence `[IAC, DONT, opt]`.
#[inline]
#[must_use]
pub const fn format_dont(opt: u8) -> [u8; 3] {
    [IAC, DONT, opt]
}

/// Doubles every `0xFF` (`IAC`) byte in `data` to ensure wire escaping.
#[must_use]
pub fn escape_iac(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().saturating_add(8));
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_helpers() {
        assert_eq!(format_will(TELOPT_BINARY), [255, 251, 0]);
        assert_eq!(format_wont(TELOPT_EOR), [255, 252, 25]);
        assert_eq!(format_do(TELOPT_TN3270E), [255, 253, 40]);
        assert_eq!(format_dont(TELOPT_TTYPE), [255, 254, 24]);
    }

    #[test]
    fn test_escape_iac() {
        let raw = [0x01, 0xFF, 0x02, 0xFF, 0x03];
        let escaped = escape_iac(&raw);
        assert_eq!(escaped, vec![0x01, 0xFF, 0xFF, 0x02, 0xFF, 0xFF, 0x03]);
    }
}
