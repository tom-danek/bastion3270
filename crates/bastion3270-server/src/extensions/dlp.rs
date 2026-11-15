//! Extension point **C — [`DlpPolicy`]** (Data Loss Prevention).
//!
//! Default implementation: [`StaticDlpPolicy`] — per-profile `allow_paste` / `allow_copy`
//! switches from TOML.
//!
//! **Enforcement model:**
//! * *Paste* is checked on the server: pasted text arrives as a `text` WebSocket message and
//!   is rejected before it reaches the session. This covers the browser's paste path, not
//!   typing: a script in the user's own browser can send the same text as single `key`
//!   messages (bounded only by the message rate limit). Paste DLP prevents accidental and
//!   casual transfer, it does not stop a user who controls their browser.
//! * *Copy* is advisory: the server tells the web client per screen whether copying is allowed.
//!   A determined user can still photograph the screen — DLP for copy reduces accidental
//!   exfiltration, it is not a cryptographic guarantee.

use bastion3270_core::SafeScreenView;

use crate::config::GatewayProfile;
use crate::extensions::auth::SessionIdentity;

/// Context available to a DLP decision.
#[derive(Debug, Clone, Copy)]
pub struct DlpContext<'a> {
    /// Who is acting.
    pub identity: &'a SessionIdentity,
    /// Which profile the session belongs to.
    pub profile: &'a GatewayProfile,
}

/// Result of a DLP check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlpDecision {
    /// Operation permitted.
    Allow,
    /// Operation refused; `reason` is shown to the user and audited.
    Deny {
        /// Human-readable reason.
        reason: String,
    },
}

/// Extension trait for clipboard / data-transfer policies.
///
/// Synchronous on purpose: evaluated on every screen update, must be cheap.
pub trait DlpPolicy: Send + Sync + core::fmt::Debug + 'static {
    /// May `text` be pasted (typed) into the session?
    fn check_paste(&self, ctx: &DlpContext<'_>, text: &str) -> DlpDecision;

    /// May the web client offer copying of this (already masked) screen?
    fn copy_allowed(&self, ctx: &DlpContext<'_>, screen: &SafeScreenView) -> bool;
}

/// Default policy: static switches from the profile configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticDlpPolicy;

impl DlpPolicy for StaticDlpPolicy {
    fn check_paste(&self, ctx: &DlpContext<'_>, _text: &str) -> DlpDecision {
        if ctx.profile.allow_paste {
            DlpDecision::Allow
        } else {
            DlpDecision::Deny {
                reason: format!("paste is disabled for profile '{}'", ctx.profile.id),
            }
        }
    }

    fn copy_allowed(&self, ctx: &DlpContext<'_>, _screen: &SafeScreenView) -> bool {
        ctx.profile.allow_copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_policy_follows_profile_switches() {
        let id = SessionIdentity::anonymous();
        let mut profile = GatewayProfile {
            id: "p".into(),
            name: "p".into(),
            description: String::new(),
            allow_paste: true,
            allow_copy: false,
            keyboard: crate::config::KeyboardPreset::default(),
            allowed_lu_names: None,
            custom: false,
            connection: bastion3270_net::ConnectionProfile::default(),
        };
        let view = SafeScreenView::empty(1, 1);
        let p = StaticDlpPolicy;
        {
            let ctx = DlpContext {
                identity: &id,
                profile: &profile,
            };
            assert_eq!(p.check_paste(&ctx, "x"), DlpDecision::Allow);
            assert!(!p.copy_allowed(&ctx, &view));
        }
        profile.allow_paste = false;
        let ctx = DlpContext {
            identity: &id,
            profile: &profile,
        };
        assert!(matches!(p.check_paste(&ctx, "x"), DlpDecision::Deny { .. }));
    }
}
