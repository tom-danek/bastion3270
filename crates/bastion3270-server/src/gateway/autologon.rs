//! Executes a [`MainframeAutoLogon`] script inside the gateway.
//!
//! The script is produced by an [`AuthProvider`](crate::AuthProvider) (e.g. RACF
//! `PassTicket`). It runs server-side, so the credential never reaches the browser, and the
//! typed characters land in a `Non-display` password field, which `SafeScreenView` masks.

use std::time::Duration;

use bastion3270_net::SessionHandle;
use tokio::sync::watch;

use crate::extensions::auth::{LogonStep, MainframeAutoLogon};
use crate::gateway::session::Snapshot;

/// Maximum time to wait for one screen condition (first screen, keyboard unlock).
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Waits until `pred` holds for the latest snapshot. Returns the snapshot `seq`.
async fn wait_for<F>(rx: &mut watch::Receiver<Snapshot>, pred: F) -> Option<u64>
where
    F: Fn(&Snapshot) -> bool,
{
    let fut = async {
        loop {
            {
                let snap = rx.borrow_and_update();
                if snap.state.is_terminal() {
                    return None;
                }
                if pred(&snap) {
                    return Some(snap.seq);
                }
            }
            rx.changed().await.ok()?;
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, fut).await.ok().flatten()
}

/// Runs the script. Returns `true` if every step completed.
pub(crate) async fn run(
    handle: SessionHandle,
    mut rx: watch::Receiver<Snapshot>,
    logon: MainframeAutoLogon,
) -> bool {
    // 1. First formatted screen with an unlocked keyboard (e.g. TSO / VTAM logon panel).
    let Some(mut last_seq) = wait_for(&mut rx, |s| {
        s.state.is_connected() && s.view.is_formatted() && !s.keyboard.is_locked()
    })
    .await
    else {
        return false;
    };

    for step in logon.steps {
        let ok = match step {
            // Only into a password field: if the panel is not what the script expects, the
            // secret is not typed into a visible field (where the browser would see it).
            LogonStep::Text(secret) => handle.send_secret(secret.expose()).await.is_ok(),
            LogonStep::Action(action) => handle.send_action(action).await.is_ok(),
            LogonStep::Aid(aid) => {
                last_seq = rx.borrow().seq;
                handle.press_aid(aid).await.is_ok()
            }
            LogonStep::WaitForUnlock => {
                // A *newer* snapshot than the AID, with the keyboard unlocked again.
                let after = last_seq;
                wait_for(&mut rx, |s| s.seq > after && !s.keyboard.is_locked())
                    .await
                    .is_some()
            }
        };
        if !ok {
            return false;
        }
    }
    true
}
