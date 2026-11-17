//! Drives a real browser over WebDriver (W3C) for the web client tests.
//!
//! The browser is chosen with `BASTION3270_WEBDRIVER` (`chrome` — the default —, `firefox` or
//! `edge`) and reached at `BASTION3270_WEBDRIVER_URL` (default: chromedriver / msedgedriver on
//! `http://127.0.0.1:9515`, geckodriver on `http://127.0.0.1:4444`). The WebDriver server has to
//! be started beforehand; see `docs/DEVELOPMENT.md`.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures_util::FutureExt;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thirtyfour::prelude::*;

/// How long [`wait_until`] waits before failing the test.
pub const WAIT: Duration = Duration::from_secs(10);

/// The browsers the tests run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Firefox,
    Edge,
}

impl Browser {
    /// The browser named by `BASTION3270_WEBDRIVER`.
    pub fn selected() -> Self {
        match std::env::var("BASTION3270_WEBDRIVER").as_deref() {
            Ok("firefox") => Self::Firefox,
            Ok("edge") => Self::Edge,
            Ok("chrome") | Err(_) => Self::Chrome,
            Ok(other) => panic!("BASTION3270_WEBDRIVER={other}: use chrome, firefox or edge"),
        }
    }

    fn default_url(self) -> &'static str {
        match self {
            Self::Chrome | Self::Edge => "http://127.0.0.1:9515",
            Self::Firefox => "http://127.0.0.1:4444",
        }
    }
}

/// Opens a headless browser session with a fixed window size (the canvas must fit).
async fn open_session() -> WebDriver {
    let browser = Browser::selected();
    let url = std::env::var("BASTION3270_WEBDRIVER_URL")
        .unwrap_or_else(|_| browser.default_url().to_owned());
    let result = match browser {
        Browser::Chrome => {
            let mut caps = DesiredCapabilities::chrome();
            for arg in ["--headless=new", "--window-size=1280,900", "--disable-gpu"] {
                caps.add_arg(arg).unwrap();
            }
            WebDriver::new(&url, caps).await
        }
        Browser::Edge => {
            let mut caps = DesiredCapabilities::edge();
            for arg in ["--headless=new", "--window-size=1280,900", "--disable-gpu"] {
                caps.add_arg(arg).unwrap();
            }
            WebDriver::new(&url, caps).await
        }
        Browser::Firefox => {
            let mut caps = DesiredCapabilities::firefox();
            for arg in ["-headless", "--width=1280", "--height=900"] {
                caps.add_arg(arg).unwrap();
            }
            WebDriver::new(&url, caps).await
        }
    };
    result.unwrap_or_else(|e| {
        panic!("cannot start a {browser:?} session via the WebDriver server at {url}: {e}")
    })
}

/// geckodriver serves one session at a time, while `cargo test` runs tests in parallel; Firefox
/// sessions of this process therefore take turns. (A `tokio` mutex works across the separate
/// runtimes of the `#[tokio::test]` functions.)
static ONE_FIREFOX_SESSION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Runs `body` with a fresh browser session and always closes the session afterwards, also
/// when `body` panics (an assertion failed), so no headless browser is left running.
pub async fn with_browser<F, Fut>(body: F)
where
    F: FnOnce(WebDriver) -> Fut,
    Fut: Future<Output = ()>,
{
    let _turn = match Browser::selected() {
        Browser::Firefox => Some(ONE_FIREFOX_SESSION.lock().await),
        Browser::Chrome | Browser::Edge => None,
    };
    let driver = open_session().await;
    let outcome = AssertUnwindSafe(body(driver.clone())).catch_unwind().await;
    let _ = driver.quit().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// Runs `script` in the page (`arguments[0..]` = `args`) and converts its return value.
pub async fn js<T: DeserializeOwned>(driver: &WebDriver, script: &str, args: Vec<Value>) -> T {
    driver
        .execute(script, args)
        .await
        .unwrap_or_else(|e| panic!("script failed: {e}\n{script}"))
        .convert()
        .unwrap()
}

/// A Chrome DevTools Protocol command sent through the driver's vendor endpoint
/// `/session/{id}/{vendor}/cdp/execute`. chromedriver serves it under `goog`, msedgedriver
/// under `ms`; `WebDriver::cdp` of thirtyfour knows only `goog`, so Edge answers it with
/// "unknown command".
#[derive(Debug)]
struct DevToolsCommand {
    vendor: &'static str,
    method: String,
    params: Value,
}

impl thirtyfour::common::command::FormatRequestData for DevToolsCommand {
    fn format_request(&self, session_id: &thirtyfour::SessionId) -> thirtyfour::RequestData {
        thirtyfour::RequestData::new(
            axum::http::Method::POST,
            format!("/session/{session_id}/{}/cdp/execute", self.vendor),
        )
        .add_body(serde_json::json!({ "cmd": self.method, "params": self.params }))
    }
}

/// Runs the DevTools command `method` with `params` in Chrome or Edge and returns its result.
/// Firefox has no DevTools endpoint; callers skip it.
pub async fn devtools(driver: &WebDriver, method: &str, params: Value) -> Value {
    let vendor = match Browser::selected() {
        Browser::Chrome => "goog",
        Browser::Edge => "ms",
        Browser::Firefox => panic!("Firefox has no DevTools endpoint"),
    };
    let command = DevToolsCommand {
        vendor,
        method: method.to_owned(),
        params,
    };
    driver
        .cmd(command)
        .await
        .and_then(thirtyfour::session::http::CmdResponse::value_json)
        .unwrap_or_else(|e| panic!("DevTools {method} failed: {e}"))
}

/// Imports the page module `module` (e.g. `/keymap.js`) in the browser and returns
/// `body(m)`, where `body` is the source of a JavaScript function taking the module object.
/// The module therefore runs in the real browser, exactly as the client loads it.
pub async fn with_module(driver: &WebDriver, module: &str, body: &str) -> Value {
    let script = format!(
        "const done = arguments[arguments.length - 1];\n\
         import(arguments[0])\n\
           .then((m) => done({{ ok: ({body})(m) }}))\n\
           .catch((e) => done({{ error: String(e) + '\\n' + (e && e.stack) }}));"
    );
    let ret = driver
        .execute_async(&script, vec![Value::from(module)])
        .await
        .unwrap();
    let value = ret.json().clone();
    if let Some(error) = value.get("error") {
        panic!("{module}: {error}");
    }
    value["ok"].clone()
}

/// Polls `probe` (a script returning a value or `null`) until it returns non-null, and returns
/// that value. Panics with `what` after [`WAIT`].
pub async fn wait_until(driver: &WebDriver, what: &str, probe: &str) -> Value {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let value: Value = js(driver, probe, vec![]).await;
        if !value.is_null() {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The text the client would put on the clipboard for a copy (the selection, or the whole
/// screen), obtained by dispatching a real `copy` event, or `None` when the client refused
/// (copy disabled by policy).
///
/// The text is read from the event's own `clipboardData`: Firefox gives the event a copy of the
/// `DataTransfer` passed to the constructor, Chromium the same object.
pub async fn copy_text(driver: &WebDriver) -> Option<String> {
    js(
        driver,
        "const canvas = document.getElementById('screen');\n\
         canvas.focus();\n\
         const event = new ClipboardEvent('copy',\n\
           { clipboardData: new DataTransfer(), bubbles: true, cancelable: true });\n\
         document.dispatchEvent(event);\n\
         const data = event.clipboardData;\n\
         return data.types.includes('text/plain') ? data.getData('text/plain') : null;",
        vec![],
    )
    .await
}

/// Focuses the terminal canvas (without clicking: a click moves the 3270 cursor).
pub async fn focus_terminal(driver: &WebDriver) {
    let () = js(
        driver,
        "document.getElementById('screen').focus(); return null;",
        vec![],
    )
    .await;
}

/// Offset of the centre of screen cell `(row, col)` from the centre of the canvas, in CSS
/// pixels (the origin W3C pointer actions use for an element).
pub async fn cell_offset(
    driver: &WebDriver,
    row: u16,
    col: u16,
    rows: u16,
    cols: u16,
) -> (i64, i64) {
    let [x, y]: [f64; 2] = js(
        driver,
        "const r = document.getElementById('screen').getBoundingClientRect();\n\
         const [row, col, rows, cols] = arguments;\n\
         const w = r.width / cols, h = r.height / rows;\n\
         return [(col + 0.5) * w - r.width / 2, (row + 0.5) * h - r.height / 2];",
        vec![row.into(), col.into(), rows.into(), cols.into()],
    )
    .await;
    #[allow(clippy::cast_possible_truncation)]
    (x.round() as i64, y.round() as i64)
}
