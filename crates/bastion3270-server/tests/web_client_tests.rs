//! Tests of the web client (`web/*.js`) in real browsers over WebDriver.
//!
//! Each test runs the real gateway and a scripted mock TN3270E host in this process and drives
//! the browser against the gateway, so assertions cover the whole path: browser key → WebSocket
//! → gateway → bytes at the host, and host screen → `SafeScreenView` → canvas / OIA / clipboard.
//! The pure client modules (`keymap.js`, `screen.js`) are imported and called in the browser.
//!
//! The tests need a WebDriver server and are ignored by default:
//!
//! ```text
//! chromedriver --port=9515 &      # or: geckodriver --port 4444 & with BASTION3270_WEBDRIVER=firefox
//! cargo test -p bastion3270-server --test web_client_tests -- --ignored
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use std::sync::LazyLock;

use bastion3270_core::address::BufferAddress;
use bastion3270_server::ServerConfig;
use common::browser::{
    cell_offset, copy_text, focus_terminal, js, wait_until, with_browser, with_module, Browser,
};
use common::gateway::{start, Running};
use common::mock_host::{self, aid_of, host_receives_aid, MockHost};
use serde_json::{json, Value};
use thirtyfour::prelude::*;

const ROWS: u16 = 24;
const COLS: u16 = 80;

// ─── Host screens ───────────────────────────────────────────────────────────────────

const SF: u8 = 0x1D;
const SFE: u8 = 0x29;
const SBA: u8 = 0x11;
const IC: u8 = 0x13;
/// Field attribute bytes (with the graphic bits of the code table).
const FA_PROTECTED: u8 = 0x60;
const FA_UNPROTECTED: u8 = 0x40;
const FA_NON_DISPLAY: u8 = 0x4C;
const FA_SKIP: u8 = 0xF0;
const AID_ENTER: u8 = 0x7D;
const AID_PF3: u8 = 0xF3;
const AID_PF8: u8 = 0xF8;
const AID_PF13: u8 = 0xC1;
const AID_CLEAR: u8 = 0x6D;
/// WebDriver's Right Control key (W3C WebDriver, keyboard actions: `"\u{E051}"`).
const RIGHT_CTRL: &str = "\u{E051}";

fn sba(row: u16, col: u16) -> [u8; 3] {
    let [a, b] = BufferAddress::new(usize::from(row * COLS + col), usize::from(ROWS * COLS))
        .unwrap()
        .encode_12bit()
        .unwrap();
    [SBA, a, b]
}

fn ebcdic(text: &str) -> Vec<u8> {
    use bastion3270_core::ebcdic::{CodePage, CP037};
    text.chars()
        .map(|c| CP037.char_to_ebcdic(c).unwrap())
        .collect()
}

/// TN3270E 3270-DATA header + Erase/Write (restore keyboard) + `orders` + `IAC EOR`.
fn record(orders: &[u8]) -> Vec<u8> {
    let mut r = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xC3];
    r.extend_from_slice(orders);
    r.extend_from_slice(&[0xFF, 0xEF]);
    r
}

/// Row 0: `USERID:` and an 8-position input field (cursor in it); row 1: `PASSWORD:` and an
/// 8-position **non-display** field; row 2: `RED TEXT` in a protected red field (SFE).
static LOGON: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut o = vec![SF, FA_PROTECTED];
    o.extend(ebcdic("USERID:"));
    o.extend(sba(0, 9));
    o.extend([SF, FA_UNPROTECTED, IC]);
    o.extend(sba(0, 18));
    o.extend([SF, FA_SKIP]);
    o.extend(sba(1, 0));
    o.extend([SF, FA_PROTECTED]);
    o.extend(ebcdic("PASSWORD:"));
    o.extend(sba(1, 10));
    o.extend([SF, FA_NON_DISPLAY]);
    o.extend(sba(1, 19));
    o.extend([SF, FA_SKIP]);
    o.extend(sba(2, 0));
    o.extend([SFE, 2, 0xC0, FA_PROTECTED, 0x42, 0xF2]); // 3270 attribute + foreground red
    o.extend(ebcdic("RED TEXT"));
    o.extend([SF, FA_SKIP]);
    record(&o)
});

/// Enter → `WELCOME <first modified field>`; any other AID → the logon screen again (which
/// also restores the keyboard).
fn reply(read: &[u8]) -> Option<Vec<u8>> {
    let aid = aid_of(read)?;
    if aid != AID_ENTER {
        return Some(LOGON.clone());
    }
    // Read Modified: header(5) AID cursor(2) then SBA a1 a2 data ... per modified field.
    let fields = read.get(8..)?;
    let user: Vec<u8> = fields
        .split(|b| *b == SBA)
        .find(|f| f.len() > 2)
        .map_or_default(|f| f[2..].iter().copied().take_while(|b| *b != 0xFF).collect());
    let mut o = vec![SF, FA_PROTECTED];
    o.extend(ebcdic("WELCOME "));
    o.extend(user);
    Some(record(&o))
}

// ─── Fixture ────────────────────────────────────────────────────────────────────────

struct Fixture {
    gateway: Running,
    host: MockHost,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with("").await
    }

    /// Like [`Fixture::start`], with `extra` TOML (e.g. an `[auth]` section) in the config.
    async fn start_with(extra: &str) -> Self {
        let host = mock_host::spawn(LOGON.as_slice(), reply).await;
        let cfg = ServerConfig::from_toml_str(&format!(
            r#"
            {extra}

            [[profiles]]
            id = "host"
            name = "Mock host"
            [profiles.connection]
            tls_mode = "disabled"
            host = "127.0.0.1"
            port = {port}
            terminal_model = "Model2"
            idle_timeout_ms = 600000

            [[profiles]]
            id = "pcomm"
            name = "PCOMM host"
            keyboard = "pcomm"
            [profiles.connection]
            tls_mode = "disabled"
            host = "127.0.0.1"
            port = {port}
            terminal_model = "Model2"
            idle_timeout_ms = 600000

            [[profiles]]
            id = "nocopy"
            name = "No copy"
            allow_copy = false
            [profiles.connection]
            tls_mode = "disabled"
            host = "127.0.0.1"
            port = {port}
            terminal_model = "Model2"
            idle_timeout_ms = 600000
            "#,
            port = host.port
        ))
        .unwrap();
        let gateway = start(cfg, |ext| ext).await;
        Self { gateway, host }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.gateway.addr)
    }

    /// Loads the client, picks `profile` and waits until the first screen is shown.
    async fn open(&self, driver: &WebDriver, profile: &str) {
        driver.goto(self.url()).await.unwrap();
        self.open_from_picker(driver, profile).await;
    }

    /// Picks `profile` in the profile picker shown by the page and waits for the first screen.
    async fn open_from_picker(&self, driver: &WebDriver, profile: &str) {
        let name = match profile {
            "host" => "Mock host",
            "nocopy" => "No copy",
            "pcomm" => "PCOMM host",
            other => panic!("unknown profile {other}"),
        };
        let button = wait_until(
            driver,
            "the profile picker",
            "const b = [...document.querySelectorAll('#profiles button')]\n\
               .find((b) => b.firstChild && b.firstChild.textContent === arguments[0]);\n\
             return b ? true : null;"
                .replace("arguments[0]", &format!("{name:?}"))
                .as_str(),
        )
        .await;
        assert_eq!(button, json!(true));
        driver
            .find(By::XPath(format!(
                "//ul[@id='profiles']//button[starts-with(normalize-space(.), '{name}')]"
            )))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_first_host_screen(driver).await;
    }
}

/// Probe for the message line: its text while it is shown, else `null`.
const MESSAGE: &str = "const m = document.getElementById('message'); \
     return m.hidden ? null : document.getElementById('message-text').textContent;";

/// Waits until the message line contains `needle` and returns its text.
async fn wait_for_message(driver: &WebDriver, needle: &str) -> String {
    let probe = format!(
        "const m = document.getElementById('message'); \
         const t = document.getElementById('message-text').textContent; \
         return !m.hidden && t.includes({needle:?}) ? t : null;"
    );
    wait_until(driver, &format!("message {needle:?}"), &probe)
        .await
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// A TCP forwarder between the browser and the gateway whose connections can all be cut at
/// once, as a dropped Wi-Fi or a sleeping laptop does.
struct Severable {
    addr: std::net::SocketAddr,
    links: std::sync::Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Severable {
    async fn start(target: std::net::SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let links = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let registry = std::sync::Arc::clone(&links);
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let link = tokio::spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                registry.lock().unwrap().push(link);
            }
        });
        Self { addr, links }
    }

    /// Drops every forwarded connection (both sockets are closed).
    fn sever(&self) {
        for link in self.links.lock().unwrap().drain(..) {
            link.abort();
        }
    }
}

/// Waits until the screen text (as the client copies it) contains `needle`.
async fn wait_for_screen_text(driver: &WebDriver, needle: &str) {
    let deadline = tokio::time::Instant::now() + common::browser::WAIT;
    loop {
        if copy_text(driver).await.is_some_and(|t| t.contains(needle)) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "screen never showed {needle:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The OIA line (raw text; WebDriver's rendered text could collapse its spacing).
async fn oia(driver: &WebDriver) -> String {
    js(
        driver,
        "return document.getElementById('oia').textContent;",
        vec![],
    )
    .await
}

/// Waits until the session is bound and the host's first screen is rendered.
///
/// The session state (LU name) reaches the page before the host's first write; until then the
/// keyboard is locked with `X [Field]` and the screen is empty. (A copy cannot be used to wait:
/// it may be disabled by the profile.)
async fn wait_for_first_host_screen(driver: &WebDriver) {
    wait_until(
        driver,
        "the first host screen",
        "const t = document.getElementById('oia').textContent;\n\
         const shown = !document.getElementById('terminal').hidden;\n\
         return shown && t.includes('LU LUTEST01') && !t.includes('X [Field]') ? t : null;",
    )
    .await;
}

/// Waits until the OIA contains `needle`.
async fn wait_for_oia(driver: &WebDriver, needle: &str) {
    let probe = format!(
        "const t = document.getElementById('oia').textContent;\n\
         return t.includes({needle:?}) ? t : null;"
    );
    wait_until(driver, &format!("OIA {needle:?}"), &probe).await;
}

/// RGBA of the canvas pixel at the centre of screen cell `(row, col)`.
async fn pixel(driver: &WebDriver, row: u16, col: u16) -> [u8; 4] {
    js(
        driver,
        "const c = document.getElementById('screen');\n\
         const [row, col, rows, cols] = arguments;\n\
         const w = c.width / cols, h = c.height / rows;\n\
         const d = c.getContext('2d').getImageData(\n\
           Math.floor((col + 0.5) * w), Math.floor((row + 0.5) * h), 1, 1).data;\n\
         return [d[0], d[1], d[2], d[3]];",
        vec![row.into(), col.into(), ROWS.into(), COLS.into()],
    )
    .await
}

/// `true` if any pixel inside screen cell `(row, col)` satisfies the RGB predicate source
/// `test` (a JavaScript expression over `r`, `g`, `b`).
async fn cell_has_pixel(driver: &WebDriver, row: u16, col: u16, test: &str) -> bool {
    let script = format!(
        "const c = document.getElementById('screen');\n\
         const [row, col, rows, cols] = arguments;\n\
         const w = Math.floor(c.width / cols), h = Math.floor(c.height / rows);\n\
         const d = c.getContext('2d').getImageData(col * w, row * h, w, h).data;\n\
         for (let i = 0; i < d.length; i += 4) {{\n\
           const r = d[i], g = d[i + 1], b = d[i + 2];\n\
           if ({test}) return true;\n\
         }}\n\
         return false;"
    );
    js(
        driver,
        &script,
        vec![row.into(), col.into(), ROWS.into(), COLS.into()],
    )
    .await
}

// ─── Pure modules, run in the browser ───────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn keymap_module_maps_keys_like_wc3270() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        let cases: Vec<(Value, Value)> = vec![
            (
                json!({"key": "Enter"}),
                json!({"type": "aid", "aid": "enter"}),
            ),
            (
                json!({"key": "Enter", "shiftKey": true}),
                json!({"type": "action", "action": "newline"}),
            ),
            (
                json!({"key": "Enter", "ctrlKey": true}),
                json!({"type": "action", "action": "newline"}),
            ),
            (
                json!({"key": "Tab"}),
                json!({"type": "action", "action": "tab"}),
            ),
            (
                json!({"key": "Tab", "shiftKey": true}),
                json!({"type": "action", "action": "backtab"}),
            ),
            (
                json!({"key": "End"}),
                json!({"type": "action", "action": "field_end"}),
            ),
            (
                json!({"key": "End", "shiftKey": true}),
                json!({"type": "action", "action": "erase_eof"}),
            ),
            (
                json!({"key": "Insert"}),
                json!({"type": "action", "action": "toggle_insert"}),
            ),
            (
                json!({"key": "Escape"}),
                json!({"type": "action", "action": "reset"}),
            ),
            (
                json!({"key": "Home"}),
                json!({"type": "action", "action": "home"}),
            ),
            (
                json!({"key": "Backspace"}),
                json!({"type": "action", "action": "backspace"}),
            ),
            (
                json!({"key": "Delete"}),
                json!({"type": "action", "action": "delete"}),
            ),
            (
                json!({"key": "ArrowLeft"}),
                json!({"type": "action", "action": "left"}),
            ),
            (
                json!({"key": "ArrowDown"}),
                json!({"type": "action", "action": "down"}),
            ),
            (json!({"key": "F1"}), json!({"type": "aid", "aid": "pf1"})),
            (json!({"key": "F12"}), json!({"type": "aid", "aid": "pf12"})),
            (
                json!({"key": "F1", "shiftKey": true}),
                json!({"type": "aid", "aid": "pf13"}),
            ),
            (
                json!({"key": "F12", "shiftKey": true}),
                json!({"type": "aid", "aid": "pf24"}),
            ),
            (
                json!({"key": "PageUp"}),
                json!({"type": "aid", "aid": "pf7"}),
            ),
            (
                json!({"key": "PageDown"}),
                json!({"type": "aid", "aid": "pf8"}),
            ),
            (json!({"key": "a"}), json!({"type": "key", "ch": "a"})),
            (
                json!({"key": "Z", "shiftKey": true}),
                json!({"type": "key", "ch": "Z"}),
            ),
            (json!({"key": "é"}), json!({"type": "key", "ch": "é"})),
            (json!({"key": " "}), json!({"type": "key", "ch": " "})),
            // Shortcuts the browser handles, and keys the terminal does not use.
            (json!({"key": "c", "ctrlKey": true}), json!("browser")),
            (json!({"key": "v", "ctrlKey": true}), json!("browser")),
            (json!({"key": "a", "ctrlKey": true}), Value::Null),
            (json!({"key": "a", "altKey": true}), Value::Null),
            (json!({"key": "a", "metaKey": true}), Value::Null),
            (json!({"key": "F13"}), Value::Null),
            (json!({"key": "Shift"}), Value::Null),
            (json!({"key": "constructor"}), Value::Null),
        ];
        let events: Vec<Value> = cases.iter().map(|(e, _)| e.clone()).collect();
        let results = with_module(
            &driver,
            "/keymap.js",
            &format!(
                "(m) => {}.map((e) => m.keyToMessage(e))",
                Value::from(events)
            ),
        )
        .await;
        for ((event, expected), actual) in cases.iter().zip(results.as_array().unwrap()) {
            assert_eq!(actual, expected, "key event {event}");
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn screen_module_resolves_styles_selection_and_oia() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        let r = with_module(
            &driver,
            "/screen.js",
            r#"(m) => ({
                defaultProtected: m.runStyle({ fg: 0, bg: 0, hl: 0, f: 1 }),
                defaultUnprotected: m.runStyle({ fg: 0, bg: 0, hl: 0, f: 0 }),
                redOnBlue: m.runStyle({ fg: 0xf2, bg: 0xf1, hl: 0, f: 0 }),
                reverse: m.runStyle({ fg: 0xf2, bg: 0, hl: 2, f: 0 }),
                underline: m.runStyle({ fg: 0, bg: 0, hl: 4, f: 0 }).underline,
                unknownColour: m.colorOf(0x99, false),
                selection: m.selectionFrom({ row: 5, col: 9 }, { row: 2, col: 3 }),
                rectText: m.selectionText({ text: ["ab  cd  ", "efgh    ", "ij      "] },
                                          { r0: 0, r1: 1, c0: 1, c1: 4 }),
                wholeText: m.selectionText({ text: ["ab  ", "    ", "c   "] }, null),
                inside: m.cellAt(25, 45, { left: 5, top: 5 }, { w: 10, h: 20 }, 24, 80),
                beforeStart: m.cellAt(-50, -50, { left: 0, top: 0 }, { w: 10, h: 20 }, 24, 80),
                pastEnd: m.cellAt(5000, 5000, { left: 0, top: 0 }, { w: 10, h: 20 }, 24, 80),
                oiaConnected: m.oiaText({ state: "connected", tls: false, tn3270e: true,
                    mode: "3270", lu: "LUTEST01", insert: true, keyboard: "" },
                    { cursor: [0, 9] }),
                oiaSscp: m.oiaText({ state: "connected", tls: true, tn3270e: true,
                    mode: "sscp-lu", lu: null, insert: false, keyboard: "X SYSTEM" },
                    { cursor: [23, 79] }),
                oiaDown: m.oiaText({ state: "connecting", tls: false, tn3270e: false,
                    mode: "negotiating", insert: false, keyboard: "" }, { cursor: [0, 0] }),
                oiaGeometry: m.oiaText({ state: "connected", tls: true, tn3270e: true,
                    mode: "3270", insert: false, keyboard: "", model: "dynamic",
                    codepage: "cp1141" }, { rows: 62, cols: 160, cursor: [1, 2] }).cursor,
            })"#,
        )
        .await;
        assert_eq!(r["defaultProtected"], json!({"fg": "#5cb8ff", "bg": null, "underline": false}));
        assert_eq!(r["defaultUnprotected"]["fg"], json!("#2eeb5a"));
        assert_eq!(r["redOnBlue"], json!({"fg": "#ff4d4d", "bg": "#4299ff", "underline": false}));
        // Reverse video: the foreground becomes the background, the screen background the text.
        assert_eq!(r["reverse"], json!({"fg": "#0a0e14", "bg": "#ff4d4d", "underline": false}));
        assert_eq!(r["underline"], json!(true));
        assert_eq!(r["unknownColour"], json!("#2eeb5a"));
        assert_eq!(r["selection"], json!({"r0": 2, "r1": 5, "c0": 3, "c1": 9}));
        assert_eq!(r["rectText"], json!("b  c\nfgh"));
        assert_eq!(r["wholeText"], json!("ab\n\nc"));
        assert_eq!(r["inside"], json!({"row": 2, "col": 2}));
        assert_eq!(r["beforeStart"], json!({"row": 0, "col": 0}));
        assert_eq!(r["pastEnd"], json!({"row": 23, "col": 79}));
        assert_eq!(
            r["oiaConnected"],
            json!({"left": "4A  TCP  TN3270E  LU LUTEST01  INS  ", "lock": " ".repeat(14), "cursor": "  001/010"})
        );
        assert_eq!(
            r["oiaSscp"],
            json!({"left": "4A  TLS  TN3270E  SSCP-LU  ", "lock": "X SYSTEM      ", "cursor": "  024/080"})
        );
        assert_eq!(r["oiaDown"]["left"], json!("4-  TCP  TN3270  "));
        assert_eq!(r["oiaDown"]["lock"], json!("connecting    "));
        assert_eq!(r["oiaGeometry"], json!("  DYN 62×160  CP1141  002/003"));
    })
    .await;
}

// ─── End to end ─────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn renders_the_host_screen_with_colours_cursor_and_oia() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        wait_for_oia(&driver, "LU LUTEST01").await;
        let line = oia(&driver).await;
        assert!(
            line.starts_with("4A  TCP  TN3270E  LU LUTEST01"),
            "{line:?}"
        );
        assert!(
            line.ends_with("001/011"),
            "cursor after the input field attribute: {line:?}"
        );

        // The cursor cell is tinted with the cursor colour (cyan over the dark background).
        let [r, g, b, _] = pixel(&driver, 0, 10).await;
        assert!(g > 100 && b > 100 && r < 80, "cursor cell {r},{g},{b}");
        // An empty cell far from any text is the screen background.
        assert_eq!(pixel(&driver, 20, 60).await, [0x0a, 0x0e, 0x14, 0xff]);
        // `USERID:` is drawn in the protected default colour (blue-ish), `RED TEXT` in red.
        assert!(
            cell_has_pixel(&driver, 0, 1, "b > 180 && r < 140").await,
            "USERID text"
        );
        assert!(
            cell_has_pixel(&driver, 2, 1, "r > 180 && g < 120 && b < 120").await,
            "red text"
        );

        let text = copy_text(&driver).await.unwrap();
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(rows[0], " USERID:");
        assert_eq!(rows[1], " PASSWORD:");
        assert_eq!(rows[2], " RED TEXT");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn logon_reaches_the_host_and_the_password_never_reaches_the_page() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys("HERC01")
            .send_keys(Key::Tab)
            .send_keys("SECRET")
            .perform()
            .await
            .unwrap();
        // The typed password is masked everywhere in the page before it is sent.
        wait_for_oia(&driver, "002/018").await; // cursor after the 6th password character
        let screen = copy_text(&driver).await.unwrap();
        assert!(screen.contains("HERC01"), "{screen:?}");
        assert!(
            !screen.contains("SECRET"),
            "password on the screen: {screen:?}"
        );
        let page: String = js(
            &driver,
            "return document.documentElement.outerHTML + document.body.innerText;",
            vec![],
        )
        .await;
        assert!(!page.contains("SECRET"), "password in the page");

        driver
            .action_chain()
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        let read = host_receives_aid(&mut fx.host.received, AID_ENTER).await;
        let has = |needle: &[u8]| read.windows(needle.len()).any(|w| w == needle);
        assert!(has(&ebcdic("HERC01")), "user id at the host");
        assert!(has(&ebcdic("SECRET")), "password at the host");

        wait_for_screen_text(&driver, "WELCOME HERC01").await;
        let page: String = js(
            &driver,
            "return document.documentElement.outerHTML + document.body.innerText;",
            vec![],
        )
        .await;
        assert!(!page.contains("SECRET"), "password in the page after logon");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn function_and_editing_keys_reach_the_host() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        focus_terminal(&driver).await;

        for (key, aid) in [(Key::F3, AID_PF3), (Key::PageDown, AID_PF8)] {
            driver
                .action_chain()
                .send_keys(key)
                .perform()
                .await
                .unwrap();
            host_receives_aid(&mut fx.host.received, aid).await;
            wait_for_oia(&driver, "001/011").await; // the host restored the logon screen
        }
        driver
            .action_chain()
            .key_down(Key::Shift)
            .send_keys(Key::F1)
            .key_up(Key::Shift)
            .perform()
            .await
            .unwrap();
        host_receives_aid(&mut fx.host.received, AID_PF13).await;
        wait_for_oia(&driver, "001/011").await;

        // Insert toggles insert mode (shown in the OIA).
        driver
            .action_chain()
            .send_keys(Key::Insert)
            .perform()
            .await
            .unwrap();
        wait_for_oia(&driver, "INS").await;
        driver
            .action_chain()
            .send_keys(Key::Insert)
            .perform()
            .await
            .unwrap();
        wait_until(
            &driver,
            "insert mode off",
            "return document.getElementById('oia').textContent.includes('INS') ? null : true;",
        )
        .await;

        // Shift+End erases to the end of the field.
        driver
            .action_chain()
            .send_keys("ABC")
            .send_keys(Key::Home)
            .perform()
            .await
            .unwrap();
        wait_for_screen_text(&driver, "ABC").await;
        driver
            .action_chain()
            .key_down(Key::Shift)
            .send_keys(Key::End)
            .key_up(Key::Shift)
            .perform()
            .await
            .unwrap();
        wait_until(
            &driver,
            "the field to be erased",
            "return document.getElementById('oia').textContent.includes('001/011') ? true : null;",
        )
        .await;
        let deadline = tokio::time::Instant::now() + common::browser::WAIT;
        while copy_text(&driver).await.unwrap().contains("ABC") {
            assert!(
                tokio::time::Instant::now() < deadline,
                "Shift+End did not erase the field"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn drag_selects_a_rectangle_and_copy_respects_the_policy() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        let canvas = driver.find(By::Id("screen")).await.unwrap();
        // Drag from row 0 col 1 to row 1 col 6: "USERID" over "PASSWO".
        let (x0, y0) = cell_offset(&driver, 0, 1, ROWS, COLS).await;
        let (x1, y1) = cell_offset(&driver, 1, 6, ROWS, COLS).await;
        driver
            .action_chain()
            .move_to_element_with_offset(&canvas, x0, y0)
            .click_and_hold()
            .move_to_element_with_offset(&canvas, x1, y1)
            .release()
            .perform()
            .await
            .unwrap();
        assert_eq!(copy_text(&driver).await.unwrap(), "USERID\nPASSWO");
        // A drag is not a click: the cursor stayed in the input field.
        assert!(oia(&driver).await.ends_with("001/011"));

        // A plain click moves the cursor and drops the selection.
        let (x, y) = cell_offset(&driver, 3, 20, ROWS, COLS).await;
        driver
            .action_chain()
            .move_to_element_with_offset(&canvas, x, y)
            .click()
            .perform()
            .await
            .unwrap();
        wait_for_oia(&driver, "004/021").await;
        assert!(
            copy_text(&driver).await.unwrap().starts_with(" USERID:"),
            "whole screen"
        );

        // Disconnect returns to the picker; a profile without copy refuses it with a notice.
        driver
            .find(By::Id("btn-disconnect"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_until(
            &driver,
            "the profile picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        fx.open(&driver, "nocopy").await;
        assert_eq!(copy_text(&driver).await, None, "copy must be refused");
        let toast = wait_until(&driver, "the copy notice", MESSAGE).await;
        assert_eq!(toast, json!("Copying from this system is not allowed."));
    })
    .await;
}

/// Copy and paste through the real system clipboard with the real shortcuts (trusted
/// events): the selection `USERID` is copied with Ctrl+C and pasted into the input field with
/// Ctrl+V, then reaches the host.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn clipboard_copy_and_paste_with_the_keyboard_reach_the_host() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        let canvas = driver.find(By::Id("screen")).await.unwrap();
        let (x0, y0) = cell_offset(&driver, 0, 1, ROWS, COLS).await;
        let (x1, y1) = cell_offset(&driver, 0, 6, ROWS, COLS).await;
        driver
            .action_chain()
            .move_to_element_with_offset(&canvas, x0, y0)
            .click_and_hold()
            .move_to_element_with_offset(&canvas, x1, y1)
            .release()
            .key_down(Key::Control)
            .send_keys("c")
            .key_up(Key::Control)
            .perform()
            .await
            .unwrap();
        // The cursor is still in the input field (a drag does not move it): paste there.
        driver
            .action_chain()
            .key_down(Key::Control)
            .send_keys("v")
            .key_up(Key::Control)
            .perform()
            .await
            .unwrap();
        wait_for_screen_text(&driver, "USERID:  USERID").await;
        driver
            .action_chain()
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        let read = host_receives_aid(&mut fx.host.received, AID_ENTER).await;
        assert!(
            read.windows(6).any(|w| w == ebcdic("USERID")),
            "pasted text at the host"
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn reload_resumes_the_session_and_a_second_tab_takes_it_over() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys("HERC01")
            .perform()
            .await
            .unwrap();
        wait_for_screen_text(&driver, "HERC01").await;
        assert_eq!(fx.host.connection_count(), 1);

        // Reload: the client resumes the same session (same screen, no new host connection).
        driver.refresh().await.unwrap();
        wait_for_oia(&driver, "LU LUTEST01").await;
        wait_for_screen_text(&driver, "HERC01").await;
        assert_eq!(
            fx.host.connection_count(),
            1,
            "resume must not reconnect to the host"
        );

        // A second tab with the same resume data takes the session over.
        let saved: String = js(
            &driver,
            "return sessionStorage.getItem('bastion3270.sessions');",
            vec![],
        )
        .await;
        let first = driver.window().await.unwrap();
        let second = driver.new_tab().await.unwrap();
        driver.switch_to_window(second).await.unwrap();
        driver.goto(fx.url()).await.unwrap();
        let () = js(
            &driver,
            "sessionStorage.setItem('bastion3270.sessions', arguments[0]); return null;",
            vec![Value::from(saved)],
        )
        .await;
        driver.refresh().await.unwrap();
        wait_for_screen_text(&driver, "HERC01").await;
        assert_eq!(
            fx.host.connection_count(),
            1,
            "takeover must not reconnect to the host"
        );

        driver.switch_to_window(first).await.unwrap();
        let toast = wait_until(&driver, "the takeover notice", MESSAGE).await;
        assert_eq!(
            toast,
            json!("The session was opened in another browser tab.")
        );
    })
    .await;
}

/// Log out ends the session and forgets the bearer token and the resume data of the tab: the
/// next person at a shared workstation starts at the login screen, even after a reload.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn log_out_ends_the_session_and_forgets_the_credentials() {
    let digest = bastion3270_server::extensions::auth::encode_hex(
        &bastion3270_server::extensions::auth::sha256(b"web-token-1"),
    );
    let fx = Fixture::start_with(&format!(
        "[auth]\nmode = \"static-token\"\n[[auth.tokens]]\nsubject = \"op\"\nsha256 = \"{digest}\""
    ))
    .await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        wait_until(
            &driver,
            "the login screen",
            "return document.getElementById('login').hidden ? null : true;",
        )
        .await;
        let field = driver.find(By::Id("token")).await.unwrap();
        let submit = driver
            .find(By::Css("#login-form button[type=submit]"))
            .await
            .unwrap();
        // A token that cannot travel as a sub-protocol name is refused with a message.
        field.send_keys("web token").await.unwrap();
        submit.click().await.unwrap();
        let toast = wait_until(&driver, "the token message", MESSAGE).await;
        assert!(
            toast
                .as_str()
                .unwrap_or_default()
                .contains("cannot be sent"),
            "{toast}"
        );
        field.clear().await.unwrap();
        field.send_keys("web-token-1").await.unwrap();
        submit.click().await.unwrap();
        fx.open_from_picker(&driver, "host").await;

        driver
            .find(By::Id("btn-logout"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_until(
            &driver,
            "the login screen after log out",
            "return document.getElementById('login').hidden ? null : true;",
        )
        .await;
        let stored: Value = js(
            &driver,
            "return [sessionStorage.getItem('bastion3270.token'), \
                     sessionStorage.getItem('bastion3270.sessions')];",
            vec![],
        )
        .await;
        assert_eq!(stored, json!([null, null]));

        driver.refresh().await.unwrap();
        wait_until(
            &driver,
            "the login screen after a reload",
            "return document.getElementById('login').hidden ? null : true;",
        )
        .await;
    })
    .await;
}

/// The last screen may hold customer data: after Disconnect nothing of it stays on the canvas.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn disconnect_wipes_the_screen_from_the_page() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        wait_for_screen_text(&driver, "USERID:").await;
        let painted = "const c = document.getElementById('screen');\n\
             const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;\n\
             return d.some((v) => v !== 0);";
        let before: bool = js(&driver, painted, vec![]).await;
        assert!(before, "the screen is drawn while connected");

        driver
            .find(By::Id("btn-disconnect"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_until(
            &driver,
            "the profile picker after disconnect",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        let after: bool = js(&driver, painted, vec![]).await;
        assert!(!after, "no pixel of the last screen may remain");
        let oia: String = js(
            &driver,
            "return document.getElementById('oia').textContent;",
            vec![],
        )
        .await;
        assert_eq!(oia, "", "no status line of the ended session");
    })
    .await;
}

// ─── Messages, reconnect, language ─────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn i18n_and_status_modules_translate_and_plan_reconnects() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        let i18n = with_module(
            &driver,
            "/i18n.js",
            r#"(m) => ({
                complete: m.complete(),
                czech: m.pickLanguage(null, ["cs-CZ", "en-US"]),
                stored: m.pickLanguage("en", ["cs-CZ"]),
                unknown: m.pickLanguage("xx", ["de-DE"]),
                text: m.t("cs", "msg.reconnecting", { attempt: 3 }),
                fallback: m.t("cs", "no.such.key"),
            })"#,
        )
        .await;
        assert_eq!(
            i18n,
            json!({
                "complete": true, "czech": "cs", "stored": "en", "unknown": "en",
                "text": "Spojení se přerušilo. Připojuji znovu (pokus 3)…",
                "fallback": "no.such.key",
            })
        );
        let status = with_module(
            &driver,
            "/status.js",
            r#"(m) => ({
                delays: [1, 2, 3, 4, 5, 6].map((a) => m.reconnectDelay(a, 0, 300)),
                late: m.reconnectDelay(9, 299500, 300),
                shutdown: m.closedMessage("server_shutdown"),
                user: m.closedMessage("user"),
                gateway: ["idle", "lifetime", "identity_expired", "ended"]
                    .map((r) => m.closedMessage(r).key),
                odd: m.closedMessage("rate_limited_by_moon").key,
                connect: m.errorMessage("connect_failed", "x").level,
                paste: m.errorMessage("paste_too_long", "x").level,
                unknown: m.errorMessage("weird", "boom"),
            })"#,
        )
        .await;
        assert_eq!(
            status["delays"],
            json!([1000, 2000, 4000, 8000, 15000, 15000])
        );
        assert_eq!(status["late"], Value::Null);
        assert_eq!(status["shutdown"]["again"], json!(true));
        assert_eq!(
            status["user"],
            json!({"key": "closed.user", "params": {}, "level": "info", "again": false})
        );
        assert_eq!(status["odd"], json!("closed.other"));
        assert_eq!(
            status["gateway"],
            json!([
                "closed.idle",
                "closed.lifetime",
                "closed.identity_expired",
                "closed.ended"
            ]),
            "the gateway's own reasons have their own text"
        );
        assert_eq!(status["connect"], json!("error"));
        assert_eq!(status["paste"], json!("warn"));
        assert_eq!(status["unknown"]["params"]["message"], json!("boom"));
    })
    .await;
}

/// A lost connection (network drop) is resumed by the page on its own: the user sees
/// "reconnecting", then the same session (the host never saw a second connection).
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn a_lost_connection_is_resumed_without_the_user() {
    let fx = Fixture::start().await;
    let link = Severable::start(fx.gateway.addr).await;
    with_browser(|driver| async move {
        driver.goto(format!("http://{}/", link.addr)).await.unwrap();
        fx.open_from_picker(&driver, "host").await;
        wait_for_screen_text(&driver, "USERID").await;

        link.sever();
        wait_for_message(&driver, "Reconnecting").await;
        wait_for_message(&driver, "The connection is back.").await;
        wait_for_screen_text(&driver, "USERID").await;
        assert_eq!(
            fx.host.connection_count(),
            1,
            "the session survived the drop"
        );
    })
    .await;
}

/// A gateway restart ends the session with a plain-language reason and offers to connect
/// again with the same profile.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn a_gateway_restart_is_explained_and_offers_to_connect_again() {
    let mut fx = Fixture::start().await;
    let stop = fx.gateway.shutdown.take().unwrap();
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        stop.send(()).unwrap();
        wait_for_message(&driver, "The gateway was restarted").await;
        let again = js::<bool>(
            &driver,
            "return !document.getElementById('message-again').hidden;",
            vec![],
        )
        .await;
        assert!(again, "Connect again is offered");
        let leftover = js::<Value>(
            &driver,
            "return sessionStorage.getItem('bastion3270.sessions');",
            vec![],
        )
        .await;
        assert_eq!(leftover, Value::Null, "no resume data of an ended session");
    })
    .await;
}

/// The language can be switched at any time; static texts and the message on screen follow.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_language_can_be_switched_to_czech() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        wait_for_message(&driver, "Connected to Mock host").await;
        js::<Value>(
            &driver,
            "const s = document.getElementById('lang'); s.value = 'cs'; \
             s.dispatchEvent(new Event('change')); return null;",
            vec![],
        )
        .await;
        wait_for_message(&driver, "Připojeno k Mock host").await;
        let texts = js::<Value>(
            &driver,
            "return [document.documentElement.lang, \
                     document.getElementById('btn-disconnect').textContent, \
                     document.querySelector('#picker h2').textContent];",
            vec![],
        )
        .await;
        assert_eq!(texts, json!(["cs", "Odpojit", "Připojit k"]));
        let remembered = js::<Value>(
            &driver,
            "return localStorage.getItem('bastion3270.lang');",
            vec![],
        )
        .await;
        assert_eq!(remembered, json!("cs"));
    })
    .await;
}

// ─── Screen size: auto-fit, zoom ─────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn fit_cell_finds_the_largest_font_that_fits() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        let r = with_module(
            &driver,
            "/screen.js",
            r"(m) => {
                const mt = { w: 60, ascent: 75, descent: 20 };
                const fits = (c, W, H, rows, cols) => c.w * cols <= W && c.h * rows <= H;
                const a = m.fitCell(1000, 600, 24, 80, mt, 0);
                const next = { w: Math.ceil(0.6 * (a.font + 1)), h: Math.ceil(0.95 * (a.font + 1) * 1.2) };
                return {
                    fits: fits(a, 1000, 600, 24, 80),
                    largest: !fits(next, 1000, 600, 24, 80),
                    model5: fits(m.fitCell(1000, 600, 27, 132, mt, 0), 1000, 600, 27, 132),
                    tiny: m.fitCell(50, 50, 24, 80, mt, 0).font,
                    zoomed: m.fitCell(1000, 600, 24, 80, mt, 2).font > a.font,
                    clamped: m.fitCell(1000, 600, 24, 80, mt, 99).font
                        === m.fitCell(1000, 600, 24, 80, mt, m.MAX_ZOOM).font,
                    baseline: a.ascent > 0 && a.ascent < a.h,
                };
            }",
        )
        .await;
        assert_eq!(
            r,
            json!({"fits": true, "largest": true, "model5": true, "tiny": 8,
                   "zoomed": true, "clamped": true, "baseline": true})
        );
    })
    .await;
}

/// The screen fills the window and follows its size; Ctrl + / Ctrl - / Ctrl 0 zoom the
/// terminal (not the page) and the zoom is remembered.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_screen_fits_the_window_and_zooms() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.set_window_rect(0, 0, 900, 700).await.unwrap();
        fx.open(&driver, "host").await;
        let size = || async {
            js::<Value>(
                &driver,
                "const r = document.getElementById('screen').getBoundingClientRect(); \
                 return [Math.round(r.width), Math.round(r.height), Math.round(r.bottom), \
                         window.innerWidth, window.innerHeight];",
                vec![],
            )
            .await
        };
        let small = size().await;
        let [w, _, bottom, inner_w, inner_h] = [0, 1, 2, 3, 4].map(|i| small[i].as_i64().unwrap());
        assert!(
            w <= inner_w && bottom <= inner_h,
            "fits the window: {small}"
        );
        assert!(w > inner_w / 2, "uses the window: {small}");

        driver.set_window_rect(0, 0, 1400, 1000).await.unwrap();
        let wider = wait_until(
            &driver,
            "a larger screen after the resize",
            &format!(
                "const w = document.getElementById('screen').getBoundingClientRect().width; \
                 return w > {w} + 20 ? Math.round(w) : null;"
            ),
        )
        .await;
        assert!(wider.as_i64().unwrap() > w);

        let zoom = |key: &'static str| {
            let driver = &driver;
            async move {
                js::<Value>(
                    driver,
                    "const c = document.getElementById('screen'); c.focus(); \
                     c.dispatchEvent(new KeyboardEvent('keydown', \
                       { key: arguments[0], ctrlKey: true, bubbles: true, cancelable: true })); \
                     return Math.round(c.getBoundingClientRect().width);",
                    vec![Value::from(key)],
                )
                .await
                .as_i64()
                .unwrap()
            }
        };
        let fitted = zoom("0").await;
        let out = zoom("-").await;
        assert!(out < fitted, "Ctrl - shrinks: {out} < {fitted}");
        let stored = js::<Value>(
            &driver,
            "return localStorage.getItem('bastion3270.zoom');",
            vec![],
        )
        .await;
        assert_eq!(stored, json!("-1"));
        assert_eq!(zoom("0").await, fitted, "Ctrl 0 restores the fitted size");
    })
    .await;
}

/// The message line above the screen takes space without a window resize: when it goes the
/// screen grows into the space, and when it appears the screen shrinks again so the key bar
/// stays in the window (no page scroll).
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_screen_refits_when_the_message_line_appears_or_goes() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        // Wide and low: the height limits the screen, so the message line's space counts.
        driver.set_window_rect(0, 0, 1400, 700).await.unwrap();
        fx.open(&driver, "nocopy").await;
        // `[screen height, message shown]` once the whole page (key bar included) fits the
        // window, else `null`.
        let fitted = "const h = Math.round(document.getElementById('screen')\
               .getBoundingClientRect().height); \
             const k = document.getElementById('keybar').getBoundingClientRect(); \
             const page = document.documentElement; \
             const fits = k.bottom <= innerHeight && page.scrollHeight <= page.clientHeight; \
             return fits ? [h, !document.getElementById('message').hidden] : null;";
        let start = wait_until(&driver, "the page to fit with \"Connected\"", fitted).await;
        assert_eq!(
            start[1],
            json!(true),
            "the connect message is shown: {start}"
        );
        let with_message = start[0].as_i64().unwrap();

        let close = || async {
            driver
                .find(By::Id("message-close"))
                .await
                .unwrap()
                .click()
                .await
                .unwrap();
        };
        close().await;
        let grown = wait_until(
            &driver,
            "the screen to grow into the message line's space",
            &format!(
                "const v = (() => {{ {fitted} }})(); \
                 return v && !v[1] && v[0] > {with_message} ? v : null;"
            ),
        )
        .await;

        // A refused copy shows a warning, which stays until it is dismissed.
        assert_eq!(copy_text(&driver).await, None);
        wait_until(
            &driver,
            "the screen to shrink under the warning",
            &format!(
                "const v = (() => {{ {fitted} }})(); \
                 return v && v[1] && v[0] === {with_message} ? v : null;"
            ),
        )
        .await;
        close().await;
        wait_until(
            &driver,
            "the screen to grow again",
            &format!(
                "const v = (() => {{ {fitted} }})(); \
                 return v && !v[1] && v[0] === {} ? v : null;",
                grown[0]
            ),
        )
        .await;
    })
    .await;
}

// ─── Keyboard presets ───────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn keymap_module_maps_the_pcomm_layout() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        let r = with_module(
            &driver,
            "/keymap.js",
            r"(m) => {
                const k = (e) => m.keyToMessage(e, 'pcomm');
                return {
                    enter: k({ key: 'Enter', code: 'Enter' }),
                    numpadEnter: k({ key: 'Enter', code: 'NumpadEnter' }),
                    pause: k({ key: 'Pause' }),
                    esc: k({ key: 'Escape' }),
                    shiftEsc: k({ key: 'Escape', shiftKey: true }),
                    pa1: k({ key: 'Insert', altKey: true }),
                    pa2: k({ key: 'Home', altKey: true }),
                    pa3: k({ key: 'PageUp', shiftKey: true }),
                    pageDown: k({ key: 'PageDown' }),
                    end: k({ key: 'End' }),
                    shiftEnd: k({ key: 'End', shiftKey: true }),
                    altEnd: k({ key: 'End', altKey: true }),
                    numpadEnd: k({ key: 'End', code: 'Numpad1' }),
                    dup: k({ key: 'Insert', shiftKey: true }),
                    fm: k({ key: 'Home', shiftKey: true }),
                    pf13: k({ key: 'F1', shiftKey: true }),
                    copy: k({ key: 'c', ctrlKey: true }),
                    rightCtrl: m.ctrlTap('ControlRight', 'pcomm'),
                    leftCtrl: m.ctrlTap('ControlLeft', 'pcomm'),
                    x3270Ctrl: m.ctrlTap('ControlRight', 'x3270'),
                    x3270Enter: m.keyToMessage({ key: 'Enter' }),
                };
            }",
        )
        .await;
        let aid = |a: &str| json!({"type": "aid", "aid": a});
        let action = |a: &str| json!({"type": "action", "action": a});
        assert_eq!(r["enter"], action("newline"));
        assert_eq!(r["numpadEnter"], aid("enter"));
        assert_eq!(r["pause"], aid("clear"));
        assert_eq!(r["esc"], json!({"type": "attention", "key": "attn"}));
        assert_eq!(r["shiftEsc"], json!({"type": "attention", "key": "sysreq"}));
        assert_eq!(
            (&r["pa1"], &r["pa2"], &r["pa3"]),
            (&aid("pa1"), &aid("pa2"), &aid("pa3"))
        );
        assert_eq!(r["pageDown"], Value::Null);
        assert_eq!(r["end"], action("erase_eof"));
        assert_eq!(r["shiftEnd"], action("erase_field"));
        assert_eq!(r["altEnd"], action("erase_input"));
        assert_eq!(r["numpadEnd"], action("field_end"));
        assert_eq!(
            (&r["dup"], &r["fm"]),
            (&action("dup"), &action("field_mark"))
        );
        assert_eq!(r["pf13"], aid("pf13"));
        assert_eq!(r["copy"], json!("browser"));
        assert_eq!(r["rightCtrl"], aid("enter"));
        assert_eq!(r["leftCtrl"], action("reset"));
        assert_eq!(r["x3270Ctrl"], Value::Null);
        assert_eq!(r["x3270Enter"], aid("enter"));

        // Every function in the key help has a text in both languages.
        let functions = with_module(
            &driver,
            "/keymap.js",
            "(m) => Object.values(m.HELP).flat().map(([fn]) => fn)",
        )
        .await;
        let missing = with_module(
            &driver,
            "/i18n.js",
            &format!(
                "(i18n) => {functions}.filter((fn) => i18n.t('en', fn) === fn \
                 || i18n.t('cs', fn) === fn)"
            ),
        )
        .await;
        assert_eq!(missing, json!([]));
    })
    .await;
}

/// A profile with the PCOMM layout: a Right Ctrl tap is Enter, Pause is Clear, the Enter key
/// is New Line (no AID); Ctrl+C is never an Enter. A user may switch the layout of the profile
/// for themselves in the key help.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_pcomm_layout_of_a_profile_reaches_the_host_and_can_be_switched() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "pcomm").await;
        focus_terminal(&driver).await;

        driver
            .action_chain()
            .send_keys(RIGHT_CTRL)
            .perform()
            .await
            .unwrap();
        host_receives_aid(&mut fx.host.received, AID_ENTER).await;
        wait_for_screen_text(&driver, "WELCOME").await;

        driver
            .action_chain()
            .send_keys(Key::Pause)
            .perform()
            .await
            .unwrap();
        host_receives_aid(&mut fx.host.received, AID_CLEAR).await;
        wait_for_first_host_screen(&driver).await;

        // Enter (the main key: WebDriver's "Return"; its "Enter" is the numpad key) is New
        // Line, Ctrl+C a copy: neither reaches the host.
        driver
            .action_chain()
            .send_keys(Key::Return)
            .key_down(Key::Control)
            .send_keys("c")
            .key_up(Key::Control)
            .perform()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        if let Ok(read) = fx.host.received.try_recv() {
            panic!("no AID for Enter (New Line) or Ctrl+C, but the host got {read:02X?}");
        }

        // The user switches this profile to the x3270 layout: Enter is Enter again.
        driver
            .find(By::Id("btn-help"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        js::<Value>(
            &driver,
            "const s = document.getElementById('preset'); s.value = 'x3270'; \
             s.dispatchEvent(new Event('change')); \
             document.getElementById('keyhelp').close(); return null;",
            vec![],
        )
        .await;
        let remembered = js::<Value>(
            &driver,
            "return localStorage.getItem('bastion3270.keyboard.pcomm');",
            vec![],
        )
        .await;
        assert_eq!(remembered, json!("x3270"));
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        host_receives_aid(&mut fx.host.received, AID_ENTER).await;
    })
    .await;
}

// ─── Settings ────────────────────────────────────────────────────────────────────────

/// Sets a form control in the settings dialog and fires its `change` event.
async fn set_control(driver: &WebDriver, id: &str, value: Value) {
    js::<Value>(
        driver,
        "const [id, value] = arguments; const el = document.getElementById(id); \
         if (el.type === 'checkbox') el.checked = value; else el.value = value; \
         el.dispatchEvent(new Event('change', { bubbles: true })); return null;",
        vec![Value::from(id), value],
    )
    .await;
}

/// Closes the settings dialog with its Close button, as a user does.
async fn close_settings(driver: &WebDriver) {
    driver
        .find(By::Css("#settings form button"))
        .await
        .unwrap()
        .click()
        .await
        .unwrap();
}

/// Display settings apply at once and are remembered: the light theme repaints the screen
/// and the page; the key bar can be hidden.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn display_settings_apply_at_once_and_are_remembered() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        driver
            .find(By::Id("btn-settings"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        set_control(&driver, "set-theme", json!("light")).await;
        set_control(&driver, "set-keybar", json!(false)).await;
        assert_eq!(
            pixel(&driver, 20, 60).await,
            [0xfb, 0xfb, 0xf7, 0xff],
            "light background"
        );
        let page = js::<Value>(
            &driver,
            "return [document.documentElement.dataset.theme, \
                     document.getElementById('keybar').hidden, \
                     JSON.parse(localStorage.getItem('bastion3270.display')).theme, \
                     document.querySelector('meta[name=\"theme-color\"]').content];",
            vec![],
        )
        .await;
        assert_eq!(page, json!(["light", true, "light", "#ffffff"]));

        driver.refresh().await.unwrap();
        wait_for_first_host_screen(&driver).await;
        assert_eq!(
            pixel(&driver, 20, 60).await,
            [0xfb, 0xfb, 0xf7, 0xff],
            "after a reload"
        );
    })
    .await;
}

/// The choices made before a session (screen, code page) are stored per profile in the picker
/// and travel with `open`; a screen size the gateway does not accept is explained.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn session_settings_travel_with_the_next_open() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        driver
            .find(By::Id("options-host"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        set_control(&driver, "opt-host-model", json!("4")).await;
        set_control(&driver, "opt-host-codepage", json!("cp1047")).await;
        let stored = js::<Value>(
            &driver,
            "return JSON.parse(localStorage.getItem('bastion3270.session-options.host'));",
            vec![],
        )
        .await;
        assert_eq!(stored["model"], json!("4"));
        assert_eq!(stored["codepage"], json!("cp1047"));
        fx.open_from_picker(&driver, "host").await;
        // The new session uses cp1047: "[" is X'AD' there (X'BA' in cp037).
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys("[")
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        let read = host_receives_aid(&mut fx.host.received, AID_ENTER).await;
        assert!(read.contains(&0xAD) && !read.contains(&0xBA), "{read:02X?}");
        assert!(
            oia(&driver).await.contains("M4"),
            "the status line names the model"
        );

        // A screen size the gateway does not accept: refused with an explanation.
        driver
            .find(By::Id("btn-disconnect"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        driver
            .find(By::Id("options-host"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        set_control(&driver, "opt-host-model", json!("dynamic")).await;
        set_control(&driver, "opt-host-rows", json!(99)).await;
        driver
            .find(By::XPath(
                "//ul[@id='profiles']//button[starts-with(normalize-space(.), 'Mock host')]"
                    .to_owned(),
            ))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_message(&driver, "not accepted").await;
    })
    .await;
}

/// Blank fill is a general setting: switched off in the settings dialog, it applies to the
/// open session at once. Typed after two empty positions, "X" then reaches the host without
/// the two blanks blank fill would have put before it (the profile's default is on).
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn blank_fill_is_switched_for_the_open_session() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        driver
            .find(By::Id("btn-settings"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        set_control(&driver, "set-blank", json!("off")).await;
        close_settings(&driver).await;
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys(Key::Right)
            .send_keys(Key::Right)
            .send_keys("X")
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        let read = host_receives_aid(&mut fx.host.received, AID_ENTER).await;
        assert!(read.contains(&0xE7), "{read:02X?}"); // "X"
        assert!(
            !read.windows(3).any(|w| w == [0x40, 0x40, 0xE7]),
            "no blanks before X with blank fill off: {read:02X?}"
        );
    })
    .await;
}

// ─── Session tabs, picker ────────────────────────────────────────────────────────────

/// The number of session tabs in the header.
async fn tab_count(driver: &WebDriver) -> u64 {
    js::<Value>(
        driver,
        "return document.querySelectorAll('#tabs .tab').length;",
        vec![],
    )
    .await
    .as_u64()
    .unwrap()
}

/// Two sessions in tabs: each keeps its own screen, Alt+1 / Alt+2 switch, a reload resumes
/// both (no new host connection), the close button ends one after a confirmation.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn sessions_run_in_tabs_and_survive_a_reload() {
    let mut fx = Fixture::start().await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys("FIRST")
            .perform()
            .await
            .unwrap();
        wait_for_screen_text(&driver, "FIRST").await;

        driver
            .find(By::Id("btn-new"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        // The picker appears once the profiles are loaded (a fetch), not with the click.
        wait_until(
            &driver,
            "the picker offers the way back to the sessions",
            "return document.getElementById('picker-back').hidden ? null : true;",
        )
        .await;
        fx.open_from_picker(&driver, "pcomm").await;
        assert_eq!(tab_count(&driver).await, 2);
        assert_eq!(fx.host.connection_count(), 2);
        let second_has_first = copy_text(&driver).await.unwrap().contains("FIRST");
        assert!(!second_has_first, "the new tab shows its own screen");

        // Alt+1 shows the first session again.
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .key_down(Key::Alt)
            .send_keys("1")
            .key_up(Key::Alt)
            .perform()
            .await
            .unwrap();
        wait_for_screen_text(&driver, "FIRST").await;

        // A reload resumes both tabs, without reconnecting to the host.
        driver.refresh().await.unwrap();
        wait_until(
            &driver,
            "both tabs resumed",
            "return document.querySelectorAll('#tabs .tab:not(.connecting)').length === 2 \
                    ? true : null;",
        )
        .await;
        wait_for_screen_text(&driver, "FIRST").await;
        assert_eq!(fx.host.connection_count(), 2, "resumed, not reconnected");

        // Closing a connected tab asks first; the other session stays.
        driver
            .find(By::Css("#tabs .tab .tab-close"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        driver.accept_alert().await.unwrap();
        wait_until(
            &driver,
            "one tab left",
            "return document.querySelectorAll('#tabs .tab').length === 1 ? true : null;",
        )
        .await;
        wait_for_first_host_screen(&driver).await;
        let disconnect = host_receives_disconnect_or_close(&mut fx.host).await;
        assert!(disconnect, "the closed tab's session ended");
    })
    .await;
}

/// The host side of a closed tab: its connection is closed by the gateway.
async fn host_receives_disconnect_or_close(host: &mut MockHost) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if host.closed_count() >= 1 {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// The gateway's tab limit is kept by the page.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_tab_limit_of_the_gateway_is_kept() {
    let fx = Fixture::start_with("[limits]\nmax_tabs_per_page = 1").await;
    with_browser(|driver| async move {
        fx.open(&driver, "host").await;
        driver
            .find(By::Id("btn-new"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_message(&driver, "At most 1 sessions").await;
        assert_eq!(tab_count(&driver).await, 1);
    })
    .await;
}

/// The picker: a single profile is opened at once; with many profiles a filter appears; the
/// profile used last is offered on top.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_picker_opens_a_single_profile_and_filters_many() {
    let host = mock_host::spawn(LOGON.as_slice(), reply).await;
    let profile = |id: &str, name: &str| {
        format!(
            "[[profiles]]\nid = \"{id}\"\nname = \"{name}\"\n[profiles.connection]\n\
             tls_mode = \"disabled\"\nhost = \"127.0.0.1\"\nport = {}\n\
             terminal_model = \"Model2\"\n",
            host.port
        )
    };
    let single = start(
        ServerConfig::from_toml_str(&profile("only", "Only one")).unwrap(),
        |e| e,
    )
    .await;
    let many = (1..=9)
        .map(|i| profile(&format!("lpar{i}"), &format!("LPAR {i}")))
        .collect::<String>();
    let many = start(ServerConfig::from_toml_str(&many).unwrap(), |e| e).await;
    with_browser(|driver| async move {
        driver.goto(format!("http://{}/", single.addr)).await.unwrap();
        wait_for_first_host_screen(&driver).await;
        assert_eq!(tab_count(&driver).await, 1, "opened without the picker");

        driver.goto(format!("http://{}/", many.addr)).await.unwrap();
        let shown = wait_until(
            &driver,
            "the picker with a filter",
            "const f = document.getElementById('picker-filter'); \
             return document.getElementById('picker').hidden || f.hidden ? null : \
                    document.querySelectorAll('#profiles li').length;",
        )
        .await;
        assert_eq!(shown, json!(9));
        driver.find(By::Id("picker-filter")).await.unwrap().send_keys("LPAR 7").await.unwrap();
        let filtered = wait_until(
            &driver,
            "one profile after filtering",
            "const n = document.querySelectorAll('#profiles li').length; return n === 1 ? n : null;",
        )
        .await;
        assert_eq!(filtered, json!(1));

        // Used once, LPAR 7 is offered on top next time.
        driver
            .find(By::XPath("//ul[@id='profiles']//button".to_owned()))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_first_host_screen(&driver).await;
        driver.find(By::Id("btn-disconnect")).await.unwrap().click().await.unwrap();
        let recent = wait_until(
            &driver,
            "the recent profiles",
            "const r = document.getElementById('recent'); \
             return document.getElementById('picker').hidden || r.hidden ? null : r.textContent;",
        )
        .await;
        assert_eq!(recent, json!("LPAR 7"));
    })
    .await;
}

/// Session options on the start screen: folded per profile, saved like the settings dialog's.
/// A code page chosen there reaches the host; an LU outside the profile's allowed names is
/// refused with an explanation.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn session_options_can_be_set_in_the_picker() {
    let mut host = mock_host::spawn(LOGON.as_slice(), reply).await;
    let profile = |id: &str, name: &str, extra: &str| {
        format!(
            "[[profiles]]\nid = \"{id}\"\nname = \"{name}\"\n{extra}\n[profiles.connection]\n\
             tls_mode = \"disabled\"\nhost = \"127.0.0.1\"\nport = {}\n\
             terminal_model = \"Model2\"\n",
            host.port
        )
    };
    let toml = format!(
        "{}{}",
        profile("free", "Free LU", ""),
        profile("fixed", "CICS only", "allowed_lu_names = [\"CICS*\"]")
    );
    let gw = start(ServerConfig::from_toml_str(&toml).unwrap(), |e| e).await;
    with_browser(|driver| async move {
        driver.goto(format!("http://{}/", gw.addr)).await.unwrap();
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;

        // The restricted profile names its allowed LUs and refuses another one.
        driver
            .find(By::Id("options-fixed"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        let hint = js::<Value>(
            &driver,
            "return document.querySelector('#profiles .profile-options small').textContent;",
            vec![],
        )
        .await;
        assert_eq!(hint, json!("Allowed: CICS*"));
        set_control(&driver, "opt-fixed-lu", json!("tso0001")).await;
        let stored = js::<Value>(
            &driver,
            "return JSON.parse(localStorage.getItem('bastion3270.session-options.fixed')).lu_name;",
            vec![],
        )
        .await;
        assert_eq!(stored, json!("TSO0001"));
        driver
            .find(By::XPath(
                "//ul[@id='profiles']//button[starts-with(normalize-space(.), 'CICS only')]"
                    .to_owned(),
            ))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_message(&driver, "LU TSO0001 is not allowed").await;

        // The free profile: the code page chosen in the picker is used by the session.
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        driver
            .find(By::Id("options-free"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        set_control(&driver, "opt-free-codepage", json!("cp1047")).await;
        driver
            .find(By::XPath(
                "//ul[@id='profiles']//button[starts-with(normalize-space(.), 'Free LU')]"
                    .to_owned(),
            ))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_first_host_screen(&driver).await;
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys("[")
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        let read = host_receives_aid(&mut host.received, AID_ENTER).await;
        assert!(read.contains(&0xAD), "{read:02X?}");
        let oia = oia(&driver).await;
        assert!(oia.contains("CP1047"), "{oia}");
    })
    .await;
}

/// A connection of the user's own: defined in the picker (host, port, no TLS, a code page),
/// saved in the browser, opened through the gateway's policy check; it survives a reload and
/// is listed under "My connections". With custom connections disabled the button is not shown.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn a_connection_of_the_users_own_can_be_defined_and_opened() {
    let mut fx = Fixture::start().await;
    let closed = Fixture::start_with("[custom_connections]\nenabled = false").await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        driver
            .find(By::Id("btn-custom-new"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        driver
            .find(By::Id("custom-name"))
            .await
            .unwrap()
            .send_keys("Lab")
            .await
            .unwrap();
        driver
            .find(By::Id("custom-host"))
            .await
            .unwrap()
            .send_keys("127.0.0.1")
            .await
            .unwrap();
        set_control(&driver, "custom-port", json!(fx.host.port)).await;
        set_control(&driver, "custom-tls", json!(false)).await;
        set_control(&driver, "custom-opt-codepage", json!("cp1047")).await;
        driver
            .find(By::Id("custom-connect"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_for_first_host_screen(&driver).await;

        let tab = js::<Value>(
            &driver,
            "return document.querySelector('#tabs .tab-main').textContent;",
            vec![],
        )
        .await;
        assert_eq!(tab, json!("Lab"));
        focus_terminal(&driver).await;
        driver
            .action_chain()
            .send_keys("[")
            .send_keys(Key::Enter)
            .perform()
            .await
            .unwrap();
        let read = host_receives_aid(&mut fx.host.received, AID_ENTER).await;
        assert!(
            read.contains(&0xAD),
            "cp1047 chosen for the connection: {read:02X?}"
        );

        // A reload resumes it (no new host connection) and keeps its name.
        driver.refresh().await.unwrap();
        wait_for_first_host_screen(&driver).await;
        assert_eq!(fx.host.connection_count(), 1);
        let tab = js::<Value>(
            &driver,
            "return document.querySelector('#tabs .tab-main').textContent;",
            vec![],
        )
        .await;
        assert_eq!(tab, json!("Lab"));

        driver
            .find(By::Id("btn-disconnect"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        let listed = wait_until(
            &driver,
            "my connections",
            "const l = document.getElementById('custom-list'); \
             return document.getElementById('picker').hidden || l.hidden ? null : l.textContent;",
        )
        .await;
        assert!(listed.as_str().unwrap().contains("Lab"), "{listed}");

        // Disabled by the administrator: not offered.
        driver.goto(closed.url()).await.unwrap();
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        let offered = js::<bool>(
            &driver,
            "return !document.getElementById('btn-custom-new').hidden;",
            vec![],
        )
        .await;
        assert!(!offered);
    })
    .await;
}

/// Printing (button, Ctrl+P or the browser's menu, all through `beforeprint`) puts the active
/// screen into the print view and removes it after printing; a profile without copy prints
/// only the notice that printing is not allowed.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn printing_shows_only_the_screen_and_follows_the_copy_policy() {
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        let printed = |event: &'static str| {
            let driver = &driver;
            async move {
                js::<String>(
                    driver,
                    "window.dispatchEvent(new Event(arguments[0])); \
                     return document.getElementById('print-view').textContent;",
                    vec![Value::from(event)],
                )
                .await
            }
        };
        fx.open(&driver, "host").await;
        let text = printed("beforeprint").await;
        assert!(text.starts_with("Mock host — "), "{text}");
        assert!(
            text.contains("USERID:") && text.contains("LU LUTEST01"),
            "{text}"
        );
        assert_eq!(printed("afterprint").await, "", "nothing stays in the page");

        driver
            .find(By::Id("btn-disconnect"))
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        wait_until(
            &driver,
            "the picker",
            "return document.getElementById('picker').hidden ? null : true;",
        )
        .await;
        fx.open_from_picker(&driver, "nocopy").await;
        let text = printed("beforeprint").await;
        assert_eq!(text, "Printing this system's screens is not allowed.\n");
        wait_for_message(&driver, "not allowed").await;
    })
    .await;
}

/// Chrome and Edge decide themselves whether a page can be installed as an application, so
/// the test asks the browser (DevTools `Page.getAppManifest`, `Page.getInstallabilityErrors`)
/// instead of repeating its rules. Firefox cannot be asked; the manifest and its icons are
/// checked without a browser in `http_routes_tests`.
#[tokio::test]
#[ignore = "needs a WebDriver server (see the module docs)"]
async fn the_browser_finds_the_client_installable() {
    if Browser::selected() == Browser::Firefox {
        eprintln!("skipped: Firefox has no installability check");
        return;
    }
    let fx = Fixture::start().await;
    with_browser(|driver| async move {
        driver.goto(fx.url()).await.unwrap();
        let tools = driver.cdp();
        let manifest = tools
            .send_raw("Page.getAppManifest", json!({}))
            .await
            .unwrap();
        assert!(
            manifest["url"]
                .as_str()
                .is_some_and(|url| url.ends_with("/manifest.webmanifest")),
            "the page's manifest was loaded: {manifest}"
        );
        assert_eq!(manifest["errors"], json!([]), "manifest errors");
        let answer = tools
            .send_raw("Page.getInstallabilityErrors", json!({}))
            .await
            .unwrap();
        assert_eq!(
            answer["installabilityErrors"],
            json!([]),
            "the browser refuses to install the client"
        );
    })
    .await;
}
