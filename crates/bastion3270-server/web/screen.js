// Pure helpers for the screen projection sent by the gateway (`WireScreen` / `WireStatus` in
// `src/protocol.rs`): colours, selection, pointer → cell and the OIA line.
//
// No DOM access, so they can be tested in any browser by importing the module.

/** IBM 3279 palette, identical to the desktop client's "classic3279". */
export const COLORS = Object.freeze({
  0xf0: "#0a0e14", 0xf1: "#4299ff", 0xf2: "#ff4d4d", 0xf3: "#ff79c6",
  0xf4: "#2eeb5a", 0xf5: "#00e5ff", 0xf6: "#ffea55", 0xf7: "#f8f8f2",
  0xf8: "#0a0e14", 0xf9: "#1e5ad7", 0xfa: "#ff9e3b", 0xfb: "#bd93f9",
  0xfc: "#8aff80", 0xfd: "#a4ffff", 0xfe: "#9aa5b1", 0xff: "#f8f8f2",
});
export const DEFAULT_PROTECTED = "#5cb8ff";
export const DEFAULT_UNPROTECTED = "#2eeb5a";
export const BG = "#0a0e14";

/**
 * Colour themes of the screen: background, the 16 colour codes, the default colours of
 * protected / unprotected fields, cursor and selection. `classic` is the 3279 look above;
 * `light` keeps the colours distinguishable on a light background (black and white text turn
 * dark); `green` is a monochrome 3278 green screen.
 */
const GREEN = "#33ff66";
export const THEMES = Object.freeze({
  classic: Object.freeze({
    bg: BG, colors: COLORS, prot: DEFAULT_PROTECTED, unprot: DEFAULT_UNPROTECTED,
    cursor: "#00e5ff", selection: "#4299ff",
  }),
  light: Object.freeze({
    bg: "#fbfbf7",
    colors: Object.freeze({
      0xf0: "#111111", 0xf1: "#1f5fbf", 0xf2: "#c62828", 0xf3: "#ad1457",
      0xf4: "#2e7d32", 0xf5: "#00838f", 0xf6: "#8a6d00", 0xf7: "#111111",
      0xf8: "#111111", 0xf9: "#1a3f9e", 0xfa: "#c25a00", 0xfb: "#6a1b9a",
      0xfc: "#388e3c", 0xfd: "#00695c", 0xfe: "#555555", 0xff: "#111111",
    }),
    prot: "#1f5fbf", unprot: "#2e7d32", cursor: "#0077aa", selection: "#4299ff",
  }),
  green: Object.freeze({
    bg: "#020a03",
    colors: Object.freeze(Object.fromEntries(Object.keys(COLORS).map((k) => [k, GREEN]))),
    prot: GREEN, unprot: GREEN, cursor: GREEN, selection: "#1f8f3a",
  }),
  // A monochrome amber screen (the desktop client's "Amber screen"): bright amber for
  // high-intensity colours, darker for blue / grey, normal amber otherwise.
  amber: Object.freeze({
    bg: "#140c02",
    colors: Object.freeze(Object.fromEntries(Object.keys(COLORS).map((k) => {
      const code = Number(k);
      if (code === 0xf0 || code === 0xf8) return [k, "#140c02"];
      if ([0xf2, 0xf6, 0xf7, 0xff].includes(code)) return [k, "#ffe28a"];
      if ([0xf1, 0xf9, 0xfe].includes(code)) return [k, "#d48800"];
      return [k, "#ffb81c"];
    }))),
    prot: "#e09600", unprot: "#ffb81c", cursor: "#ffb800", selection: "#8a5a08",
  }),
});

/** Run flag: the cells are protected. */
const F_PROTECTED = 1;
/** Highlight bits (`hl`). */
const HL_REVERSE = 2;
const HL_UNDERSCORE = 4;

/** Colour of a 3279 colour code; `0` (default) is `fallback`, or the field default. */
export function colorOf(code, protectedCell, fallback, theme = THEMES.classic) {
  if (code === 0) {
    if (fallback !== undefined) return fallback;
    return protectedCell ? theme.prot : theme.unprot;
  }
  return theme.colors[code] || theme.unprot;
}

/**
 * How the cells of one style run are painted: foreground, background (`null` = screen
 * background) and underline. Reverse video swaps foreground and background.
 */
export function runStyle(run, theme = THEMES.classic) {
  const prot = (run.f & F_PROTECTED) !== 0;
  let fg = colorOf(run.fg, prot, undefined, theme);
  let bg = run.bg === 0 ? null : colorOf(run.bg, prot, theme.bg, theme);
  if (run.hl & HL_REVERSE) {
    const t = fg;
    fg = bg || theme.bg;
    bg = t;
  }
  return { fg, bg, underline: (run.hl & HL_UNDERSCORE) !== 0 };
}

/** The screen cell under a pointer position, clamped to the screen (a drag may leave it). */
export function cellAt(clientX, clientY, rect, cell, rows, cols) {
  const clamp = (v, max) => Math.min(Math.max(v, 0), max - 1);
  return {
    row: clamp(Math.floor((clientY - rect.top) / cell.h), rows),
    col: clamp(Math.floor((clientX - rect.left) / cell.w), cols),
  };
}

/** The rectangle (inclusive) spanned by the anchor cell and the current cell. */
export function selectionFrom(anchor, point) {
  return {
    r0: Math.min(anchor.row, point.row), r1: Math.max(anchor.row, point.row),
    c0: Math.min(anchor.col, point.col), c1: Math.max(anchor.col, point.col),
  };
}

/**
 * Clipboard text of the selection, or of the whole screen when `sel` is null: one line per
 * row, trailing blanks removed. Only text the gateway sent, so hidden fields are blank.
 */
export function selectionText(screen, sel) {
  const rows = sel
    ? screen.text.slice(sel.r0, sel.r1 + 1).map((r) => r.slice(sel.c0, sel.c1 + 1))
    : screen.text;
  return rows.map((r) => r.trimEnd()).join("\n");
}

const MODES = Object.freeze({ "sscp-lu": "SSCP-LU", nvt: "NVT", unbound: "UNBOUND" });

/** 1-based, three-digit cursor coordinate. */
function pad3(n) { return String(n + 1).padStart(3, "0"); }

/**
 * The OIA line: `{ left, lock, cursor }`. The lock part is rendered in its own element so it
 * can be styled.
 */
export function oiaText(status, screen) {
  const left = (status.state === "connected" ? "4A" : "4-") + "  " +
    (status.tls ? "TLS" : "TCP") + "  " + (status.tn3270e ? "TN3270E" : "TN3270") +
    (MODES[status.mode] ? "  " + MODES[status.mode] : "") +
    (status.lu ? "  LU " + status.lu : "") + (status.insert ? "  INS" : "") + "  ";
  const lock = (status.keyboard || (status.state === "connected" ? "" : status.state)).padEnd(14, " ");
  // The session's model, the screen's current size and the code page, as in the desktop
  // client ("M4 43×80 CP037"; a dynamic model shows "DYN").
  const model = status.model ? (status.model === "dynamic" ? "DYN" : "M" + status.model) : "";
  const geometry = model
    ? model + " " + screen.rows + "×" + screen.cols + (status.codepage ? "  " + status.codepage.toUpperCase() : "") + "  "
    : "";
  const cursor = "  " + geometry + pad3(screen.cursor[0]) + "/" + pad3(screen.cursor[1]);
  return { left, lock, cursor };
}

/** Smallest and largest font size (CSS pixels) of the screen. */
export const MIN_FONT = 8;
export const MAX_FONT = 72;
/** Zoom steps of `Ctrl +` / `Ctrl -` (each step × 1.1 on top of the fitted size). */
export const MIN_ZOOM = -6;
export const MAX_ZOOM = 8;

/**
 * The cell size for a `rows` × `cols` screen in an area of `availW` × `availH` CSS pixels:
 * the largest font size whose cells fit (zoom 0), times 1.1 per zoom step, within
 * `MIN_FONT`..`MAX_FONT`. With zoom > 0 the screen may be larger than the area (it scrolls).
 *
 * @param {{w: number, ascent: number, descent: number}} m  glyph metrics at a 100 px font
 * @returns {{font: number, w: number, h: number, ascent: number}}  `ascent` = baseline offset
 */
export function fitCell(availW, availH, rows, cols, m, zoom) {
  const cell = (font) => {
    const glyph = ((m.ascent + m.descent) * font) / 100;
    const h = Math.ceil(glyph * 1.2);
    return {
      font,
      w: Math.ceil((m.w * font) / 100),
      h,
      ascent: Math.round((h - glyph) / 2 + (m.ascent * font) / 100),
    };
  };
  let font = MAX_FONT;
  while (font > MIN_FONT) {
    const c = cell(font);
    if (c.w * cols <= availW && c.h * rows <= availH) break;
    font -= 1;
  }
  const z = Math.min(Math.max(Math.trunc(zoom) || 0, MIN_ZOOM), MAX_ZOOM);
  return cell(Math.min(Math.max(Math.round(font * 1.1 ** z), MIN_FONT), MAX_FONT));
}

/**
 * The text printed for a screen: a title line, a blank line, the screen rows (trailing blanks
 * trimmed), the status line. Only text the gateway sent (hidden fields are already blank).
 *
 * @param {{text: string[]}} screen
 * @param {string} title  e.g. "PROD1 — 14. 11. 2026 10:21"
 * @param {string} statusLine  the status line text
 */
export function printText(screen, title, statusLine) {
  const rows = screen.text.map((row) => row.replace(/\s+$/, ""));
  return [title, "", ...rows, "", statusLine.trim()].join("\n") + "\n";
}

