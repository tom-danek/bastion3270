// Browser key → bastion3270.v1 message mapping, in two presets:
//
// * `x3270` — the wc3270 conventions (Enter = Enter, Shift+Enter = New Line);
// * `pcomm` — the default 3270 layout of IBM Personal Communications for the Enhanced
//   keyboard (Right Ctrl = Enter, Enter = New Line, Left Ctrl = Reset, Pause = Clear, Esc =
//   Attn, Alt+Insert / Alt+Home = PA1 / PA2, End = Erase EOF).
//
// Pure: no DOM access, so it can be tested in any browser by importing the module.

export const PRESETS = Object.freeze(["x3270", "pcomm"]);

/** Keys that map one to one to an editing action in both presets. */
export const ACTIONS = Object.freeze({
  Tab: "tab", Home: "home", ArrowLeft: "left", ArrowRight: "right", ArrowUp: "up",
  ArrowDown: "down", Backspace: "backspace", Delete: "delete", End: "field_end",
  Escape: "reset", Insert: "toggle_insert",
});

/** Returned for keys the browser must handle itself (copy and paste shortcuts). */
export const BROWSER = "browser";

const aid = (name) => ({ type: "aid", aid: name });
const action = (name) => ({ type: "action", action: name });
const attention = (name) => ({ type: "attention", key: name });

/** F1–F12 → PF1–12, with Shift PF13–24 (both presets). */
function functionKey(key, shiftKey) {
  if (!/^F([1-9]|1[0-2])$/.test(key)) return null;
  return aid("pf" + (parseInt(key.slice(1), 10) + (shiftKey ? 12 : 0)));
}

/** The PCOMM mapping of a key event, `undefined` when the key is not special there. */
function pcomm(e) {
  const { key, code = "", shiftKey = false, altKey = false } = e;
  if (key === "Enter") return code === "NumpadEnter" ? aid("enter") : action("newline");
  if (key === "Pause") return aid("clear");
  if (key === "Escape") return shiftKey ? attention("sysreq") : attention("attn");
  if (key === "Insert") {
    if (altKey) return aid("pa1");
    return shiftKey ? action("dup") : action("toggle_insert");
  }
  if (key === "Home") {
    if (altKey) return aid("pa2");
    return shiftKey ? action("field_mark") : action("home");
  }
  if (key === "PageUp") return shiftKey ? aid("pa3") : null;
  if (key === "PageDown") return null;
  if (key === "End") {
    if (code === "Numpad1") return action("field_end");
    if (altKey) return action("erase_input");
    return shiftKey ? action("erase_field") : action("erase_eof");
  }
  return undefined;
}

/** The x3270 mapping of a key event, `undefined` when the key is not special there. */
function x3270(e) {
  const { key, shiftKey = false, ctrlKey = false } = e;
  if (key === "Enter") return shiftKey || ctrlKey ? action("newline") : aid("enter");
  if (key === "End" && shiftKey) return action("erase_eof"); // as wc3270
  if (key === "PageUp") return aid("pf7");
  if (key === "PageDown") return aid("pf8");
  return undefined;
}

/**
 * The protocol message for a key press, `BROWSER` for Ctrl+C / Ctrl+V (so the copy and paste
 * events fire), or `null` for keys the terminal does not use.
 *
 * @param {{key: string, code?: string, shiftKey?: boolean, ctrlKey?: boolean,
 *          altKey?: boolean, metaKey?: boolean}} e  a `KeyboardEvent` or an object with the
 *          same fields
 * @param {string} [preset]  `x3270` (default) or `pcomm`
 */
export function keyToMessage(e, preset = "x3270") {
  const { key, shiftKey = false, ctrlKey = false, altKey = false, metaKey = false } = e;
  if (ctrlKey && (key === "c" || key === "v")) return BROWSER;
  const special = preset === "pcomm" ? pcomm(e) : x3270(e);
  if (special !== undefined) return special;
  if (key === "Tab" && shiftKey) return action("backtab");
  const pf = functionKey(key, shiftKey);
  if (pf) return pf;
  if (Object.hasOwn(ACTIONS, key)) return action(ACTIONS[key]);
  if (key.length === 1 && !ctrlKey && !metaKey && !altKey) return { type: "key", ch: key };
  return null;
}

/**
 * The message for a Ctrl key pressed and released alone (no other key in between): in the
 * PCOMM preset Right Ctrl is Enter and Left Ctrl is Reset; `null` otherwise. A Ctrl that
 * starts a shortcut (Ctrl+C) is therefore never an Enter.
 *
 * @param {string} code  `KeyboardEvent.code` of the Ctrl key (`ControlRight` / `ControlLeft`)
 * @param {string} [preset]
 */
export function ctrlTap(code, preset = "x3270") {
  if (preset !== "pcomm") return null;
  if (code === "ControlRight") return aid("enter");
  if (code === "ControlLeft") return action("reset");
  return null;
}

/**
 * The key help of a preset: `[function, keys]` rows; `function` is an i18n key (`fn.*`),
 * `keys` the key names as printed on a keyboard.
 */
export const HELP = Object.freeze({
  x3270: Object.freeze([
    ["fn.enter", "Enter"], ["fn.newline", "Shift+Enter, Ctrl+Enter"], ["fn.reset", "Esc"],
    ["fn.pf", "F1–F12, Shift+F1–F12 (PF13–24)"], ["fn.pf78", "PageUp / PageDown (PF7 / PF8)"],
    ["fn.erase_eof", "Shift+End"], ["fn.field_end", "End"], ["fn.insert", "Insert"],
    ["fn.tab", "Tab / Shift+Tab"], ["fn.copy_paste", "Ctrl+C / Ctrl+V"],
    ["fn.keybar", "Clear, PA1–PA3, Attn, SysReq, Dup, Field Mark"],
  ]),
  pcomm: Object.freeze([
    ["fn.enter", "Right Ctrl, Numpad Enter"], ["fn.newline", "Enter"], ["fn.reset", "Left Ctrl"],
    ["fn.clear", "Pause"], ["fn.attn_sysreq", "Esc / Shift+Esc"],
    ["fn.pa", "Alt+Insert / Alt+Home / Shift+PageUp (PA1 / PA2 / PA3)"],
    ["fn.pf", "F1–F12, Shift+F1–F12 (PF13–24)"], ["fn.erase_eof", "End"],
    ["fn.erase_field_input", "Shift+End / Alt+End"], ["fn.field_end", "Numpad End"],
    ["fn.dup_fm", "Shift+Insert / Shift+Home"], ["fn.insert", "Insert"],
    ["fn.tab", "Tab / Shift+Tab"], ["fn.copy_paste", "Ctrl+C / Ctrl+V"],
  ]),
});
