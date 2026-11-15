# User Guide

This guide is for people who work with mainframe applications through bastion3270: first the
web client, then the [keyboard reference](#4-keyboard-reference) for both the web and the
desktop client. Administrators configure the gateway with the
[configuration reference](CONFIGURATION.md).

## 1. Connect

Open the address of the gateway that your administrator gave you.

1. **Gateway token.** If the gateway asks for a token, enter the one you were given. The
   browser keeps it only for this tab. **Log out** forgets it again.
2. **Pick a system.** The list shows the systems the administrator configured. Click one to
   connect. Your last five systems appear under *Recent*, and a filter field appears once the
   list is long.
3. **Options** (under each system, if the administrator allows them): screen model or a custom
   size, code page and LU name. The gateway checks every choice. The browser remembers your
   choices for that system.
4. **My connections** (if the gateway allows it): **+ New connection** takes a name, host,
   port and TLS. These connections are stored in this browser only. The gateway may allow only
   some targets or only TLS; if it refuses one, you are told when you connect.

The top bar shows the open sessions as tabs. With **+** you open another session, up to the
number the administrator allows per page (4 by default). Alt+1…9 selects a tab, and
Alt+PageUp / Alt+PageDown selects the next or previous one.

### Install the web client as an application

The browser can keep the web client like an installed program: it then opens in a window of
its own, without the address bar and the browser's tabs, and has an icon in the taskbar, the
Start menu or the Dock. It is still the same page of the same gateway. It needs the
connection to the gateway, and nothing more is stored on your computer than in a browser tab.

* **Chrome and Edge:** click the install icon at the end of the address bar, or choose the
  install command in the browser's menu. They offer it only when the gateway is opened over
  HTTPS.
* **Safari on macOS:** *File* → *Add to Dock*.
* **Firefox on Windows:** click the web apps icon in the address bar, then *Add to taskbar*.
  Firefox on Linux and macOS cannot install web applications.

Remove the application again from its window's menu or in the operating system's list of
applications.

## 2. Work with the screen

* **Typing** works as on a 3270 terminal. Characters go into the input field under the cursor.
  Protected fields and non-numeric input in numeric fields are refused, and the status line
  shows why (see [§3](#3-status-line-and-messages)).
* **Mouse:** a click moves the cursor. Dragging selects a rectangle of the screen.
* **Copy** (Ctrl+C) copies the selection, or the whole screen without one. Hidden fields
  (passwords) are copied as blanks: the browser never receives their content.
* **Paste** (Ctrl+V) types the text as if you entered it, the way x3270 pastes:
  * protected positions are skipped;
  * every line starts in the column where the paste started;
  * the paste stops at the end of the screen;
  * a Tab in the text moves to the next field.

  The gateway limits the length of a paste. The administrator may also switch copying,
  pasting and printing off for a system.
* **Print** (Ctrl+P or 🖶) prints only the screen and the status line, with the system name and
  the time.
* **Zoom:** the screen fills the window. Ctrl + and Ctrl − make it larger or smaller, and
  Ctrl 0 fits it again. **⛶** switches to full screen.
* **Key bar** under the screen: Enter, Clear, Reset, PA1–PA3, Erase EOF, Erase Input, Attn,
  SysReq, Dup, Field Mark and PF1–PF12, for keys your keyboard does not have.
* **Settings (⚙):**
  * colours (classic dark, light, green or amber screen);
  * block or underline cursor, blinking cursor and a crosshair;
  * the key bar on or off;
  * *Blank fill*: whether typing after empty positions of a field turns them into spaces.

  The browser remembers these settings.
* **Language:** English or Czech. The status line stays in the usual 3270 notation, as in
  other emulators.

### Interrupted connections

A session lives in the gateway, not in the browser tab. If the network drops, the client
reconnects on its own: after 1, 2, 4 and 8 seconds, then every 15 seconds. It stops when the
gateway has ended the session; the gateway waits five minutes by default. Reloading the page
returns to the same sessions. If the session is opened in another tab, this tab says so and
lets the other one continue.

**Disconnect** ends the active session. **Log out** ends all sessions of the tab and forgets
the token, so the next person at a shared workstation starts at the login screen.

## 3. Status line and messages

The line under the screen (the OIA) shows, from left to right:

* **Connection:** `4A` when connected, `4-` when not.
* **Encryption:** `TLS` or `TCP`.
* **Protocol:** `TN3270E` or `TN3270`, plus `SSCP-LU` or `NVT` when the host is not in 3270 mode.
* **LU name**, and `INS` in insert mode.
* **Keyboard state** (see the table below).
* **Screen:** model and size, code page and cursor position (`M2 24×80  CP037  012/034`).

| Keyboard state | Meaning | What to do |
|---|---|---|
| (empty) | Ready for input. | |
| `X Wait` | The host is processing your input. | Wait. |
| `X SYSTEM` | The host locked the keyboard. | Wait, or press Reset. |
| `X PROTECTED` | You typed into a protected position. | Reset, then move to an input field. |
| `X NUMERIC` | The field accepts digits only. | Reset, then type digits. |
| `X >` | The field is full (insert mode). | Reset; switch insert mode off or delete characters. |
| `X -f` | The function is not available here, e.g. 3270 keys in NVT mode. | Reset. |
| `X [Field]` | Connected, waiting for the host's first screen. | Wait. |
| `X Not Connected` | No connection to the host. | Connect again. |

The message line above the screen explains the session in your language:

* connecting and reconnecting;
* why a session ended, with **Connect again** when you did not end it yourself;
* refused paste or print;
* errors of the gateway.

Information disappears by itself. Warnings and errors stay until you dismiss them.

## 4. Keyboard reference

Two layouts are available:

* **x3270 / wc3270** (default);
* **IBM Personal Communications** (PCOMM).

The administrator chooses the default for each system. You can switch it for that system with
**⌨** in the web client or in the desktop profile manager, and the choice is remembered. The
**⌨** dialog also shows the current layout.

### Both layouts

| Function | Keys |
|---|---|
| PF1–PF12 | F1–F12 |
| PF13–PF24 | Shift+F1–F12 |
| Next / previous field | Tab / Shift+Tab |
| First input field | Home |
| Move the cursor | Arrow keys |
| Delete left / under the cursor | Backspace / Delete |
| Insert mode on / off | Insert |
| Copy / paste | Ctrl+C / Ctrl+V |
| Zoom in / out / fit | Ctrl + / Ctrl − / Ctrl 0 |

### x3270 / wc3270

| Function | Keys |
|---|---|
| Enter | Enter |
| New Line | Shift+Enter, Ctrl+Enter |
| Reset | Esc |
| PF7 / PF8 (page up / down) | PageUp / PageDown |
| End of field | End |
| Erase EOF | Shift+End |
| Clear, PA1–PA3, Attn, SysReq, Dup, Field Mark, Erase Input | key bar (desktop: see below) |

### IBM Personal Communications

| Function | Keys |
|---|---|
| Enter | Right Ctrl, numeric keypad Enter |
| New Line | Enter |
| Reset | Left Ctrl |
| Clear | Pause |
| Attn / SysReq | Esc / Shift+Esc |
| PA1 / PA2 / PA3 | Alt+Insert / Alt+Home / Shift+PageUp |
| Erase EOF | End |
| Erase Field / Erase Input | Shift+End / Alt+End |
| End of field | End on the numeric keypad (Num Lock off) |
| Dup / Field Mark | Shift+Insert / Shift+Home |

Right Ctrl and Left Ctrl act only when pressed and released alone. Ctrl+C is still copy.

### Web client only

| Function | Keys |
|---|---|
| Print the screen | Ctrl+P |
| Select session tab 1–9 | Alt+1…9 |
| Next / previous tab | Alt+PageUp / Alt+PageDown |

### Desktop client

The desktop client uses the same layouts. It also has shortcuts for the keys of the web key
bar:

| Function | Keys |
|---|---|
| Reset | Ctrl+R |
| Clear | Ctrl+L, Alt+C |
| Erase EOF / Erase Input | Ctrl+E / Ctrl+U |
| PA1 / PA2 / PA3 | Alt+1 / Alt+2 / Alt+3 |

The desktop cannot tell the left and right Ctrl keys apart, and it does not see Pause.
In the PCOMM layout it therefore uses Ctrl+Enter for Enter, Ctrl+R for Reset and Ctrl+L for
Clear.
