# osakb — Open Source iPhone as remote **keyboard** and **trackpad** for Mac.

1. Open your Terminal
2. Clone this repo with git on your machine
3. Run the server with Node.js
4. Scan the QR code with your iPhone
5. Grant Accessibility rights for Terminal.
6. Use the web app to control your mac.
7. (optional) Add as Home Screen App.

> ⚠️ **DO NOT USE** if you do not trust your LAN network routers! The easiest
> way to increase trust is to install [Tailscale](https://tailscale.com) on
> your Mac and iPhone.
> See [Security](#security) or [How it works](#how-it-works) for more info.

## Requirements

- macOS
- iPhone
- Git & Node.js
- This repo - no external dependencies.
- **Accessibility permission:** the first time it sends a key, macOS will ask to
  allow your terminal (e.g. Terminal/iTerm) under
  *System Settings → Privacy & Security → Accessibility*. Grant it.

## Run

```sh
node osakb.js wifi # uses Mac .local address at port 8765
node osakb.js tailscale # uses machine hostname at port 8765
PORT=8700 node osakb.js http://192.168.0.2:8700/ # custom
```

It prints the address to open on your phone plus a QR code to make it easier.

The QR (and printed link) then point at that URL with the secret appended as the
`#fragment`.

## Install on your iPhone home screen (full-screen app)

osakb ships an app icon and web manifest, so you can add it to your home screen
and it launches full-screen with no Safari chrome:

1. Open the printed `http://<mac-ip>:8765` in **Safari** on the iPhone (must be
   Safari — Chrome/Firefox on iOS can't add to the home screen).
2. Tap the **Share** button → **Add to Home Screen** → **Add**.
3. Launch it from the new "osakb" icon. It opens full-screen.

Notes:
- Keep the Mac and phone on the same Wi-Fi or Tailscale VPN, and keep `osakb.js`
  running in the Terminal.

## The keyboard

The Keyboard tab pairs your phone's **own native keyboard** with a bar of the
special keys a phone keyboard lacks.

- **Type with the native keyboard.** Tap the capture field and your phone's
  keyboard pops up below; whatever you type — letters, numbers, symbols, **å ä ö**,
  emoji, swipe-typed words, predictive suggestions — is sent straight to the Mac.
  This means your own layout, languages, and autocomplete, instead of a fixed
  on-screen grid. (Soft keyboards don't emit reliable key events, so osakb reads
  the field's edit events instead and forwards each one as a keystroke.)
- **A special-keys bar sits above it**: ⎋ esc, ⇥ tab, the modifiers (⌘ ⌥ ⌃ ⇧),
  and a navigation row (⌫ backspace, ⌦ forward-delete, ← ↑ ↓ →, ⏎ return). These
  stay visible above the native keyboard and don't dismiss it when tapped.
- **Modifier** keys (⌘ ⌥ ⌃ ⇧) **latch**: tap one and it stays held (highlighted
  gold) until you tap it again. While held they combine with what you type next on
  the native keyboard, so you can build combos and selections:
  - tap **⌘**, then press **S** → Cmd-S (⌘ stays held — tap it again to release).
  - hold **⇧** then tap **→** repeatedly to extend a selection.
  - hold **⌘** and **⇧** together, then press **T** → Cmd-Shift-T.
- Backspace, return, and the native "delete word" gesture are all forwarded; the
  native keyboard's own shift/caps handles letter case.

## The trackpad

The app opens on the **Mouse** tab. It's a remote trackpad:

- **Drag** anywhere on the trackpad area to move the cursor (relative movement,
  like a laptop trackpad); **tap** it for a left click.
- A **scroll** strip down the side scrolls the wheel.
- **Left click** / **Right click** buttons below the pad. They are
  **press-and-hold**: the button stays down while you hold it, so you can hold a
  button and drag on the trackpad with another finger to drag-and-drop, then
  release to drop.
- A **sensitivity** slider at the top scales pointer speed (0.5–6×, default 2.5).

Moves and scrolls are coalesced client-side and sent on the same ~50 ms grid as
keystrokes, so a drag becomes a few summed deltas rather than a flood of
messages.

## How it works

Everything runs through macOS's `osascript`, in two different language modes.

**Keypresses** use AppleScript (the default mode):

```sh
osascript -e 'tell application "System Events" to key code 36'   # Enter
```

The server turns each keypress op into an AppleScript `keystroke` / `key code`
program (all of the op's actions in one `tell application` block) and runs
`osascript` once per op.

**Mouse** events use JXA — JavaScript for Automation — via `osascript -l
JavaScript`, because AppleScript has no clean way to move the cursor while JXA
can call CoreGraphics (Quartz Event Services: `CGEventCreateMouseEvent` etc.).
Spawning a JXA process per movement would be far too slow (~100 ms startup), so
osakb keeps **one long-lived `osascript` helper** and streams newline-delimited
JSON commands to its stdin — fast enough to feel like a real trackpad. (See
`mouse.js`.)

## HTTP API

- `GET /` — the keyboard web app. (public)
- `GET /nonce` — issue a fresh nonce `{ nonce, ttlMs }`. (public)
- `POST /msg` — the single **authenticated + encrypted** action endpoint. Body is
  an envelope `{ iv, ct, mac }` (see below).

There is one action endpoint; the operation (keypress vs. mouse) lives in the
*encrypted* payload, so the URL never reveals what you sent.

### The `/msg` envelope

```
iv  = base64(random 12-byte ChaCha20 nonce)
ct  = base64(ChaCha20(encKey, iv, counter=1, pad(plaintext)))
mac = hex(HMAC_SHA256(macKey, "POST\n/msg\n" + iv + "\n" + ct))   // encrypt-then-MAC

plaintext = JSON: { "n": <authNonce>, "c": <counter>, "o": [ <op>, ... ] }
op        = { "t":"k", "b": <action obj/array> }   // a keypress
          | { "t":"m", "k":"mv", "dx":<n>, "dy":<n> }   // mouse move (relative)
          | { "t":"m", "k":"cl", "btn":"l"|"r" }        // mouse click (down+up)
          | { "t":"m", "k":"dn", "btn":"l"|"r" }        // mouse button down (hold)
          | { "t":"m", "k":"up", "btn":"l"|"r" }        // mouse button up (release)
          | { "t":"m", "k":"sc", "dy":<n> }             // scroll wheel

pad(x)  = x + spaces, to a multiple of 256 bytes (JSON.parse ignores the spaces)
encKey  = SHA256("osakb-enc:" + secret)
macKey  = SHA256("osakb-mac:" + secret)
```

`o` is an **array** of ops: the client coalesces keystrokes pressed within a short
window into one message (see padding/batching below). The server verifies the MAC
over the ciphertext, decrypts, checks the nonce and counter, then runs the ops in
order.

## Security

osakb gives you **authentication, replay protection, and confidentiality** —
everything except transport-level trust for your mobile app interface.

So a simple eavesdropper in LAN can **NOT** read keystrokes or replay controls,
but if you have a compromised router in your LAN, and an Active Middle Man
attacker in your network when your phone loads the UI from the server, the
attacker can start operating your keyboard and mouse. You do not want that.

1. **Shared secret.** Stored in `~/.osakb/secret` (auto-created, 32 hex chars,
   owner-only perms), kept in memory while running. The phone gets it
   **out-of-band via the QR code** osakb prints on startup, which encodes
   `http://host.local:PORT/#<secret>`. The `#fragment` is **never sent to the
   server**, so the secret stays off the wire; the page reads it from
   `location.hash` and stores it in `localStorage`. (You can also paste it — the
   app prompts if it has none.) Two subkeys are derived from it (one for the
   cipher, one for the MAC).
2. **Confidentiality.** Every action is encrypted with **ChaCha20** before
   sending. A fresh random nonce per message means identical keystrokes never
   produce identical ciphertext, so an eavesdropper can't correlate or count
   repeats. The auth nonce + counter are *inside* the ciphertext too.
   - **Length hiding:** plaintext is padded with spaces to a multiple of 256
     bytes before encryption, so a single letter, a modifier combo, and a mouse
     move all look the same size on the wire (a stream cipher otherwise leaks length).
   - **Timing hiding (light):** sends are quantized to a ~50 ms grid and
     keystrokes in the same window are batched into one message, blurring precise
     inter-keystroke timing. (Full timing privacy would need constant-rate cover
     traffic; this is a deliberate light touch.)
3. **Authentication.** **Encrypt-then-MAC** with HMAC-SHA256 over the ciphertext;
   the server verifies the MAC *before* decrypting. The secret itself is never
   transmitted.
4. **Replay protection.** The server tracks the highest counter seen per nonce
   and rejects anything not strictly greater. Nonces are random 256-bit values,
   in-memory only (a restart invalidates old sessions), expire after 1 hour, and
   are capped to bound memory.

**Crypto in the browser:** `crypto.subtle` (Web Crypto) is only available in a
secure context (HTTPS/localhost), which plain-HTTP LAN pages are not. So the page
ships small, test-vector-verified **pure-JS SHA-256 and ChaCha20** (inlined in
`index.html`), using native Web Crypto for hashing when it *is* available.

**Remaining caveat:** this is application-layer crypto over plain HTTP, not TLS.
It protects the *contents* of requests, but there's no server-certificate trust,
so it can't stop an active man-in-the-middle who can rewrite the page itself. For
a trusted home LAN that's fine; for stronger guarantees, run it behind TLS/VPN.

## Files

- `osakb.js` — HTTP server, routing, auth/crypto, static files.
- `executor.js` — turns key actions into AppleScript and runs `osascript`.
- `mouse.js` — long-lived JXA (`osascript -l JavaScript`) helper that posts
  CoreGraphics mouse-move / click / scroll events.
- `keys.js` — key-code and modifier maps.
- `chacha20.js` — pure-JS ChaCha20 (server side; an identical copy is inlined in
  the page so both ends interoperate).
- `public/index.html` — the mobile web keyboard (self-contained; inlines SHA-256,
  ChaCha20, HMAC, and the UI).
- `public/manifest.webmanifest`, `public/icon-*.png` — home-screen app metadata.
- `vendor/qrcode-terminal/` — vendored QR-code generator (used to print the
  scan-to-connect QR on startup). See [Third-party licenses](#third-party-licenses).

## License

osakb is released under the [MIT License](LICENSE).

### Third-party licenses

This project vendors one third-party module:

- **qrcode-terminal** v0.12.0 — Apache License 2.0. See
  [`vendor/qrcode-terminal/LICENSE`](vendor/qrcode-terminal/LICENSE). The
  original source is retained unmodified, with its copyright and license
  notices intact.
