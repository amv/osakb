'use strict';

// macOS virtual key codes for named special keys.
// Reference: HIToolbox Events.h (kVK_*). Used with AppleScript `key code N`.
const KEY_CODES = {
  return: 36,
  enter: 36,
  tab: 48,
  space: 49,
  delete: 51, // backspace
  backspace: 51,
  escape: 53,
  esc: 53,
  forwarddelete: 117,
  globe: 63, // Fn / 🌐 (kVK_Function) — does little on its own; mirrors the Mac key
  fn: 63,
  home: 115,
  end: 119,
  pageup: 116,
  pagedown: 121,
  left: 123,
  right: 124,
  down: 125,
  up: 126,
  f1: 122,
  f2: 120,
  f3: 99,
  f4: 118,
  f5: 96,
  f6: 97,
  f7: 98,
  f8: 100,
  f9: 101,
  f10: 109,
  f11: 103,
  f12: 111,
};

// AppleScript modifier names accepted in `using {... down}`.
const MODIFIERS = {
  command: 'command down',
  cmd: 'command down',
  option: 'option down',
  alt: 'option down',
  control: 'control down',
  ctrl: 'control down',
  shift: 'shift down',
};

module.exports = { KEY_CODES, MODIFIERS };
