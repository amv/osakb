'use strict';

const { execFile } = require('child_process');
const { KEY_CODES, MODIFIERS } = require('./keys');

// Escape a string for safe embedding inside an AppleScript double-quoted literal.
function asString(str) {
  return '"' + String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function resolveModifiers(modifiers) {
  if (!Array.isArray(modifiers) || modifiers.length === 0) return '';
  const parts = [];
  for (const m of modifiers) {
    const key = String(m).toLowerCase();
    if (!MODIFIERS[key]) throw new Error(`Unknown modifier: ${m}`);
    parts.push(MODIFIERS[key]);
  }
  return ' using {' + parts.join(', ') + '}';
}

// Convert a single action object into one or more AppleScript statements.
// Supported actions:
//   { text: "hello" }                          -> type literal text
//   { text: "s", modifiers: ["command"] }      -> type text with modifiers (e.g. Cmd-S)
//   { key: "return" }                          -> named special key (see keys.js)
//   { code: 36 }                               -> raw macOS key code
//   { key: "left", modifiers: ["command"] }    -> special key with modifiers
//   { delay: 500 }                             -> wait, milliseconds
function actionToScript(action) {
  if (action == null || typeof action !== 'object') {
    throw new Error('Action must be an object');
  }

  if ('delay' in action) {
    const ms = Number(action.delay);
    if (!Number.isFinite(ms) || ms < 0) throw new Error('Invalid delay');
    return [`delay ${ms / 1000}`];
  }

  const mods = resolveModifiers(action.modifiers);

  if ('text' in action) {
    return [`keystroke ${asString(action.text)}${mods}`];
  }

  if ('code' in action) {
    const code = Number(action.code);
    if (!Number.isInteger(code) || code < 0) throw new Error('Invalid key code');
    return [`key code ${code}${mods}`];
  }

  if ('key' in action) {
    const name = String(action.key).toLowerCase();
    const code = KEY_CODES[name];
    if (code === undefined) throw new Error(`Unknown key: ${action.key}`);
    return [`key code ${code}${mods}`];
  }

  throw new Error('Action has no recognized field (text/key/code/delay)');
}

// Build a complete AppleScript document from a list of actions.
function buildScript(actions) {
  if (!Array.isArray(actions) || actions.length === 0) {
    throw new Error('actions must be a non-empty array');
  }
  const lines = ['tell application "System Events"'];
  for (const action of actions) {
    for (const stmt of actionToScript(action)) lines.push('  ' + stmt);
  }
  lines.push('end tell');
  return lines.join('\n');
}

// Run a list of actions on the host. Returns a Promise.
function run(actions) {
  const script = buildScript(actions);
  return new Promise((resolve, reject) => {
    if (process.platform !== 'darwin') {
      // Allow development on other platforms: log instead of executing.
      console.log('[dry-run, not macOS] would execute AppleScript:\n' + script);
      return resolve({ dryRun: true, script });
    }
    execFile('osascript', ['-e', script], (err, stdout, stderr) => {
      if (err) {
        err.stderr = stderr;
        return reject(err);
      }
      resolve({ stdout, stderr });
    });
  });
}

module.exports = { run, buildScript, actionToScript };
