'use strict';

// Mouse control for macOS, dependency-free.
//
// AppleScript can't move the cursor, but JavaScript for Automation (JXA) can call
// CoreGraphics (Quartz Event Services) to synthesize mouse-move / click / scroll
// events. Spawning `osascript -l JavaScript` per movement would be far too slow
// (JXA startup is ~100ms+), so we keep ONE long-lived helper process and stream
// newline-delimited JSON commands to its stdin. Requires Accessibility
// permission (same as the keyboard).

const { spawn } = require('child_process');

// JXA daemon: read commands from stdin forever, post CG events for each.
// Command shapes: {k:'mv',dx,dy} relative move | {k:'cl',btn:'l'|'r'} click |
// {k:'dn'|'up',btn} button hold/release | {k:'sc',dy} scroll. Event-type
// constants are numeric (kCG* enums aren't reliably bridged as symbols):
// mouseMoved=5, L down/up=1/2, R down/up=3/4, L/R dragged=6/7. We track which
// button is held so a move becomes a drag (so press-hold + move = drag-and-drop).
const DAEMON = `
ObjC.import('Foundation');
ObjC.import('CoreGraphics');
function loc(){ return $.CGEventGetLocation($.CGEventCreate($())); }
function post(ev){ $.CGEventPost(0, ev); }
var leftDown = false, rightDown = false;
function handle(line){
  line = line.trim();
  if(!line) return;
  var c;
  try { c = JSON.parse(line); } catch(e){ return; }
  if(c.k === 'mv'){
    var l = loc(); var mp = $.CGPointMake(l.x + c.dx, l.y + c.dy);
    // While a button is held, send the matching drag event instead of a plain move.
    var type = leftDown ? 6 : (rightDown ? 7 : 5);
    var btn = rightDown ? 1 : 0;
    post($.CGEventCreateMouseEvent($(), type, mp, btn));
  } else if(c.k === 'cl'){
    var l2 = loc(); var p = $.CGPointMake(l2.x, l2.y);
    var right = c.btn === 'r';
    post($.CGEventCreateMouseEvent($(), right ? 3 : 1, p, right ? 1 : 0));
    post($.CGEventCreateMouseEvent($(), right ? 4 : 2, p, right ? 1 : 0));
  } else if(c.k === 'dn'){
    var ld = loc(); var rd = c.btn === 'r';
    if(rd) rightDown = true; else leftDown = true;
    post($.CGEventCreateMouseEvent($(), rd ? 3 : 1, $.CGPointMake(ld.x, ld.y), rd ? 1 : 0));
  } else if(c.k === 'up'){
    var lu = loc(); var ru = c.btn === 'r';
    if(ru) rightDown = false; else leftDown = false;
    post($.CGEventCreateMouseEvent($(), ru ? 4 : 2, $.CGPointMake(lu.x, lu.y), ru ? 1 : 0));
  } else if(c.k === 'sc'){
    post($.CGEventCreateScrollWheelEvent($(), 0, 1, c.dy));
  }
}
var fh = $.NSFileHandle.fileHandleWithStandardInput;
var NL = String.fromCharCode(10);
var buf = '';
while(true){
  var data = fh.availableData;
  if(!data || data.length === 0) break;       // EOF -> exit when parent closes stdin
  buf += $.NSString.alloc.initWithDataEncoding(data, 4).js;  // NSUTF8StringEncoding = 4
  var parts = buf.split(NL);
  buf = parts.pop();                          // keep any partial trailing line
  for(var i = 0; i < parts.length; i++) handle(parts[i]);
}
`;

let helper = null;

function ensureHelper() {
  if (helper && helper.stdin && helper.stdin.writable) return helper;
  helper = spawn('osascript', ['-l', 'JavaScript', '-e', DAEMON], {
    stdio: ['pipe', 'ignore', 'pipe'],
  });
  helper.stderr.on('data', (d) => console.error('[mouse] ' + d.toString().trim()));
  helper.on('exit', () => { helper = null; });
  helper.on('error', (e) => { console.error('[mouse] helper error:', e.message); helper = null; });
  return helper;
}

// Fire-and-forget a single mouse command. Returns synchronously.
function send(cmd) {
  if (process.platform !== 'darwin') {
    console.log('[dry-run, not macOS] mouse ' + JSON.stringify(cmd));
    return { dryRun: true, cmd };
  }
  try {
    ensureHelper().stdin.write(JSON.stringify(cmd) + '\n');
  } catch (e) {
    helper = null;
    console.error('[mouse] write failed:', e.message);
  }
  return { ok: true };
}

module.exports = { send };
