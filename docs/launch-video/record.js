// Renders stage.html frame by frame while driving the real VEN dashboard (in an iframe).
// usage: node record.js --fps 30 --dsf 2 --out ven-launch.mp4 [--shots 10,26,33] [--to 40]
// Needs bin/ven (make build), Playwright with Chromium, and ffmpeg. See README.md.
const { chromium } = require('playwright');
const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const FPS = +arg('fps', 30), DSF = +arg('dsf', 1), OUT = arg('out', '');
const SHOTS = (arg('shots', '') || '').split(',').filter(Boolean).map(Number);
const DIR = __dirname, ORIGIN = 'http://127.0.0.1:7420';

(async () => {
  const [pidFile, launch] = execFileSync(path.join(DIR, 'setup-vault.sh')).toString().trim().split('\n');
  const token = launch.split('#launch=')[1];
  const stopServer = () => { try { process.kill(+fs.readFileSync(pidFile, 'utf8')); } catch {} };

  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: DSF });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGIN });
  await ctx.route(ORIGIN + '/**', async (route) => {
    const req = route.request();
    if (req.url().includes('/__stage.html')) return route.fulfill({ contentType: 'text/html', body: fs.readFileSync(path.join(DIR, 'stage.html')) });
    if (req.method() === 'GET' && new URL(req.url()).pathname.startsWith('/api/')) {
      // rendering is much slower than real time: keep "Updated" at "just now" for the whole video
      const resp = await route.fetch();
      const now = new Date().toISOString();
      const body = (await resp.text()).replace(/("(?:created|updated)At"\s*:\s*")[^"]*"/g, `$1${now}"`);
      return route.fulfill({ response: resp, body });
    }
    if (req.resourceType() !== 'document') return route.continue();
    // let the dashboard render inside the stage iframe (recording only)
    const resp = await route.fetch();
    const headers = { ...resp.headers() };
    delete headers['x-frame-options'];
    if (headers['content-security-policy']) headers['content-security-policy'] = headers['content-security-policy'].replace(/frame-ancestors[^;]*;?/, '');
    return route.fulfill({ response: resp, headers });
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.error('pageerror', e.message));
  await page.goto(ORIGIN + '/__stage.html');
  await page.evaluate((tk) => { document.getElementById('app').src = '/#launch=' + tk; }, token);
  await page.waitForTimeout(1500);

  const duration = +arg('to', 0) || await page.evaluate(() => window.__duration);
  const events = (await page.evaluate(() => window.__events)).sort((a, b) => a.t - b.t);
  const typed = new Map();

  let ff = null;
  if (OUT) {
    ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-i', '-',
      '-vf', 'scale=1920:1080:flags=lanczos', '-c:v', 'libx264', '-preset', 'slow', '-crf', '15', '-pix_fmt', 'yuv420p',
      '-movflags', '+faststart', OUT], { stdio: ['pipe', 'inherit', 'inherit'] });
  }
  const N = Math.round(duration * FPS);
  const shotFrames = new Set(SHOTS.map((s) => Math.round(s * FPS)));
  let mouseReal = false;
  const t0 = Date.now();
  for (let f = 0; f <= N; f++) {
    const t = f / FPS;
    const cur = await page.evaluate((t) => window.__render(t), t);
    if (cur.real) { await page.mouse.move(cur.x, cur.y); mouseReal = true; }
    else if (mouseReal) { await page.mouse.move(1919, 1079); mouseReal = false; }
    let acted = false;
    for (const e of events) {
      if (e.kind === 'click' && e.t <= t && e.t > t - 1 / FPS) { await page.mouse.down(); await page.mouse.up(); acted = true; }
      if (e.kind === 'type' && t >= e.t) {
        const done = typed.get(e) || 0;
        const want = Math.min(e.text.length, Math.ceil(e.text.length * Math.min(1, (t - e.t) / e.dur)));
        if (want > done) {
          for (const ch of e.text.slice(done, want)) {
            if (ch === '\n') await page.keyboard.press('Enter'); else await page.keyboard.insertText(ch);
          }
          typed.set(e, want); acted = true;
        }
      }
    }
    if (acted) { await page.waitForTimeout(40); await page.evaluate((t) => window.__render(t), t); }
    if (ff || shotFrames.has(f)) {
      const buf = await page.screenshot({ type: 'png' });
      if (ff && !ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once('drain', r));
      if (shotFrames.has(f)) fs.writeFileSync(path.join(DIR, `shot-${t.toFixed(2)}.png`), buf);
    }
    if (f % (FPS * 5) === 0) console.log(`t=${t.toFixed(1)}s  frame ${f}/${N}  ${((Date.now() - t0) / 1000).toFixed(0)}s elapsed`);
  }
  if (ff) { ff.stdin.end(); await new Promise((r) => ff.on('close', r)); }
  await browser.close();
  stopServer();
  console.log('done');
})();
