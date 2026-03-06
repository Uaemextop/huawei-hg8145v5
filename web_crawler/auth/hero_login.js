#!/usr/bin/env node
/**
 * hero_login.js — ulixee/Hero-based Lenovo ID login for Akamai bypass.
 *
 * Hero (https://github.com/ulixee/hero) uses a proprietary agent protocol
 * with a built-in Human Emulator that adds realistic mouse movements, typing
 * delays, and scroll behaviour.  Because it communicates with the browser via
 * a custom CDP-over-WebSocket tunnel (not the standard WebDriver protocol),
 * it avoids the automation fingerprints that Akamai Bot Manager detects in
 * Playwright and Selenium.
 *
 * Usage (called from lenovo_id.py via subprocess):
 *   node hero_login.js <login_url> <email> <password>
 *
 * Environment:
 *   HERO_HEADLESS   - "false" to run with a visible browser (default: true)
 *   HERO_TIMEOUT    - milliseconds to wait for password field (default: 30000)
 *
 * Outputs a single JSON line to stdout:
 *   {"wust": "<token>"}        — success
 *   {"error": "<message>"}     — failure
 *
 * Exit codes: 0 = WUST obtained, 1 = failure.
 *
 * Install:
 *   cd web_crawler/auth && npm install
 */

'use strict';

// In CI / container environments the Chrome setuid sandbox binary is not
// owned by root (chmod 4755).  Setting ULX_NO_CHROME_SANDBOX before the
// @ulixee packages are loaded causes their env module to pick up the flag
// and pass --no-sandbox / --disable-setuid-sandbox to Chrome at launch.
process.env.ULX_NO_CHROME_SANDBOX = process.env.ULX_NO_CHROME_SANDBOX ?? '1';

const [, , loginUrl, email, password] = process.argv;

if (!loginUrl || !email || !password) {
  process.stderr.write(
    'Usage: node hero_login.js <login_url> <email> <password>\n'
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract lenovoid.wust=<token> from a URL or HTML string. */
function findWust(text) {
  if (!text) return null;
  const m = text.match(/lenovoid\.wust=([^&\s"'<>]+)/);
  return m ? m[1] : null;
}

/** Sleep for the given number of milliseconds. */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Main login flow
// ---------------------------------------------------------------------------

async function heroLogin() {
  // Lazy-load Hero so that the script fails fast with a clear error if the
  // npm dependency has not been installed yet.
  let Hero;
  try {
    Hero = require('@ulixee/hero-playground');
  } catch (e) {
    process.stdout.write(
      JSON.stringify({
        error:
          '@ulixee/hero-playground not installed.  ' +
          'Run: cd web_crawler/auth && npm install',
      }) + '\n'
    );
    process.exit(1);
  }

  const headless =
    (process.env.HERO_HEADLESS || 'true').toLowerCase() !== 'false';
  const pwTimeout = parseInt(process.env.HERO_TIMEOUT || '30000', 10);

  const hero = new Hero({
    // Emulate a realistic Windows 10 Chrome user agent.
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
      'AppleWebKit/537.36 (KHTML, like Gecko) ' +
      'Chrome/120.0.0.0 Safari/537.36',
    viewport: { width: 1280, height: 800 },
    locale: 'es-419',
    timezoneId: 'America/Mexico_City',
    showChrome: !headless,
    // Disable Chrome setuid sandbox for CI / container environments where
    // the chrome-sandbox binary is not owned by root (chmod 4755).
    noChromeSandbox: true,
  });

  try {
    // Capture navigation events so we can detect the WUST redirect even if
    // the page navigates away before we can read hero.url.
    let capturedWust = null;
    hero.activeTab.on('resource', resource => {
      try {
        const url = resource.url;
        if (url && (url.includes('lenovoIdSuccess') || url.includes('lenovoid.wust'))) {
          const w = findWust(url);
          if (w && !capturedWust) {
            capturedWust = w;
            process.stderr.write(`[Hero] WUST captured from navigation: ${url.slice(0, 120)}\n`);
          }
        }
      } catch (_) { /* ignore event errors */ }
    });

    // -----------------------------------------------------------------------
    // Step 1: Load the Lenovo ID login page.
    // -----------------------------------------------------------------------
    process.stderr.write(`[Hero] Navigating to login page: ${loginUrl.slice(0, 100)}\n`);
    await hero.goto(loginUrl);

    // Wait for the page to reach a stable rendering state.  This also gives
    // the Akamai bmak sensor and reCAPTCHA Enterprise scripts time to
    // initialise and execute their JS challenges.
    await hero.waitForPaintingStable();

    // Initial wait for Akamai sensor_data accumulation.
    // The _abck cookie starts as ~-1~ (unvalidated).  Human Emulator
    // interactions (typing, clicking) are required to advance it to ~0~.
    await sleep(20000);

    // -----------------------------------------------------------------------
    // Step 2: Fill in the email address.
    // Hero DOM interaction uses $click() and $type() (the $ methods trigger
    // real browser interactions via the Human Emulator).
    // -----------------------------------------------------------------------
    process.stderr.write('[Hero] Filling email…\n');
    let emailFilled = false;
    const emailSelectors = [
      '#emailOrPhoneInput',
      'input.noneTheme1',
      'input[type="text"]:not([style*="display:none"])',
    ];
    for (const sel of emailSelectors) {
      try {
        const el = hero.querySelector(sel);
        await el.$waitForVisible({ timeoutMs: 8000 });
        await el.$click();
        await sleep(400);
        await el.$type(email);
        emailFilled = true;
        process.stderr.write(`[Hero] Email filled via selector: ${sel}\n`);
        break;
      } catch (_) { /* try next selector */ }
    }
    if (!emailFilled) {
      process.stdout.write(JSON.stringify({ error: 'Email field not found' }) + '\n');
      return false;
    }

    // -----------------------------------------------------------------------
    // Step 2.5: Wait for _abck to validate BEFORE clicking Next.
    //
    // Critical timing fix: the Akamai sensor updates _abck from ~-1~ to ~0~
    // based on human-like interactions (mouse, keyboard).  The AJAX call to
    // ajaxUserExistedServlet is made immediately when we click Next.  If we
    // click before _abck=~0~, Akamai blocks the AJAX and the SPA never
    // transitions to the password step.  Polling here ensures we click only
    // after the cookie is validated.
    // -----------------------------------------------------------------------
    process.stderr.write('[Hero] Waiting for _abck cookie to validate (target: ~0~)…\n');
    let abckValidated = false;
    for (let i = 0; i < 25; i++) {
      try {
        const abck = await hero.activeTab.getJsValue(
          `document.cookie.includes('_abck') && !document.cookie.match(/_abck=[^~]*~-1~/) || false`
        );
        if (abck === true) {
          abckValidated = true;
          process.stderr.write('[Hero] _abck validated ✓\n');
          break;
        }
      } catch (_) { /* ignore */ }
      await sleep(2000);
    }
    if (!abckValidated) {
      process.stderr.write('[Hero] _abck not validated after 50s — proceeding anyway\n');
    }

    await sleep(500);

    // -----------------------------------------------------------------------
    // Step 3: Click the "Next" / "Siguiente" button (SPA step A).
    // Now that _abck is validated, the AJAX email-validation request
    // (ajaxUserExistedServlet) should succeed and the SPA will transition
    // to the password step.
    // -----------------------------------------------------------------------
    process.stderr.write('[Hero] Clicking Next button…\n');
    const nextSelectors = [
      'div.loginClass1 button',
      'button[type="submit"]',
    ];
    let nextClicked = false;
    for (const sel of nextSelectors) {
      try {
        const btn = hero.querySelector(sel);
        await btn.$waitForVisible({ timeoutMs: 4000 });
        await btn.$click();
        nextClicked = true;
        break;
      } catch (_) { /* try next */ }
    }
    if (!nextClicked) {
      await hero.keyboard.press('Enter');
    }

    // -----------------------------------------------------------------------
    // Step 4: Wait for the password field to appear (SPA step B).
    // With _abck=~0~, the AJAX should go through.  Allow up to 60s for the
    // server-side email validation and SPA transition.
    // -----------------------------------------------------------------------
    process.stderr.write('[Hero] Waiting for password field (up to 60 s)…\n');
    let passwordAppeared = false;
    for (let i = 0; i < 60; i++) {
      try {
        const vis = await hero.activeTab.getJsValue(
          `(() => { const e = document.querySelector('#emailOrPhonePswInput'); return !!(e && e.offsetParent !== null); })()`
        );
        if (vis === true) {
          passwordAppeared = true;
          process.stderr.write(`[Hero] Password field appeared at t=${i}s ✓\n`);
          break;
        }
      } catch (_) { /* ignore */ }
      await sleep(1000);
    }
    if (!passwordAppeared) {
      process.stderr.write('[Hero] Password field did not appear — using direct form submission\n');
    }

    if (passwordAppeared) {
      // -----------------------------------------------------------------------
      // Step 5a: Fill password and submit (normal SPA flow).
      // -----------------------------------------------------------------------
      process.stderr.write('[Hero] Filling password…\n');
      const pwEl = hero.querySelector('#emailOrPhonePswInput');
      await pwEl.$click();
      await sleep(300);
      await pwEl.$type(password);

      // Wait for reCAPTCHA Enterprise token and Akamai bid to be populated.
      await sleep(5000);

      // Click submit (loadingBtnHide class or any button in loginClass2).
      process.stderr.write('[Hero] Clicking submit…\n');
      const submitSelectors = [
        'button.loadingBtnHide',
        'div.loginClass2 button[type="submit"]',
        'div.loginClass2 button',
      ];
      let submitClicked = false;
      for (const sel of submitSelectors) {
        try {
          const btn = hero.querySelector(sel);
          await btn.$waitForVisible({ timeoutMs: 4000 });
          await btn.$click();
          submitClicked = true;
          break;
        } catch (_) { /* try next */ }
      }
      if (!submitClicked) {
        await hero.keyboard.press('Enter');
      }
    } else {
      // -----------------------------------------------------------------------
      // Step 5b: Direct form submission fallback.
      //
      // When the SPA password step doesn't appear (AJAX still blocked), bypass
      // it by posting the loginClass2 form directly via XMLHttpRequest.
      // XHR gives us responseURL (the final URL after all redirects) without
      // page navigation, so we can extract the WUST even if the redirect goes
      // cross-origin to lsa.lenovo.com.
      // -----------------------------------------------------------------------
      process.stderr.write('[Hero] Attempting direct form submission via XHR…\n');

      // Compute double-MD5 hash in Node.js (matches login.js nextHandler).
      const crypto = require('crypto');
      const inner = crypto.createHash('md5').update(password).digest('hex').toUpperCase();
      const hashed = crypto.createHash('md5').update(inner).digest('hex').toUpperCase();

      // Collect reCAPTCHA Enterprise token via the browser's grecaptcha object.
      let gt = '';
      try {
        gt = await hero.activeTab.getJsValue(
          `(async () => {
            if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {
              try {
                return await grecaptcha.enterprise.execute(
                  '6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub',
                  {action: 'LOGIN'}
                );
              } catch(e) { return ''; }
            }
            return '';
          })()`
        ) || '';
        if (gt) process.stderr.write('[Hero] reCAPTCHA Enterprise token obtained\n');
      } catch (_) { /* reCAPTCHA unavailable */ }

      // Read bid (Fingerprint2 browser ID) from the page.
      let bid = '';
      try {
        bid = await hero.activeTab.getJsValue(
          `(() => {
            const el = document.querySelector('.jsBid, input[name="bid"]');
            return el ? el.value : '';
          })()`
        ) || '';
      } catch (_) { /* bid unavailable */ }

      // Fill and submit via XHR so we get responseURL after redirects.
      const emailJs = JSON.stringify(email);
      const hashedJs = JSON.stringify(hashed);
      const gtJs = JSON.stringify(gt);
      const bidJs = JSON.stringify(bid);

      let xhrResult = null;
      for (let attempt = 1; attempt <= 3 && !xhrResult; attempt++) {
        if (attempt > 1) {
          process.stderr.write(`[Hero] XHR retry ${attempt}/3…\n`);
          await sleep(5000);
        }
        try {
          xhrResult = await hero.activeTab.getJsValue(
            `(async () => {
              const f = document.querySelector('.loginClass2 form');
              if (!f) return { error: 'form not found' };

              // Build the POST body from form fields.
              const params = new URLSearchParams(new FormData(f));
              // Override with our values.
              params.set('username', ${emailJs});
              params.set('password', ${hashedJs});
              params.set('loginfinish', '1');
              params.set('gt', ${gtJs});
              if (${bidJs}) params.set('bid', ${bidJs});

              // Use XHR so we get responseURL after cross-origin redirects.
              return await new Promise((resolve) => {
                const xhr = new XMLHttpRequest();
                xhr.timeout = 90000;
                xhr.onload = function() {
                  resolve({ responseURL: xhr.responseURL, status: xhr.status,
                             body: xhr.responseText.substring(0, 300) });
                };
                xhr.onerror = function() {
                  resolve({ error: 'xhr network error', status: xhr.status });
                };
                xhr.ontimeout = function() {
                  resolve({ error: 'xhr timeout' });
                };
                xhr.open('POST', f.action, true);
                xhr.withCredentials = true;
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.send(params.toString());
              });
            })()`
          );
        } catch (e) {
          process.stderr.write(`[Hero] XHR error (attempt ${attempt}): ${e.message}\n`);
        }
      }

      if (xhrResult) {
        process.stderr.write(`[Hero] XHR result: ${JSON.stringify(xhrResult).slice(0, 200)}\n`);
        const xhrWust = findWust(xhrResult.responseURL || '') ||
                        findWust(xhrResult.body || '');
        if (xhrWust) {
          process.stdout.write(JSON.stringify({ wust: xhrWust }) + '\n');
          return true;
        }
      }

      // Fallback: also try the traditional form.submit() after XHR (maybe
      // the XHR is blocked by CORS but form navigation goes through).
      process.stderr.write('[Hero] Trying form.submit() as final fallback…\n');
      try {
        await hero.activeTab.getJsValue(
          `(() => {
            const f = document.querySelector('.loginClass2 form');
            if (!f) return false;
            f.querySelectorAll('input[name="username"],.emailAddressInput').forEach(e => e.value = ${emailJs});
            f.querySelectorAll('input[name="password"]').forEach(e => e.value = ${hashedJs});
            f.querySelectorAll('input[name="loginfinish"]').forEach(e => e.value = '1');
            let g = f.querySelector('input[name="gt"]');
            if (!g) { g = document.createElement('input'); g.type='hidden'; g.name='gt'; f.appendChild(g); }
            g.value = ${gtJs};
            const bidEl = f.querySelector('.jsBid,input[name="bid"]');
            if (bidEl && ${bidJs}) bidEl.value = ${bidJs};
            f.submit();
            return true;
          })()`
        );
      } catch (_) { /* navigation interrupts evaluate */ }
    }

    // -----------------------------------------------------------------------
    // Step 6: Wait for the WUST redirect (up to 90 s).
    // -----------------------------------------------------------------------
    process.stderr.write('[Hero] Waiting for WUST redirect…\n');
    for (let i = 0; i < 90; i++) {
      // Check if event handler already captured a WUST.
      if (capturedWust) {
        process.stdout.write(JSON.stringify({ wust: capturedWust }) + '\n');
        return true;
      }

      let currentUrl = '';
      try {
        currentUrl = await hero.url;
      } catch (_) { /* ignore */ }

      const wust = findWust(currentUrl);
      if (wust) {
        process.stdout.write(JSON.stringify({ wust }) + '\n');
        return true;
      }

      if (
        currentUrl.includes('lenovoIdSuccess') ||
        currentUrl.includes('lmsa.lenovo.com')
      ) {
        // Reached callback page but WUST not in URL — check body
        break;
      }

      await sleep(1000);
    }

    // Last resort: check the current page body for a WUST token.
    try {
      const bodyHtml = await hero.activeTab.getJsValue('document.documentElement.innerHTML') || '';
      const wust = findWust(bodyHtml) || findWust(await hero.url);
      if (wust) {
        process.stdout.write(JSON.stringify({ wust }) + '\n');
        return true;
      }
    } catch (_) { /* ignore */ }

    if (capturedWust) {
      process.stdout.write(JSON.stringify({ wust: capturedWust }) + '\n');
      return true;
    }

    let finalUrl = '';
    try { finalUrl = await hero.url; } catch (_) { /* ignore */ }
    process.stdout.write(
      JSON.stringify({ error: 'WUST not found after login', url: finalUrl }) + '\n'
    );
    return false;
  } finally {
    try { await hero.close(); } catch (_) { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

heroLogin()
  .then(ok => process.exit(ok ? 0 : 1))
  .catch(err => {
    process.stdout.write(JSON.stringify({ error: err.message || String(err) }) + '\n');
    process.exit(1);
  });
