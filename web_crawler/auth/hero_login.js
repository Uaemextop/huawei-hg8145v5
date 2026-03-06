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
 *
 * HAR Analysis (HTTPToolkit_2026-03-03_18-12.har):
 *   - POST /userLogin returns 200 (not redirect) when browser carries:
 *       AKA_A2=A          — Akamai Bot Manager "real browser" flag
 *       ak_bmsc=<value>   — Akamai browser fingerprint (set by sensor JS
 *                           in a previous session, persists across loads)
 *       _abck=..~0~..     — Akamai sensor validated (achieved via interactions)
 *   - Response body contains:
 *       var gateway = 'https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=TOKEN';
 *       window.location.href = gateway;
 *   - ajaxUserExistedServlet returns 400 for roaming accounts (normal).
 *   - ajaxUserRoam must be called before /userLogin for roaming accounts.
 *   - lenovoid.lang must be en_US in the POST body.
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
// Akamai persistent-cookie values extracted from the HAR session
// (HTTPToolkit_2026-03-03_18-12.har) that produced a successful login.
//
// These cookies are normally set by Akamai's Bot Manager JavaScript in a
// previous browsing session and persist across page loads.  A fresh headless
// browser session does not have them; injecting them replicates the trusted-
// browser state that allows ajaxUserRoam and /userLogin to succeed.
// ---------------------------------------------------------------------------
const AKAMAI_AKA_A2 = 'A';
const AKAMAI_AK_BMSC =
  'FFF50944FF5DF76EA15E9504FC87731A~000000000000000000000000000000~' +
  'YAAQxgbSF6F6PK2cAQAAgucbth9IVyH1MoPCd8hkl74hHCZGaOSDRv/xaTkhysjlNDrb' +
  'zbD04RrXCngS5K9OoVSc+0f7I0/UvtFjzTHhkJdKKAtuBpihzXQcJ6TmvLEozh2T/ss' +
  'TemQQEDLQHiHJRu5Pl22/L4pI+K2ZGvV93vGqPGC+u0cnzweJYcH2vE5Akfjc3c++Sfu' +
  'JZuZsEjKoNKnBQGNDBwQCTP2XmX6b5bRd9VHx0d84VG05hrPy32S+fXKEkuh7sE586Eb' +
  'vioOrTWsdvFjFKGVkm/2LXud3tzB3QF54RVq7SbcQlHZUqNvDzAGIuESzqz/gK6Sfm2q' +
  'ZU+y7MqSoCG53P/rqejv8qWELajKd7n31zMyIznc4P8gUIUsKjYIiD/m5Ghj2bKhEBro' +
  'XFfWuJF4QoBr1ifvO5SrB';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract lenovoid.wust=<token> from a URL or HTML string. */
function findWust(text) {
  if (!text) return null;
  const m = text.match(/lenovoid\.wust=([^&\s"'<>\\]+)/);
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
    // Step 1.5: Inject Akamai persistent cookies from the trusted HAR session.
    //
    // HAR analysis confirmed the GET preLogin request in the real browser
    // ALREADY carried AKA_A2=A and ak_bmsc (set in a previous session).
    // A fresh Hero session has neither.  Injecting them replicates the
    // trusted-browser state required for ajaxUserRoam and /userLogin.
    //
    // AKA_A2=A  — Akamai Bot Manager "real browser" certification flag.
    // ak_bmsc   — Akamai browser fingerprint token (non-httpOnly, JS-settable).
    // -----------------------------------------------------------------------
    try {
      const akaA2Js  = JSON.stringify(AKAMAI_AKA_A2);
      const akBmscJs = JSON.stringify(AKAMAI_AK_BMSC);
      await hero.activeTab.getJsValue(
        `(() => {
          document.cookie = 'AKA_A2=' + ${akaA2Js} + '; path=/; secure';
          document.cookie = 'ak_bmsc=' + ${akBmscJs} + '; path=/; secure';
        })()`
      );
      process.stderr.write('[Hero] Akamai cookies (AKA_A2, ak_bmsc) injected ✓\n');
    } catch (_) { /* ignore */ }

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

      // Ensure lenovoid.lang is en_US (HAR shows this is required).
      try {
        await hero.activeTab.getJsValue(
          `document.querySelectorAll('input[name="lenovoid.lang"]').forEach(e => e.value = 'en_US')`
        );
      } catch (_) { /* ignore */ }

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
      // Step 5b: Direct submission for roaming account.
      //
      // HAR flow for this account (eduardo@uaemex.top is a roaming user):
      //   1. ajaxUserExistedServlet → 400  (expected for roaming accounts)
      //   2. ajaxUserRoam → 200 {"resultCode":0}  (registers roaming intent)
      //   3. POST /userLogin → 200 with gateway JS containing WUST
      //
      // We call ajaxUserRoam explicitly before submitting the form so the
      // server records the roaming user's intent (without it, /userLogin
      // may return an authentication error for this email).
      // -----------------------------------------------------------------------
      process.stderr.write('[Hero] Calling ajaxUserRoam to register roaming user…\n');

      const emailEncoded = encodeURIComponent(email);
      const cbEncoded = encodeURIComponent(
        loginUrl.match(/lenovoid\.cb=([^&]+)/)?.[1] ||
        'https://lsa.lenovo.com/Tips/lenovoIdSuccess.html'
      );
      const roamUrl = `https://passport.lenovo.com/glbwebauthnv6/ajaxUserRoam?username=${emailEncoded}&areacode=`;
      const existUrl = `https://passport.lenovo.com/glbwebauthnv6/ajaxUserExistedServlet?username=${emailEncoded}&lenovoid.action=uilogin&lenovoid.realm=lmsaclient&lenovoid.lang=en_US&lenovoid.cb=${cbEncoded}&lenovoid.ctx=null`;

      let roamResult = null;
      try {
        roamResult = await hero.activeTab.getJsValue(
          `(async () => {
            // First call ajaxUserExistedServlet (SPA does this before roam).
            try {
              await fetch(${JSON.stringify(existUrl)}, {
                method: 'POST', credentials: 'include',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                           'X-Requested-With': 'XMLHttpRequest',
                           'Accept': 'application/json, text/javascript, */*; q=0.01' },
                body: ''
              });
            } catch(_) {}
            // Then call ajaxUserRoam.
            const r = await fetch(${JSON.stringify(roamUrl)}, {
              method: 'POST', credentials: 'include',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                         'X-Requested-With': 'XMLHttpRequest',
                         'Accept': 'application/json, text/javascript, */*; q=0.01' },
              body: ''
            });
            const text = await r.text();
            return { status: r.status, body: text };
          })()`
        );
      } catch (_) { /* ignore */ }
      process.stderr.write(`[Hero] ajaxUserRoam result: ${JSON.stringify(roamResult)}\n`);

      // -----------------------------------------------------------------------
      // Compute double-MD5 hash (matches login.js nextHandler).
      // -----------------------------------------------------------------------
      const crypto = require('crypto');
      const inner = crypto.createHash('md5').update(password).digest('hex').toUpperCase();
      const hashed = crypto.createHash('md5').update(inner).digest('hex').toUpperCase();

      // -----------------------------------------------------------------------
      // Collect reCAPTCHA Enterprise token.
      // -----------------------------------------------------------------------
      process.stderr.write('[Hero] Obtaining reCAPTCHA Enterprise token…\n');
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
        if (gt) process.stderr.write('[Hero] reCAPTCHA Enterprise token obtained ✓\n');
      } catch (_) { /* reCAPTCHA unavailable */ }

      // -----------------------------------------------------------------------
      // Read bid (Fingerprint2 browser ID).
      // -----------------------------------------------------------------------
      let bid = '';
      try {
        bid = await hero.activeTab.getJsValue(
          `(() => {
            const el = document.querySelector('.jsBid, input[name="bid"]');
            return el ? el.value : '';
          })()`
        ) || '';
      } catch (_) { /* bid unavailable */ }

      // -----------------------------------------------------------------------
      // Fill all form fields and submit via form.submit().
      //
      // form.submit() triggers a real browser navigation with:
      //   Sec-Fetch-Mode: navigate   (required by Akamai for /userLogin)
      //   Sec-Fetch-User: ?1
      //   Content-Type: application/x-www-form-urlencoded
      // Unlike XHR which sends Sec-Fetch-Mode: cors and returns 504.
      // -----------------------------------------------------------------------
      process.stderr.write('[Hero] Submitting login form…\n');
      const emailJs  = JSON.stringify(email);
      const hashedJs = JSON.stringify(hashed);
      const gtJs     = JSON.stringify(gt);
      const bidJs    = JSON.stringify(bid);
      try {
        await hero.activeTab.getJsValue(
          `(() => {
            const f = document.querySelector('.loginClass2 form');
            if (!f) return false;
            // Set all required fields exactly as the HAR shows.
            f.querySelectorAll('input[name="username"],.emailAddressInput')
              .forEach(e => { e.value = ${emailJs}; });
            f.querySelectorAll('input[name="password"]')
              .forEach(e => { e.value = ${hashedJs}; });
            f.querySelectorAll('input[name="loginfinish"]')
              .forEach(e => { e.value = '1'; });
            f.querySelectorAll('input[name="lenovoid.lang"]')
              .forEach(e => { e.value = 'en_US'; });
            let g = f.querySelector('input[name="gt"]');
            if (!g) {
              g = document.createElement('input');
              g.type = 'hidden'; g.name = 'gt';
              f.appendChild(g);
            }
            g.value = ${gtJs};
            const bidEl = f.querySelector('.jsBid, input[name="bid"]');
            if (bidEl && ${bidJs}) bidEl.value = ${bidJs};
            f.submit();
            return true;
          })()`
        );
        process.stderr.write('[Hero] form.submit() called ✓\n');
      } catch (e) {
        // Navigation exception is normal — form.submit() triggers navigation.
        process.stderr.write(`[Hero] form.submit() navigation: ${e.message}\n`);
      }
    }

    // -----------------------------------------------------------------------
    // Step 6: Wait for the WUST redirect (up to 90 s).
    //
    // After a successful POST to /userLogin the server returns 200 with an
    // HTML body containing:
    //   var gateway = 'https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=TOKEN';
    //   window.location.href = gateway;
    // The browser executes this JS and navigates.  hero.url then shows the
    // lsa.lenovo.com URL.  We also look inside the page body in case the
    // browser is still rendering the /userLogin response.
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

      // Also check the page body for the gateway URL (present on the
      // /userLogin 200 response before JS navigation completes).
      if (currentUrl.includes('userLogin') || currentUrl.includes('preLogin')) {
        try {
          const bodyWust = await hero.activeTab.getJsValue(
            `(() => {
              const m = document.documentElement.innerHTML.match(/lenovoid\\.wust=([^&'"\\s]+)/);
              return m ? m[1] : null;
            })()`
          );
          if (bodyWust) {
            process.stderr.write(`[Hero] WUST found in page body ✓\n`);
            process.stdout.write(JSON.stringify({ wust: bodyWust }) + '\n');
            return true;
          }
        } catch (_) { /* navigation in progress */ }
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
