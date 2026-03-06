/**
 * Ulixee Hero login script for passport.lenovo.com.
 *
 * Performs the Lenovo ID OAuth flow in a real-looking browser that bypasses
 * Akamai Bot Manager by emulating genuine browser TLS fingerprints, HTTP/2
 * settings, and DOM APIs.
 *
 * Usage:
 *   echo '<login_url>\n<email>\n<password>' | node hero_login.mjs
 *
 * Credentials are received via stdin (one value per line) to avoid
 * exposing them in process listings.
 *
 * On success prints to stdout:
 *   WUST=<token>
 *
 * On failure exits with code 1 and prints diagnostics to stderr.
 */

import Hero from "@ulixee/hero-playground";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

// Read credentials from stdin (piped by the parent Python process).
const stdinData = readFileSync(0, "utf8").trim();
const [loginUrl, email, password] = stdinData.split("\n");

if (!loginUrl || !email || !password) {
  process.stderr.write(
    "Usage: echo '<login_url>\\n<email>\\n<password>' | node hero_login.mjs\n",
  );
  process.exit(1);
}

// reCAPTCHA Enterprise site key used by passport.lenovo.com.
const RECAPTCHA_SITE_KEY = "6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub";

// Akamai sensor requires time + interaction data before _abck validates.
const AKAMAI_SENSOR_INIT_MS = 8_000;
// Timeout for the login XHR POST request.
const XHR_TIMEOUT_MS = 30_000;

const WUST_RE = /lenovoid\.wust=([^&\s"']+)/;

function findWust(text) {
  const m = WUST_RE.exec(text || "");
  return m ? m[1] : null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (msg) => process.stderr.write(`[Hero] ${msg}\n`);

async function main() {
  const hero = new Hero({
    showChrome: false,
    noChromeSandbox: true,
    userAgent: "~ chrome >= 120 && windows >= 10",
  });

  try {
    // ---- Navigate to the login page ----
    log(`Navigating to ${loginUrl.slice(0, 80)}`);
    await hero.goto(loginUrl);
    await hero.waitForPaintingStable();

    // Let Akamai sensor and page JS initialise.
    await sleep(AKAMAI_SENSOR_INIT_MS);

    // Feed the Akamai sensor with realistic mouse interaction data.
    for (let i = 0; i < 10; i++) {
      const x = 200 + Math.floor(Math.random() * 600);
      const y = 150 + Math.floor(Math.random() * 400);
      await hero.interact({ move: [x, y] });
      await sleep(50 + Math.floor(Math.random() * 100));
    }
    await sleep(3_000);

    // Wait for the global-loader overlay to disappear.
    for (let i = 0; i < 30; i++) {
      const gone = await hero.activeTab.getJsValue(
        "!document.getElementById('global-loader') || " +
          "document.getElementById('global-loader').offsetParent === null",
      );
      if (gone) break;
      await sleep(1_000);
    }

    // ---- Step 1: Fill email via Hero native interactions ----
    const emailInput = hero.document.querySelector("#emailOrPhoneInput");
    if (emailInput) {
      await hero.interact({ click: emailInput });
      await hero.interact({ type: email });
      log("Email filled");
    } else {
      log("ERROR: Email field #emailOrPhoneInput not found");
      process.exit(1);
    }

    await sleep(1_000);

    // ---- Step 2: Click "Next" and wait for SPA transition ----
    const nextBtn = hero.document.querySelector("div.loginClass1 button");
    if (nextBtn) {
      await hero.interact({ click: nextBtn });
      log("Clicked Next button");
    } else {
      await hero.interact({ keyPress: "Enter" });
      log("Pressed Enter (Next button not found)");
    }

    // Wait for SPA to transition to the password step.
    await sleep(5_000);
    let passwordAppeared = false;
    for (let i = 0; i < 15; i++) {
      await sleep(1_000);
      const vis = await hero.activeTab.getJsValue(
        "(() => { const e = document.querySelector('#emailOrPhonePswInput');" +
          " return !!(e && e.offsetParent !== null); })()",
      );
      if (vis) { passwordAppeared = true; break; }
    }

    // ---- Step 2b: If SPA didn't transition, manually trigger AJAX ----
    // The login.js ajaxPost() sends a POST with params in the URL and
    // empty body.  Status 400 = "user exists → show password step".
    if (!passwordAppeared) {
      log("SPA did not transition — calling ajaxUserExistedServlet manually");

      // Read the lenovoid.* JS variables that the page already set.
      const ajaxUrl = await hero.activeTab.getJsValue(`(() => {
        const p = typeof path !== 'undefined' ? path : '/glbwebauthnv6';
        const a = typeof lenovoidAction !== 'undefined' ? lenovoidAction : 'uilogin';
        const r = typeof lenovoidRealm !== 'undefined' ? lenovoidRealm : 'lmsaclient';
        const l = typeof lenovoidLang !== 'undefined' ? lenovoidLang : 'en_US';
        const cb = typeof lenovoidCb !== 'undefined' ? lenovoidCb : '';
        const ctx = typeof lenovoidCtx !== 'undefined' ? lenovoidCtx : 'null';
        return p + '/ajaxUserExistedServlet?username='
          + encodeURIComponent(${JSON.stringify(email)})
          + '&lenovoid.action=' + encodeURIComponent(a)
          + '&lenovoid.realm=' + encodeURIComponent(r)
          + '&lenovoid.lang=' + encodeURIComponent(l)
          + '&lenovoid.cb=' + encodeURIComponent(cb)
          + '&lenovoid.ctx=' + encodeURIComponent(ctx);
      })()`);
      log(`AJAX URL: ${ajaxUrl.slice(0, 120)}`);

      // Call the AJAX endpoint (POST with empty body, matching jQuery ajaxPost).
      const ajaxResult = await hero.activeTab.getJsValue(`(async () => {
        try {
          const resp = await fetch(${JSON.stringify(ajaxUrl)}, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
              'X-Requested-With': 'XMLHttpRequest',
            },
            body: '',
            credentials: 'same-origin',
          });
          const text = await resp.text();
          return resp.status + ':' + text.slice(0, 200);
        } catch(e) { return 'error:' + e.message; }
      })()`);
      log(`AJAX result: ${ajaxResult}`);

      const ajaxStatus = parseInt(ajaxResult, 10);

      if (ajaxStatus === 400 || ajaxStatus === 200) {
        // 400 = user exists (email login) → show password step.
        // 200 = user exists (may redirect to SSO).
        log("User validated — transitioning to password step");
        await hero.activeTab.getJsValue(`(() => {
          // Replicate what login.js does on 400 response:
          // initViewId=2, show loginClass2, hide siblings, fill email.
          const lc2 = document.querySelector('.loginClass2');
          if (lc2) {
            lc2.style.display = '';
            // Hide all sibling loginClass* divs
            const parent = lc2.parentElement;
            if (parent) {
              parent.querySelectorAll('[class*="loginClass"]').forEach(el => {
                if (el !== lc2) el.style.display = 'none';
              });
            }
          }
          // Fill email in the loginClass2 display and hidden fields
          const ea = document.querySelector('.loginClass2 .emailAddress');
          if (ea) ea.innerHTML = ${JSON.stringify(email)};
          document.querySelectorAll('.loginClass2 .emailAddressInput')
            .forEach(e => e.value = ${JSON.stringify(email)});
          document.querySelectorAll('input[name="username"]')
            .forEach(e => e.value = ${JSON.stringify(email)});
        })()`);
        await sleep(1_000);
        passwordAppeared = true;
      }
    }

    if (!passwordAppeared) {
      log("ERROR: Could not reach password step");
      process.exit(1);
    }

    // ---- Step 3: Fill password ----
    log("Filling password");

    // Ensure the password input is visible and enabled.
    await hero.activeTab.getJsValue(`(() => {
      const el = document.querySelector('#emailOrPhonePswInput');
      if (el) {
        el.style.display = '';
        el.style.visibility = 'visible';
        el.removeAttribute('disabled');
        el.removeAttribute('readonly');
        // Make sure its parent containers are visible too
        let p = el.parentElement;
        while (p) {
          if (p.style) { p.style.display = ''; p.style.visibility = 'visible'; }
          p = p.parentElement;
        }
      }
    })()`);
    await sleep(1_000);

    // Try native Hero interaction first; fall back to JS value-setting.
    let pwFilled = false;
    try {
      const pwInput = hero.document.querySelector("#emailOrPhonePswInput");
      await hero.interact({ click: pwInput });
      await hero.interact({ type: password });
      pwFilled = true;
      log("Password filled via Hero interaction");
    } catch {
      log("Hero click failed on password field — setting value via JS");
      await hero.activeTab.getJsValue(`(() => {
        const el = document.querySelector('#emailOrPhonePswInput');
        if (el) {
          el.focus();
          el.value = ${JSON.stringify(password)};
          el.dispatchEvent(new Event('input', {bubbles: true}));
          el.dispatchEvent(new Event('change', {bubbles: true}));
          el.dispatchEvent(new KeyboardEvent('keyup', {bubbles: true}));
        }
      })()`);
      pwFilled = true;
      log("Password set via JS");
    }
    await sleep(2_000);

    // ---- Step 4: Submit login via XHR ----
    // The page's own nextHandler() is scoped inside a jQuery ready
    // callback and not globally accessible.  We replicate its logic:
    // double-MD5 hash the password, obtain reCAPTCHA token (GT) and
    // Fingerprint2 bid, then POST via XMLHttpRequest (not form.submit)
    // with the X-Requested-With header that marks it as AJAX — Akamai
    // treats XHR requests differently from navigation form POSTs.
    log("Preparing login submission via XHR…");

    const submitResult = await hero.activeTab.getJsValue(`(async () => {
      // Double-MD5 hash the password (matching login.js nextHandler)
      async function md5(str) {
        const buf = new TextEncoder().encode(str);
        // Use SubtleCrypto if available, else fall back to page's MD5
        if (typeof CryptoJS !== 'undefined' && CryptoJS.MD5) {
          return CryptoJS.MD5(str).toString().toUpperCase();
        }
        // Manual fallback using the page's own md5 if loaded
        if (typeof hex_md5 === 'function') {
          return hex_md5(str).toUpperCase();
        }
        // Last resort: we'll compute it ourselves
        return null;
      }

      // Try the page's own MD5 function first
      let hashed = null;
      if (typeof hex_md5 === 'function') {
        const inner = hex_md5(${JSON.stringify(password)}).toUpperCase();
        hashed = hex_md5(inner).toUpperCase();
      } else if (typeof CryptoJS !== 'undefined' && CryptoJS.MD5) {
        const inner = CryptoJS.MD5(${JSON.stringify(password)}).toString().toUpperCase();
        hashed = CryptoJS.MD5(inner).toString().toUpperCase();
      }
      if (!hashed) return 'error:no-md5-function';

      // Get reCAPTCHA Enterprise token
      let gt = '';
      try {
        if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {
          gt = await grecaptcha.enterprise.execute(
            '${RECAPTCHA_SITE_KEY}', {action: 'LOGIN'});
        }
      } catch(e) { gt = ''; }

      // Get Fingerprint2 bid
      const bidEl = document.querySelector('.jsBid, input[name="bid"]');
      const bid = bidEl ? bidEl.value : '';

      // Collect all hidden form fields
      const form = document.querySelector('.loginClass2 form')
                   || document.querySelector('form');
      if (!form) return 'error:no-form';

      const params = new URLSearchParams();
      form.querySelectorAll('input[type="hidden"]').forEach(el => {
        if (el.name) params.set(el.name, el.value);
      });
      params.set('username', ${JSON.stringify(email)});
      params.set('password', hashed);
      params.set('loginfinish', '1');
      params.set('gt', gt);
      params.set('bid', bid);
      params.set('autoLoginState', '1');

      // Submit via XMLHttpRequest with params in URL (empty body).
      // Akamai treats empty-body POSTs differently from form-data POSTs.
      return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        const url = (form.action || '/glbwebauthnv6/userLogin')
          + '?' + params.toString();
        xhr.open('POST', url, true);
        xhr.setRequestHeader('Content-Type',
          'application/x-www-form-urlencoded; charset=utf-8');
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.timeout = XHR_TIMEOUT_MS;
        xhr.onload = function() {
          const respUrl = xhr.responseURL || '';
          const respText = xhr.responseText || '';
          resolve(xhr.status + '|' + respUrl + '|' + respText.slice(0, 2000));
        };
        xhr.onerror = function() { resolve('xhr-error'); };
        xhr.ontimeout = function() { resolve('xhr-timeout'); };
        xhr.send('');
      });
    })()`);
    log(`XHR submit result: ${(submitResult || "").slice(0, 200)}`);

    // Try to extract WUST from the XHR response.
    let wust = findWust(submitResult || "");

    // If the XHR response contains a redirect URL with WUST, navigate to it.
    if (!wust && submitResult) {
      const parts = submitResult.split("|");
      if (parts.length >= 2) {
        wust = findWust(parts[1]);  // responseURL
      }
      if (!wust && parts.length >= 3) {
        wust = findWust(parts[2]);  // responseText
      }
    }

    // Also check if the XHR triggered a page navigation.
    if (!wust) {
      await sleep(3_000);
      const curUrl = await hero.activeTab.url;
      wust = findWust(curUrl);
      if (!wust) {
        try {
          const body = await hero.activeTab.getJsValue(
            "document.documentElement?.outerHTML || ''",
          );
          wust = findWust(body);
        } catch { /* page may have navigated */ }
      }
    }

    if (wust) {
      process.stdout.write(`WUST=${wust}\n`);
      log("✓ WUST obtained");
    } else {
      try {
        const txt = await hero.activeTab.getJsValue(
          "document.body?.innerText?.slice(0, 500) || ''",
        );
        if (txt) log(`Page text: ${txt.slice(0, 300)}`);
      } catch { /* best effort */ }
      const pageUrl = await hero.activeTab.url;
      log(`✗ No WUST found — page URL: ${pageUrl}`);
      process.exit(1);
    }
  } catch (err) {
    log(`Error: ${err.message || err}`);
    process.exit(1);
  } finally {
    await hero.close();
  }
}

main();
