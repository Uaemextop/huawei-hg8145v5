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
 * On success prints to stdout (one per line):
 *   WUST=<token>
 *   JWT=<token>           (if available from lenovoIdLogin.jhtml)
 *   GUID=<uuid>           (if available)
 *
 * On failure exits with code 1 and prints diagnostics to stderr.
 */

import Hero from "@ulixee/hero-playground";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

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

const WUST_RE = /lenovoid\.wust=([^&\s"'<>]+)/;

function findWust(text) {
  const m = WUST_RE.exec(text || "");
  return m ? m[1] : null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (msg) => process.stderr.write(`[Hero] ${msg}\n`);

// Screenshot helper — saves a PNG to /tmp/ for debugging.
let screenshotIdx = 0;
async function takeScreenshot(hero, label) {
  try {
    // Hero screenshot returns a Buffer
    const buf = await hero.activeTab.takeScreenshot();
    const filename = `/tmp/hero_${++screenshotIdx}_${label.replace(/[^a-zA-Z0-9]/g, '_')}.png`;
    writeFileSync(filename, buf);
    log(`Screenshot saved: ${filename}`);
  } catch (e) {
    log(`Screenshot failed (${label}): ${e.message}`);
  }
}

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
            // Use cssText to force display with !important to override CSS rules
            lc2.style.cssText = 'display: block !important; visibility: visible !important;';
            // Also add a style tag to override any CSS rules
            const style = document.createElement('style');
            style.textContent = '.loginClass2 { display: block !important; visibility: visible !important; }';
            document.head.appendChild(style);
            // Hide all sibling loginClass* divs
            const parent = lc2.parentElement;
            if (parent) {
              parent.querySelectorAll('[class*="loginClass"]').forEach(el => {
                if (el !== lc2) el.style.cssText = 'display: none !important;';
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

    // Take screenshot BEFORE trying to fill password — shows actual page state
    await takeScreenshot(hero, "before_password");

    // Diagnose password field state
    const pwDiag = await hero.activeTab.getJsValue(`(() => {
      const el = document.querySelector('#emailOrPhonePswInput');
      if (!el) return 'NOT_FOUND';
      const rect = el.getBoundingClientRect();
      const cs = window.getComputedStyle(el);
      return JSON.stringify({
        tagName: el.tagName,
        type: el.type,
        id: el.id,
        display: cs.display,
        visibility: cs.visibility,
        opacity: cs.opacity,
        width: rect.width,
        height: rect.height,
        top: rect.top,
        left: rect.left,
        disabled: el.disabled,
        readonly: el.readOnly,
        offsetParent: el.offsetParent ? el.offsetParent.tagName : null,
        parentDisplay: el.parentElement ? window.getComputedStyle(el.parentElement).display : null,
      });
    })()`);
    log(`Password field diagnostics: ${pwDiag}`);

    // Also check if loginClass2 is visible
    const lc2Diag = await hero.activeTab.getJsValue(`(() => {
      const lc2 = document.querySelector('.loginClass2');
      if (!lc2) return 'NOT_FOUND';
      const cs = window.getComputedStyle(lc2);
      return JSON.stringify({
        display: cs.display,
        visibility: cs.visibility,
        offsetHeight: lc2.offsetHeight,
        children: lc2.children.length,
      });
    })()`);
    log(`loginClass2 diagnostics: ${lc2Diag}`);

    // Ensure the password input is visible and enabled.
    await hero.activeTab.getJsValue(`(() => {
      // Inject global CSS to force loginClass2 and password field visible
      const style = document.createElement('style');
      style.textContent = \`
        .loginClass2 { display: block !important; visibility: visible !important; height: auto !important; overflow: visible !important; }
        .loginClass2 * { visibility: visible !important; }
        #emailOrPhonePswInput { display: block !important; visibility: visible !important; width: 100% !important; height: 40px !important; opacity: 1 !important; }
      \`;
      document.head.appendChild(style);

      const el = document.querySelector('#emailOrPhonePswInput');
      if (el) {
        el.style.cssText = 'display: block !important; visibility: visible !important; width: 300px !important; height: 40px !important; opacity: 1 !important;';
        el.removeAttribute('disabled');
        el.removeAttribute('readonly');
        // Make sure its parent containers are visible too
        let p = el.parentElement;
        while (p && p !== document.body) {
          p.style.cssText += '; display: block !important; visibility: visible !important; height: auto !important; overflow: visible !important;';
          p = p.parentElement;
        }
      }
    })()`);
    await sleep(1_000);

    // Try native Hero interaction first; fall back to JS value-setting.
    try {
      const pwInput = hero.document.querySelector("#emailOrPhonePswInput");
      await hero.interact({ click: pwInput });
      await hero.interact({ type: password });
      log("Password filled via Hero interaction");
      await takeScreenshot(hero, "after_password_hero");
    } catch (pwErr) {
      log(`Hero click failed on password field: ${pwErr.message}`);
      await takeScreenshot(hero, "password_click_failed");
      log("Setting value via JS fallback");
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
      // Verify the value was set
      const pwVal = await hero.activeTab.getJsValue(`(() => {
        const el = document.querySelector('#emailOrPhonePswInput');
        return el ? el.value.length : -1;
      })()`);
      log(`Password field value length after JS set: ${pwVal}`);
      await takeScreenshot(hero, "after_password_js");
      log("Password set via JS");
    }
    await sleep(2_000);

    // ---- Step 4: Click the "Next" button to trigger native login ----
    // The page's own nextHandler() (in login.js) handles everything:
    // MD5 hashing, reCAPTCHA token, Fingerprint2 bid, and form.submit().
    // This is the correct flow — the page JS submits the form natively.
    log("Clicking Next button in loginClass2…");

    // First try native Hero click on the Next button
    let nextClicked = false;
    try {
      const nextBtn2 = hero.document.querySelector(".loginClass2 button");
      if (nextBtn2) {
        await hero.interact({ click: nextBtn2 });
        nextClicked = true;
        log("Clicked loginClass2 Next button via Hero");
      }
    } catch (e) {
      log(`Hero click on Next button failed: ${e.message}`);
    }

    // Fallback: click via JS
    if (!nextClicked) {
      const clicked = await hero.activeTab.getJsValue(`(() => {
        // Find the Next button in loginClass2
        const btn = document.querySelector('.loginClass2 button')
                 || document.querySelector('.loginClass2 .next');
        if (btn) { btn.click(); return 'clicked'; }
        return 'not-found';
      })()`);
      log(`JS click result: ${clicked}`);
      if (clicked === 'clicked') nextClicked = true;
    }

    // Wait for page's JS to process (nextHandler does async operations:
    // MD5 hash, reCAPTCHA execute, bid polling, then form.submit)
    await sleep(20_000);
    await takeScreenshot(hero, "after_next_click");

    // ---- Step 5: Extract WUST from resulting page ----
    let wust = null;

    // Check current URL (form.submit may have navigated with redirects)
    try {
      const curUrl = await hero.activeTab.url;
      log(`Post-login URL: ${curUrl.slice(0, 120)}`);
      wust = findWust(curUrl);
    } catch { /* navigation may be in progress */ }

    // Check page body for redirect URL containing WUST
    if (!wust) {
      try {
        const body = await hero.activeTab.getJsValue(
          "document.documentElement?.outerHTML?.slice(0, 10000) || ''",
        );
        wust = findWust(body);
        if (!wust) {
          // Check for JS redirect in HTML
          const redirectMatch = body.match(
            /(?:window\.location(?:\.href)?\s*=\s*["']|url=)(https?:\/\/[^"'<>\s;]+)/i
          );
          if (redirectMatch) {
            log(`Found redirect in body: ${redirectMatch[1].slice(0, 100)}`);
            wust = findWust(redirectMatch[1]);
            // Follow the redirect if it has WUST
            if (!wust) {
              try {
                await hero.goto(redirectMatch[1]);
                await sleep(5_000);
                const navUrl = await hero.activeTab.url;
                wust = findWust(navUrl);
              } catch {}
            }
          }
        }
      } catch { /* page may have navigated */ }
    }

    // Check LPSWUST cookie
    if (!wust) {
      try {
        const lpswust = await hero.activeTab.getJsValue(`(() => {
          const m = document.cookie.match(/LPSWUST=([^;]+)/);
          return m ? m[1] : '';
        })()`);
        if (lpswust) {
          wust = lpswust;
          log(`Found LPSWUST cookie: ${lpswust.slice(0, 30)}…`);
        }
      } catch {}
    }

    // If nextHandler failed (e.g. form.submit blocked by Akamai),
    // extract session data for Python server-side fallback.
    if (!wust) {
      log("No WUST from native login flow — extracting session data for fallback…");

      const sessionData = await hero.activeTab.getJsValue(`(async () => {
        let hashed = null;
        if (typeof hex_md5 === 'function') {
          const inner = hex_md5(${JSON.stringify(password)}).toUpperCase();
          hashed = hex_md5(inner).toUpperCase();
        } else if (typeof CryptoJS !== 'undefined' && CryptoJS.MD5) {
          const inner = CryptoJS.MD5(${JSON.stringify(password)}).toString().toUpperCase();
          hashed = CryptoJS.MD5(inner).toString().toUpperCase();
        }
        if (!hashed) return JSON.stringify({error: 'no-md5-function'});

        let gt = '';
        try {
          if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {
            gt = await grecaptcha.enterprise.execute(
              '${RECAPTCHA_SITE_KEY}', {action: 'LOGIN'});
          }
        } catch(e) { gt = ''; }

        const bidEl = document.querySelector('.jsBid, input[name="bid"]');
        const bid = bidEl ? bidEl.value : '';

        const form = document.querySelector('.loginClass2 form')
                     || document.querySelector('form');
        const formFields = {};
        if (form) {
          form.querySelectorAll('input[type="hidden"]').forEach(el => {
            if (el.name) formFields[el.name] = el.value;
          });
        }
        const cookies = document.cookie;
        return JSON.stringify({
          hashed, gt, bid, formFields, cookies,
          formAction: form ? form.action : '',
        });
      })()`);

      let parsedSession;
      try { parsedSession = JSON.parse(sessionData); }
      catch { parsedSession = null; }

      if (parsedSession && !parsedSession.error) {
        const formData = { ...parsedSession.formFields };
        formData.username = email;
        formData.password = parsedSession.hashed;
        formData.loginfinish = '1';
        formData.gt = parsedSession.gt;
        formData.bid = parsedSession.bid;
        formData.autoLoginState = '1';

        process.stdout.write(`FORM_DATA=${JSON.stringify(formData)}\n`);
        process.stdout.write(`COOKIES=${parsedSession.cookies}\n`);
        const formAction = parsedSession.formAction || 'https://passport.lenovo.com/glbwebauthnv6/userLogin';
        process.stdout.write(`FORM_ACTION=${formAction}\n`);
        log("Session data extracted for Python fallback");
      }
    }

    if (wust) {
      process.stdout.write(`WUST=${wust}\n`);
      log("✓ WUST obtained");
    } else {
      log("No WUST obtained — Python will attempt server-side login with extracted session");
    }
  } catch (err) {
    log(`Error: ${err.message || err}`);
    process.exit(1);
  } finally {
    await hero.close();
  }
}

main();
