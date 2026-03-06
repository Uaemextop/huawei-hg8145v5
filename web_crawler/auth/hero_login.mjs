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

/** Double-MD5 password hash matching passport.lenovo.com login.js. */
function hashPassword(pw) {
  const inner = createHash("md5").update(pw, "utf8").digest("hex").toUpperCase();
  return createHash("md5").update(inner, "utf8").digest("hex").toUpperCase();
}

const WUST_RE = /lenovoid\.wust=([^&\s"']+)/;

function findWust(text) {
  const m = WUST_RE.exec(text || "");
  return m ? m[1] : null;
}

/** Helper: sleep for *ms* milliseconds. */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function log(msg) {
  process.stderr.write(`[Hero] ${msg}\n`);
}

async function main() {
  const hero = new Hero({
    showChrome: false,
    noChromeSandbox: true,
    // Emulate a typical headed Chrome on Windows to defeat TLS and
    // DOM-level bot detection (Akamai _abck validation).
    userAgent: "~ chrome >= 120 && windows >= 10",
  });

  try {
    // ---- Navigate to the login page ----
    log(`Navigating to ${loginUrl.slice(0, 80)}`);
    await hero.goto(loginUrl);
    await hero.waitForPaintingStable();

    // Give Akamai sensor, reCAPTCHA, and page JS time to initialise.
    await sleep(8_000);

    // Simulate mouse movements to feed the Akamai sensor.
    for (let i = 0; i < 10; i++) {
      const x = 200 + Math.floor(Math.random() * 600);
      const y = 150 + Math.floor(Math.random() * 400);
      await hero.interact({ move: [x, y] });
      await sleep(50 + Math.floor(Math.random() * 100));
    }
    await sleep(3_000);

    // ---- Wait for global-loader overlay to disappear ----
    for (let i = 0; i < 30; i++) {
      const loaderGone = await hero.activeTab.getJsValue(
        "!document.getElementById('global-loader') || " +
          "document.getElementById('global-loader').offsetParent === null",
      );
      if (loaderGone) break;
      await sleep(1_000);
    }

    // ---- Step 1: Fill email ----
    const emailInput = hero.document.querySelector("#emailOrPhoneInput");
    if (emailInput) {
      await hero.interact({ click: emailInput });
      await hero.interact({ type: email });
      log("Email filled");
    } else {
      log("Email field #emailOrPhoneInput not found");
      process.exit(1);
    }

    await sleep(1_000);

    // ---- Click "Next" button ----
    const nextBtn = hero.document.querySelector("div.loginClass1 button");
    if (nextBtn) {
      await hero.interact({ click: nextBtn });
      log("Clicked Next button");
    } else {
      await hero.interact({ keyPress: "Enter" });
      log("Pressed Enter (Next button not found)");
    }

    // Wait for the AJAX email validation to complete.
    await sleep(5_000);

    // ---- Wait for password field ----
    log("Waiting for password step…");
    let passwordAppeared = false;
    for (let i = 0; i < 25; i++) {
      await sleep(1_000);
      const vis = await hero.activeTab.getJsValue(
        "(() => { const e = document.querySelector('#emailOrPhonePswInput');" +
          " return !!(e && e.offsetParent !== null); })()",
      );
      if (vis) {
        passwordAppeared = true;
        break;
      }
    }

    if (passwordAppeared) {
      // ---- SPA flow: fill password ----
      log("Password step appeared (SPA OK)");
      const pwInput = hero.document.querySelector("#emailOrPhonePswInput");
      if (pwInput) {
        await hero.interact({ click: pwInput });
        await hero.interact({ type: password });
      }

      await sleep(3_000);

      // Click submit button
      let submitted = false;
      for (const sel of ["button.loadingBtnHide", "div.loginClass2 button"]) {
        const btn = hero.document.querySelector(sel);
        try {
          const navWait = hero.activeTab.waitForLocation("change");
          await hero.interact({ click: btn });
          await Promise.race([navWait, sleep(20_000)]);
          submitted = true;
          break;
        } catch {
          continue;
        }
      }
      if (!submitted) {
        await hero.interact({ keyPress: "Enter" });
        await sleep(10_000);
      }
    } else {
      // ---- Direct form submission fallback ----
      // HAR analysis shows the successful POST to /glbwebauthnv6/userLogin
      // includes these fields: all lenovoid.* hidden fields, username,
      // password (double-MD5), loginfinish=1, bid, gt, autoLoginState=1,
      // crossRealmDomains=null, path=/glbwebauthnv6, areacode=(empty).
      // Cookies required: JSESSIONID, _abck, bm_sz, bm_sv, ak_bmsc,
      // lenovoid.webLoginSignkey, lenovoid.realm, lang.
      log("SPA blocked — attempting direct form submit (HAR-informed)");
      const hashed = hashPassword(password);

      // Dump current cookies for diagnosis.
      const cookieStr = await hero.activeTab.getJsValue("document.cookie");
      log(`Cookies: ${(cookieStr || "").slice(0, 200)}`);

      // Dump hidden fields for diagnosis.
      const hiddenFields = await hero.activeTab.getJsValue(`(() => {
        const fields = {};
        document.querySelectorAll('input[type="hidden"]').forEach(e => {
          if (e.name) fields[e.name] = e.value;
        });
        return fields;
      })()`);
      log(`Hidden fields: ${JSON.stringify(Object.keys(hiddenFields || {}))}`);

      // Get reCAPTCHA Enterprise token
      let gt = "";
      try {
        gt =
          (await hero.activeTab.getJsValue(
            `(async () => {
              if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {
                try {
                  return await grecaptcha.enterprise.execute(
                    '${RECAPTCHA_SITE_KEY}', {action: 'LOGIN'});
                } catch(e) { return ''; }
              }
              return '';
            })()`,
          )) || "";
      } catch {
        gt = "";
      }
      log(`reCAPTCHA token: ${gt ? "obtained (" + gt.length + " chars)" : "unavailable"}`);

      // Get Fingerprint2 bid
      let bid = "";
      try {
        bid =
          (await hero.activeTab.getJsValue(
            "document.querySelector('.jsBid, input[name=\"bid\"]')?.value || ''",
          )) || "";
      } catch {
        bid = "";
      }
      log(`bid: ${bid || "unavailable"}`);

      // Build form data matching the HAR capture exactly.
      // Use all hidden form fields from the page + credential fields.
      const formResult = await hero.activeTab.getJsValue(`(async () => {
        const f = document.querySelector('.loginClass2 form')
                  || document.querySelector('form');
        if (!f) return 'no-form';

        // Set credential fields
        f.querySelectorAll('input[name="username"]')
          .forEach(e => e.value = ${JSON.stringify(email)});
        f.querySelectorAll('.emailAddressInput')
          .forEach(e => e.value = ${JSON.stringify(email)});
        f.querySelectorAll('input[name="password"]')
          .forEach(e => e.value = ${JSON.stringify(hashed)});
        f.querySelectorAll('input[name="loginfinish"]')
          .forEach(e => e.value = '1');

        // Fields from HAR that may be missing
        function ensureField(name, value) {
          let el = f.querySelector('input[name="' + name + '"]');
          if (!el) {
            el = document.createElement('input');
            el.type = 'hidden';
            el.name = name;
            f.appendChild(el);
          }
          el.value = value;
        }
        ensureField('autoLoginState', '1');
        ensureField('crossRealmDomains', 'null');
        ensureField('path', '/glbwebauthnv6');
        ensureField('areacode', '');

        // GT (reCAPTCHA)
        ensureField('gt', ${JSON.stringify(gt)});

        // Bid
        const bidEl = f.querySelector('.jsBid, input[name="bid"]');
        if (bidEl && !bidEl.value) bidEl.value = ${JSON.stringify(bid)};
        if (!bidEl) ensureField('bid', ${JSON.stringify(bid)});

        // Serialize for diagnosis
        const fd = new FormData(f);
        const keys = [];
        for (const [k] of fd) keys.push(k);
        return 'fields:' + keys.join(',');
      })()`);
      log(`Form prepared: ${formResult}`);

      // Submit via the form's own submit mechanism (uses browser cookies).
      log("Submitting form…");
      await hero.activeTab.getJsValue(`(() => {
        const f = document.querySelector('.loginClass2 form')
                  || document.querySelector('form');
        if (f) f.submit();
      })()`);

      // Wait for the server to process and redirect.
      await sleep(20_000);
    }

    // ---- Extract WUST ----
    const finalUrl = await hero.activeTab.url;
    let wust = findWust(finalUrl);

    if (!wust) {
      try {
        const body = await hero.activeTab.getJsValue(
          "document.documentElement?.outerHTML || ''",
        );
        wust = findWust(body);
      } catch { /* page may have navigated away */ }
    }

    if (wust) {
      process.stdout.write(`WUST=${wust}\n`);
      log("✓ WUST obtained");
    } else {
      // Diagnostic output
      try {
        const bodySnippet = await hero.activeTab.getJsValue(
          "document.body?.innerText?.slice(0, 500) || ''",
        );
        if (bodySnippet) log(`Page text: ${bodySnippet.slice(0, 300)}`);
      } catch { /* best effort */ }
      log(`✗ No WUST found — final URL: ${finalUrl}`);
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
