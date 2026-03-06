/**
 * Ulixee Hero login script for passport.lenovo.com.
 *
 * Performs the Lenovo ID OAuth flow in a real-looking browser that bypasses
 * Akamai Bot Manager by emulating genuine browser TLS fingerprints, HTTP/2
 * settings, and DOM APIs.
 *
 * Usage:
 *   node hero_login.mjs <login_url> <email> <password>
 *
 * On success prints to stdout:
 *   WUST=<token>
 *
 * On failure exits with code 1 and prints diagnostics to stderr.
 *
 * Security: credentials are received as CLI arguments from the parent
 * Python process and are never persisted to disk.
 */

import Hero from "@ulixee/hero-playground";
import { createHash } from "node:crypto";

const [, , loginUrl, email, password] = process.argv;

if (!loginUrl || !email || !password) {
  process.stderr.write(
    "Usage: node hero_login.mjs <login_url> <email> <password>\n",
  );
  process.exit(1);
}

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

async function main() {
  const hero = new Hero({
    showChrome: false,
    // Emulate a typical headed Chrome on Windows to defeat TLS and
    // DOM-level bot detection (Akamai _abck validation).
    userAgent: "~ chrome >= 120 && windows >= 10",
  });

  try {
    // ---- Navigate to the login page ----
    process.stderr.write(`[Hero] Navigating to ${loginUrl.slice(0, 80)}\n`);
    await hero.goto(loginUrl);
    await hero.waitForPaintingStable();

    // Give Akamai sensor, reCAPTCHA, and page JS time to initialise.
    await sleep(10_000);

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
    } else {
      process.stderr.write("[Hero] Email field #emailOrPhoneInput not found\n");
      process.exit(1);
    }

    await sleep(1_000);

    // ---- Click "Next" button ----
    const nextBtn = hero.document.querySelector("div.loginClass1 button");
    if (nextBtn) {
      await hero.interact({ click: nextBtn });
    } else {
      await hero.interact({ keyPress: "Enter" });
    }

    // ---- Wait for password field ----
    process.stderr.write("[Hero] Waiting for password step…\n");
    let passwordAppeared = false;
    for (let i = 0; i < 20; i++) {
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
      process.stderr.write("[Hero] Password step appeared (SPA OK)\n");
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
      process.stderr.write(
        "[Hero] SPA blocked — attempting direct form submit\n",
      );
      const hashed = hashPassword(password);

      // Get reCAPTCHA Enterprise token
      let gt = "";
      try {
        gt =
          (await hero.activeTab.getJsValue(
            "(async () => {" +
              " if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {" +
              "  try { return await grecaptcha.enterprise.execute(" +
              "   '6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub'," +
              "   {action: 'LOGIN'});" +
              "  } catch(e) { return ''; }" +
              " } return '';" +
              "})()",
          )) || "";
      } catch {
        gt = "";
      }

      // Get Fingerprint2 bid
      let bid = "";
      try {
        bid =
          (await hero.activeTab.getJsValue(
            "document.querySelector('.jsBid')?.value || ''",
          )) || "";
      } catch {
        bid = "";
      }

      // Fill form and submit
      const formJS = `(() => {
        const f = document.querySelector('.loginClass2 form');
        if (!f) return false;
        f.querySelectorAll('input[name="username"]')
            .forEach(e => e.value = ${JSON.stringify(email)});
        f.querySelectorAll('.emailAddressInput')
            .forEach(e => e.value = ${JSON.stringify(email)});
        f.querySelectorAll('input[name="password"]')
            .forEach(e => e.value = ${JSON.stringify(hashed)});
        f.querySelectorAll('input[name="loginfinish"]')
            .forEach(e => e.value = '1');
        let g = f.querySelector('input[name="gt"]');
        if (!g) {
            g = document.createElement('input');
            g.type = 'hidden'; g.name = 'gt';
            f.appendChild(g);
        }
        g.value = ${JSON.stringify(gt)};
        const bidEl = f.querySelector('.jsBid, input[name="bid"]');
        if (bidEl && !bidEl.value) bidEl.value = ${JSON.stringify(bid)};
        f.submit();
        return true;
      })()`;
      await hero.activeTab.getJsValue(formJS);
      await sleep(10_000);
    }

    // ---- Extract WUST ----
    const finalUrl = await hero.activeTab.url;
    let wust = findWust(finalUrl);

    if (!wust) {
      const body = await hero.activeTab.getJsValue(
        "document.documentElement?.outerHTML || ''",
      );
      wust = findWust(body);
    }

    if (wust) {
      // Print WUST to stdout for the parent Python process.
      process.stdout.write(`WUST=${wust}\n`);
      process.stderr.write("[Hero] ✓ WUST obtained\n");
    } else {
      process.stderr.write(
        `[Hero] ✗ No WUST found — final URL: ${finalUrl}\n`,
      );
      process.exit(1);
    }
  } catch (err) {
    process.stderr.write(`[Hero] Error: ${err.message || err}\n`);
    process.exit(1);
  } finally {
    await hero.close();
  }
}

main();
