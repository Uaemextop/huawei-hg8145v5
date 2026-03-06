#!/usr/bin/env node
/**
 * Ulixee Hero-based Lenovo ID login script
 *
 * Uses Hero's advanced Akamai bypass capabilities to authenticate
 * with passport.lenovo.com and extract the WUST token.
 *
 * Usage:
 *   node hero_login.js <email> <password> <login_url>
 *
 * Output (JSON):
 *   {"success": true, "wust": "TOKEN_HERE"}
 *   {"success": false, "error": "Error message"}
 */

const Hero = require('@ulixee/hero');

/**
 * Double MD5 hash for Lenovo password (matches Python implementation)
 */
function hashPassword(password) {
    const crypto = require('crypto');
    const inner = crypto.createHash('md5').update(password).digest('hex').toUpperCase();
    return crypto.createHash('md5').update(inner).digest('hex').toUpperCase();
}

/**
 * Extract WUST token from URL or text
 */
function findWust(text) {
    const match = text.match(/lenovoid\.wust=([^&\s"']+)/);
    return match ? match[1] : null;
}

/**
 * Main login function using Hero
 */
async function loginWithHero(email, password, loginUrl) {
    const hero = new Hero({
        // Hero's default configuration is already optimized for stealth
        // It automatically handles:
        // - Browser fingerprinting evasion
        // - TLS fingerprinting
        // - Network timing patterns
        // - WebDriver detection bypass
        showChrome: false,  // Headless mode
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
    });

    try {
        console.error('[Hero] Navigating to login page...');
        await hero.goto(loginUrl);

        // Wait for page to load and Akamai sensor to initialize
        console.error('[Hero] Waiting for Akamai sensor initialization...');
        await hero.waitForPaintingStable();
        await new Promise(resolve => setTimeout(resolve, 10000)); // 10s for Akamai

        // Wait for loader to disappear
        const loaderExists = await hero.document.querySelector('#global-loader');
        if (loaderExists) {
            console.error('[Hero] Waiting for global loader to disappear...');
            await hero.waitForElement('#global-loader', { waitForVisible: false, timeoutMs: 30000 })
                .catch(() => {
                    // If timeout, force remove
                    console.error('[Hero] Forcing loader removal...');
                    hero.document.querySelector('#global-loader').then(el => {
                        if (el) el.remove();
                    });
                });
        }

        await new Promise(resolve => setTimeout(resolve, 2000));

        // Step 1: Fill email
        console.error('[Hero] Filling email field...');
        const emailField = await hero.document.querySelector('#emailOrPhoneInput');
        if (!emailField) {
            throw new Error('Email field not found');
        }

        await emailField.click();
        await new Promise(resolve => setTimeout(resolve, 300));
        await emailField.type(email);
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Click Next button
        console.error('[Hero] Clicking Next button...');
        const nextBtn = await hero.document.querySelector('div.loginClass1 button');
        if (nextBtn) {
            await nextBtn.click();
        } else {
            // Fallback: use JS click
            await hero.executeJs(() => {
                document.querySelector('div.loginClass1 button')?.click();
            });
        }

        // Wait for password field
        console.error('[Hero] Waiting for password field...');
        await new Promise(resolve => setTimeout(resolve, 5000));

        let passwordAppeared = false;
        for (let i = 0; i < 15; i++) {
            const pwField = await hero.document.querySelector('#emailOrPhonePswInput');
            if (pwField) {
                const isVisible = await pwField.offsetParent;
                if (isVisible !== null) {
                    passwordAppeared = true;
                    console.error('[Hero] Password field appeared (SPA transition OK)');
                    break;
                }
            }
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        if (passwordAppeared) {
            // SPA flow: fill password
            console.error('[Hero] Filling password field...');
            const pwField = await hero.document.querySelector('#emailOrPhonePswInput');
            await pwField.click();
            await new Promise(resolve => setTimeout(resolve, 200));

            // Type password character by character with realistic delays
            for (const char of password) {
                await pwField.type(char);
                await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 70));
            }

            await new Promise(resolve => setTimeout(resolve, 5000));

            // Click submit button
            console.error('[Hero] Clicking submit button...');
            const submitBtn = await hero.document.querySelector('button.loadingBtnHide');
            if (submitBtn) {
                await submitBtn.click();
            } else {
                await hero.executeJs(() => {
                    document.querySelector('div.loginClass2 button')?.click();
                });
            }

            // Wait for redirect
            console.error('[Hero] Waiting for WUST redirect...');
            for (let i = 0; i < 25; i++) {
                const url = await hero.url;
                if (url.includes('lenovoid.wust') || url.includes('lenovoIdSuccess')) {
                    console.error('[Hero] Redirect detected!');
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        } else {
            // Direct form submission fallback
            console.error('[Hero] SPA blocked, using direct form submit...');

            // Get reCAPTCHA token
            const gt = await hero.executeJs(async () => {
                if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {
                    try {
                        return await grecaptcha.enterprise.execute(
                            '6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub',
                            { action: 'LOGIN' }
                        );
                    } catch (e) {
                        return '';
                    }
                }
                return '';
            }) || '';

            // Get bid field value
            const bid = await hero.executeJs(() => {
                const el = document.querySelector('.jsBid');
                return el ? el.value : '';
            }) || '';

            const hashedPw = hashPassword(password);

            // Fill and submit form directly
            await hero.executeJs((args) => {
                const form = document.querySelector('.loginClass2 form');
                if (!form) return;

                form.querySelectorAll('input[name="username"]')
                    .forEach(e => e.value = args.email);
                form.querySelectorAll('.emailAddressInput')
                    .forEach(e => e.value = args.email);
                form.querySelectorAll('input[name="password"]')
                    .forEach(e => e.value = args.hashed);
                form.querySelectorAll('input[name="loginfinish"]')
                    .forEach(e => e.value = '1');

                let gtEl = form.querySelector('input[name="gt"]');
                if (!gtEl) {
                    gtEl = document.createElement('input');
                    gtEl.type = 'hidden';
                    gtEl.name = 'gt';
                    form.appendChild(gtEl);
                }
                gtEl.value = args.gt;

                form.submit();
            }, { email, hashed: hashedPw, gt });

            await new Promise(resolve => setTimeout(resolve, 10000));
        }

        // Extract WUST from URL
        const finalUrl = await hero.url;
        console.error(`[Hero] Final URL: ${finalUrl.substring(0, 80)}...`);

        let wust = findWust(finalUrl);
        if (!wust) {
            // Try to get from page body
            const html = await hero.document.documentElement.outerHTML;
            wust = findWust(html);
        }

        if (wust) {
            console.error('[Hero] ✓ WUST token obtained successfully!');
            console.log(JSON.stringify({ success: true, wust }));
        } else {
            // Check for error messages
            const html = await hero.document.documentElement.outerHTML;
            const bodyLower = html.toLowerCase();

            let errorMsg = 'Login failed - no WUST token found';
            if (bodyLower.includes('incorrect password') || bodyLower.includes('contraseña incorrecta')) {
                errorMsg = 'Invalid credentials';
            } else if (bodyLower.includes('captcha') || bodyLower.includes('robot')) {
                errorMsg = 'CAPTCHA challenge detected';
            } else if (bodyLower.includes('blocked') && bodyLower.includes('akamai')) {
                errorMsg = 'Blocked by Akamai Bot Manager';
            }

            console.log(JSON.stringify({ success: false, error: errorMsg }));
        }

    } catch (error) {
        console.error(`[Hero] Error: ${error.message}`);
        console.log(JSON.stringify({ success: false, error: error.message }));
    } finally {
        await hero.close();
    }
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length < 3) {
        console.error('Usage: node hero_login.js <email> <password> <login_url>');
        process.exit(1);
    }

    const [email, password, loginUrl] = args;

    loginWithHero(email, password, loginUrl)
        .then(() => process.exit(0))
        .catch(err => {
            console.error(`[Hero] Fatal error: ${err}`);
            console.log(JSON.stringify({ success: false, error: err.message }));
            process.exit(1);
        });
}
