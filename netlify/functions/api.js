const express = require('express');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const serverless = require('serverless-http');

const app = express();
const DB_PATH = '/tmp/database.json';
const JWT_SECRET = 'super-secret-key-dapur-6767';
const ADMIN_EMAIL = 'alimmfirmansyahhh@gmail.com';

const readDB = () => {
    if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }));
    try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch (e) { return { users: [] }; }
};
const writeDB = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

const dbData = readDB();
if (!dbData.users.find(u => u.email === ADMIN_EMAIL)) {
    dbData.users.push({ id: Date.now(), email: ADMIN_EMAIL, password: bcrypt.hashSync('muhlis144', 10), is_vip: 1, di_user: '', di_pass: '' });
    writeDB(dbData);
}

app.use((req, res, next) => {
    if (req.url.startsWith('/.netlify/functions/api')) req.url = req.url.replace('/.netlify/functions/api', '');
    if (!req.url.startsWith('/')) req.url = '/' + req.url;
    next();
});
app.use(express.json());
app.use(cookieParser());

const requireAuth = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Akses ditolak.' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch (err) { return res.status(401).json({ error: 'Sesi expired.' }); }
};

app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !email.toLowerCase().endsWith('@gmail.com')) return res.status(400).json({ error: 'Wajib pake email @gmail.com!' });
    const db = readDB();
    if (db.users.find(u => u.email === email.toLowerCase())) return res.status(400).json({ error: 'Email sudah dipakai.' });
    db.users.push({ id: Date.now(), email: email.toLowerCase(), password: bcrypt.hashSync(password, 10), is_vip: 0, di_user: '', di_pass: '' });
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.email === email.toLowerCase());
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
        res.cookie('auth_token', token, { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 86400000 });
        res.json({ success: true });
    } else { res.status(401).json({ error: 'Email atau password salah.' }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('auth_token'); res.json({ success: true }); });

app.get('/api/me', requireAuth, (req, res) => {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    res.json({ id: user.id, email: user.email, is_vip: user.is_vip, di_user: user.di_user, di_pass: user.di_pass });
});

app.post('/api/save-creds', requireAuth, (req, res) => {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (user) { user.di_user = req.body.di_user; user.di_pass = req.body.di_pass; writeDB(db); }
    res.json({ success: true });
});

app.post('/api/check-location', requireAuth, async (req, res) => {
    const { ip } = req.body;
    const endpoints = [
        { name: 'ipapi.is', url: `https://api.ipapi.is/?q=${ip}` },
        { name: 'ipwho.is', url: `https://ipwho.is/${ip}` },
        { name: 'ipinfo.io', url: `https://ipinfo.io/${ip}/json` },
        { name: 'ipapi.co', url: `https://ipapi.co/${ip}/json/` },
        { name: 'freeipapi.com', url: `https://freeipapi.com/api/json/${ip}` },
        { name: 'geojs.io', url: `https://get.geojs.io/v1/ip/geo/${ip}.json` },
        { name: 'db-ip.com', url: `https://api.db-ip.com/v2/free/${ip}` },
        { name: 'ipwhois.app', url: `https://ipwhois.app/json/${ip}` }
    ];
    const results = await Promise.all(endpoints.map(async (ep) => {
        try {
            const response = await axios.get(ep.url, { timeout: 6000 });
            const d = response.data;
            let city = d.city || d.cityName || (d.location && d.location.city) || '-';
            let region = d.region || d.regionName || d.stateProv || (d.location && d.location.state) || '-';
            let country = d.country || d.country_name || d.countryName || (d.location && d.location.country) || '-';
            let zip = d.postal || d.zip || (d.location && d.location.zip) || '-';
            let asn = '-';
            if (ep.name === 'ipwho.is') asn = d.connection?.asn;
            else if (ep.name === 'ipapi.is') asn = d.asn?.asn;
            else if (ep.name === 'ipinfo.io') asn = d.org ? d.org.split(' ')[0].replace('AS', '') : '-';
            else if (ep.name === 'ipapi.co') asn = d.asn ? d.asn.replace('AS', '') : '-';
            else if (ep.name === 'freeipapi.com') asn = d.asn;
            else if (ep.name === 'geojs.io') asn = d.asn;
            else if (ep.name === 'ipwhois.app') asn = d.asn;
            if (city === '-' && region === '-' && asn === '-') return { name: ep.name, status: 'Tidak ada data lokasi' };
            return { name: ep.name, status: 'ok', city, region, country, zip, asn: asn || '-' };
        } catch (err) { return { name: ep.name, status: 'Tidak ada data lokasi' }; }
    }));
    res.json({ results });
});

app.post('/api/auto-check', requireAuth, async (req, res) => {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user || !user.is_vip) return res.status(403).json({ error: 'Akses Ditolak. Bukan VIP.' });
    if (!user.di_user || !user.di_pass) return res.status(400).json({ error: 'Kredensial DI kosong.' });

    const { targetIp } = req.body;

    try {
        const geoRes = await axios.get(`https://ipwho.is/${targetIp}`);
        const geo = geoRes.data;
        if (!geo.success) return res.status(400).json({ error: 'IP target invalid.' });

        const c = geo.country_code.toLowerCase();
        const st = geo.region.toLowerCase().replace(/ /g, '');
        const ct = geo.city.toLowerCase().replace(/ /g, '');
        const zp = geo.postal || '';
        const asn = geo.connection.asn || '';

        const scenarios = [
            { name: 'FULL + ZIP', params: { cr: c, state: st, city: ct, zip: zp, asn: asn } },
            { name: 'FULL (Region+City+ASN)', params: { cr: c, state: st, city: ct, asn: asn } },
            { name: 'STATE + ASN', params: { cr: c, state: st, asn: asn } },
            { name: 'KOTA tanpa ASN', params: { cr: c, state: st, city: ct } },
            { name: 'PROVINSI tanpa ASN', params: { cr: c, state: st } },
            { name: 'ASN_ONLY', params: { cr: c, asn: asn } },
            { name: 'COUNTRY_ONLY', params: { cr: c } }
        ];

        const results = [];
        let foundPerfect = false;

        for (const scenario of scenarios) {
            if (foundPerfect) {
                results.push({ name: scenario.name, username: `-`, status: 'Skip', error: 'Dilewati (Sudah dapat yang cocok)' });
                continue;
            }

            const pStr = Object.entries(scenario.params).filter(([_,v]) => v).map(([k,v]) => `${k}.${v}`).join(';');
            const username = `${user.di_user}__${pStr}`;
            const proxyUrl = `http://${username}:${user.di_pass}@gw.dataimpulse.com:823`;
            const agent = new HttpsProxyAgent(proxyUrl);
            const start = Date.now();

            try {
                const r = await axios.get('https://ipwho.is/', { httpsAgent: agent, timeout: 4000 });
                const timeMs = Date.now() - start;
                
                if (r.data.success) {
                    const rCountry = (r.data.country_code || '').toLowerCase();
                    
                    // Validasi Mutlak: Kalau beda negara, reject!
                    if (rCountry !== c) {
                        results.push({ name: scenario.name, username: username, status: 'Gagal', error: `Meleset ke ${r.data.country} (${r.data.country_code})` });
                        continue;
                    }

                    const rCity = (r.data.city || '').toLowerCase().replace(/ /g, '');
                    const rRegion = (r.data.region || '').toLowerCase().replace(/ /g, '');
                    const rAsn = String(r.data.connection.asn);

                    const isCountry = true; 
                    const isState = rRegion === st;
                    const isCity = rCity === ct;
                    const isAsn = rAsn === String(asn);

                    let pct = 30; // Minimal dapet negara
                    if (isState) pct += 20;
                    if (isCity) pct += 20;
                    if (isAsn) pct += 30;

                    let finalUsername = username;
                    if (pct >= 75) {
                        const fullParams = { cr: c, state: st, city: ct, zip: zp, asn: asn };
                        const fullPStr = Object.entries(fullParams).filter(([_,v]) => v).map(([k,v]) => `${k}.${v}`).join(';');
                        finalUsername = `${user.di_user}__${fullPStr}`;
                        foundPerfect = true; // Berenti loop
                    }

                    results.push({
                        name: scenario.name, username: finalUsername, status: 'Sukses', percentage: pct, time: (timeMs / 1000).toFixed(1) + ' dtk',
                        exitIp: r.data.ip, exitCity: r.data.city, exitRegion: r.data.region, exitAsn: r.data.connection.asn, exitIsp: r.data.connection.isp,
                        matchDetails: { country: isCountry, state: isState, city: isCity, asn: isAsn }
                    });
                } else {
                    results.push({ name: scenario.name, username: username, status: 'Gagal', error: 'IP Kosong.' });
                }
            } catch (e) {
                results.push({ name: scenario.name, username: username, status: 'Gagal', error: 'Timeout / Gateway 503.' });
            }
        }

        const targetInfo = { ip: targetIp, country: geo.country_code, region: geo.region, city: geo.city, zip: geo.postal, asn: geo.connection.asn, isp: geo.connection.isp };
        res.json({ results, targetInfo });

    } catch (err) { res.status(500).json({ error: 'Gagal nembak API IP/Proxy.' }); }
});

const requireAdmin = (req, res, next) => {
    if (req.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'Bukan Owner.' });
    next();
};
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => res.json(readDB().users));
app.post('/api/admin/grant-vip', requireAuth, requireAdmin, (req, res) => {
    const db = readDB();
    const user = db.users.find(u => u.id === req.body.userId);
    if (user) { user.is_vip = req.body.isVip ? 1 : 0; writeDB(db); }
    res.json({ success: true });
});

module.exports.handler = serverless(app);
