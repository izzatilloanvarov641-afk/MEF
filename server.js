require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mef-secret';
const ADMIN_USERNAMES = (process.env.ADMIN_USERNAMES || process.env.ADMIN_USERNAME || 'admin').split(',').map(u => u.trim().toLowerCase());
function userIsAdmin(username) { return ADMIN_USERNAMES.includes((username || '').toLowerCase()); }

// ── DATABASE ─────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ──────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.cookies.mef_token || (req.headers['authorization'] || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { data: user } = await supabase.from('users').select('*').eq('id', payload.userId).maybeSingle();
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = { id: user.id, username: user.username, email: user.email, games_played: user.games_played, games_won: user.games_won };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!userIsAdmin(req.user.username)) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ── AUTH ROUTES ──────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, underscores only' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
  const { data: existingEmail } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
  if (existingEmail) return res.status(409).json({ error: 'Email already registered' });
  const { data: existingUsername } = await supabase.from('users').select('id').eq('username', username).maybeSingle();
  if (existingUsername) return res.status(409).json({ error: 'Username taken' });
  const hash = await bcrypt.hash(password, 12);
  const id = Date.now().toString();
  const { error } = await supabase.from('users').insert({ id, username, email, password_hash: hash, games_played: 0, games_won: 0, best_ehs: 0, best_growth: 0, total_trades: 0, match_history: [], created_at: new Date().toISOString() });
  if (error) { console.error('Registration error:', error); return res.status(500).json({ error: 'Registration failed' }); }
  const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('mef_token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true, user: { id, username, email, games_played: 0, games_won: 0, isAdmin: userIsAdmin(username) } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
  if (!user) return res.status(401).json({ error: 'No account with that email' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect password' });
  await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('mef_token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true, user: { id: user.id, username: user.username, email: user.email, games_played: user.games_played, games_won: user.games_won, isAdmin: userIsAdmin(user.username) } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('mef_token');
  res.json({ success: true });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const { data: u } = await supabase.from('users').select('*').eq('id', req.user.id).maybeSingle();
  res.json({ user: { ...req.user, isAdmin: userIsAdmin(req.user.username), match_history: u.match_history || [], best_ehs: u.best_ehs || 0, best_growth: u.best_growth || 0, total_trades: u.total_trades || 0 } });
});

app.get('/api/leaderboard', async (req, res) => {
  const { data: users } = await supabase.from('users').select('username, games_played, games_won, best_ehs, best_growth');
  const leaderboard = (users || []).map(u => ({ username: u.username, games_played: u.games_played, games_won: u.games_won, best_ehs: u.best_ehs || 0, best_growth: u.best_growth || 0, win_rate: u.games_played > 0 ? Math.round(u.games_won / u.games_played * 100) : 0 }));
  leaderboard.sort((a, b) => b.games_won - a.games_won || b.best_ehs - a.best_ehs);
  res.json({ leaderboard: leaderboard.slice(0, 50) });
});

// ── GAME DATA ────────────────────────────────────────────────
const COUNTRIES = [
  // ── G20 ORIGINAL ────────────────────────────────────────────
  { id:'us', name:'United States', flag:'🇺🇸', gdp:29000, gdpCap:85000, pop:335, interest:5.25, tax:21, govSpend:25, exports:3050, imports:3200, inflation:3.1, growth:2.8, debt:122, currency:'USD', fxRate:1.00, unemployment:3.9, creditScore:9, creditLabel:'AA+', fdi:310, currencyStrength:100, budget:2000, resources:{oil:8,gas:8,coal:6,food:7,minerals:6,tech:10,manufacturing:9,pharma:9,finance:10,tourism:8} },
  { id:'cn', name:'China', flag:'🇨🇳', gdp:18600, gdpCap:13100, pop:1412, interest:3.45, tax:25, govSpend:32, exports:3380, imports:2590, inflation:0.3, growth:4.6, debt:84, currency:'CNY', fxRate:7.24, unemployment:5.1, creditScore:8, creditLabel:'A+', fdi:180, currencyStrength:100, budget:1200, resources:{oil:5,gas:5,coal:8,food:6,minerals:7,tech:8,manufacturing:10,pharma:6,finance:7,tourism:6} },
  { id:'de', name:'Germany', flag:'🇩🇪', gdp:4700, gdpCap:55600, pop:84, interest:4.50, tax:30, govSpend:45, exports:1710, imports:1560, inflation:2.3, growth:0.1, debt:64, currency:'EUR', fxRate:0.92, unemployment:3.4, creditScore:10, creditLabel:'AAA', fdi:120, currencyStrength:100, budget:800, resources:{oil:2,gas:3,coal:5,food:5,minerals:5,tech:9,manufacturing:10,pharma:8,finance:8,tourism:7} },
  { id:'jp', name:'Japan', flag:'🇯🇵', gdp:4200, gdpCap:33700, pop:125, interest:0.10, tax:30, govSpend:37, exports:765, imports:900, inflation:2.8, growth:0.9, debt:261, currency:'JPY', fxRate:149.5, unemployment:2.6, creditScore:9, creditLabel:'AA-', fdi:25, currencyStrength:100, budget:700, resources:{oil:1,gas:2,coal:3,food:4,minerals:3,tech:10,manufacturing:10,pharma:8,finance:9,tourism:8} },
  { id:'in', name:'India', flag:'🇮🇳', gdp:3900, gdpCap:2700, pop:1435, interest:6.50, tax:30, govSpend:16, exports:535, imports:720, inflation:4.8, growth:6.8, debt:84, currency:'INR', fxRate:83.1, unemployment:7.8, creditScore:7, creditLabel:'BBB-', fdi:71, currencyStrength:100, budget:600, resources:{oil:3,gas:4,coal:7,food:8,minerals:6,tech:8,manufacturing:7,pharma:9,finance:6,tourism:7} },
  { id:'uk', name:'United Kingdom', flag:'🇬🇧', gdp:3400, gdpCap:49600, pop:68, interest:5.25, tax:25, govSpend:42, exports:610, imports:690, inflation:2.5, growth:0.9, debt:98, currency:'GBP', fxRate:0.79, unemployment:4.2, creditScore:9, creditLabel:'AA', fdi:85, currencyStrength:100, budget:650, resources:{oil:4,gas:5,coal:3,food:4,minerals:3,tech:8,manufacturing:6,pharma:8,finance:10,tourism:9} },
  { id:'fr', name:'France', flag:'🇫🇷', gdp:3200, gdpCap:47400, pop:68, interest:4.50, tax:32, govSpend:55, exports:610, imports:720, inflation:2.1, growth:1.1, debt:110, currency:'EUR', fxRate:0.92, unemployment:7.3, creditScore:9, creditLabel:'AA-', fdi:90, currencyStrength:100, budget:600, resources:{oil:2,gas:2,coal:2,food:8,minerals:4,tech:7,manufacturing:7,pharma:8,finance:8,tourism:10} },
  { id:'br', name:'Brazil', flag:'🇧🇷', gdp:2200, gdpCap:10300, pop:215, interest:10.75, tax:34, govSpend:39, exports:340, imports:270, inflation:4.6, growth:2.9, debt:89, currency:'BRL', fxRate:4.97, unemployment:7.8, creditScore:6, creditLabel:'BB', fdi:65, currencyStrength:100, budget:400, resources:{oil:7,gas:6,coal:4,food:10,minerals:8,tech:4,manufacturing:5,pharma:5,finance:5,tourism:8} },
  { id:'it', name:'Italy', flag:'🇮🇹', gdp:2200, gdpCap:37200, pop:59, interest:4.50, tax:28, govSpend:48, exports:650, imports:590, inflation:1.7, growth:0.7, debt:137, currency:'EUR', fxRate:0.92, unemployment:6.7, creditScore:7, creditLabel:'BBB', fdi:40, currencyStrength:100, budget:400, resources:{oil:2,gas:3,coal:2,food:7,minerals:4,tech:6,manufacturing:8,pharma:7,finance:7,tourism:10} },
  { id:'ca', name:'Canada', flag:'🇨🇦', gdp:2200, gdpCap:55600, pop:40, interest:5.00, tax:28, govSpend:42, exports:580, imports:540, inflation:2.7, growth:1.3, debt:106, currency:'CAD', fxRate:1.36, unemployment:6.1, creditScore:10, creditLabel:'AAA', fdi:55, currencyStrength:100, budget:500, resources:{oil:9,gas:9,coal:6,food:8,minerals:8,tech:7,manufacturing:6,pharma:6,finance:8,tourism:7} },
  { id:'ru', name:'Russia', flag:'🇷🇺', gdp:2100, gdpCap:14500, pop:145, interest:16.00, tax:20, govSpend:35, exports:480, imports:360, inflation:9.0, growth:3.6, debt:17, currency:'RUB', fxRate:90.5, unemployment:2.9, creditScore:4, creditLabel:'CCC', fdi:-10, currencyStrength:100, budget:300, resources:{oil:10,gas:10,coal:8,food:7,minerals:9,tech:5,manufacturing:6,pharma:4,finance:3,tourism:5} },
  { id:'kr', name:'South Korea', flag:'🇰🇷', gdp:1800, gdpCap:35200, pop:52, interest:3.50, tax:25, govSpend:33, exports:635, imports:620, inflation:2.1, growth:2.3, debt:54, currency:'KRW', fxRate:1325, unemployment:2.8, creditScore:9, creditLabel:'AA', fdi:18, currencyStrength:100, budget:450, resources:{oil:1,gas:1,coal:2,food:4,minerals:4,tech:9,manufacturing:10,pharma:7,finance:7,tourism:6} },
  { id:'au', name:'Australia', flag:'🇦🇺', gdp:1800, gdpCap:68800, pop:26, interest:4.35, tax:30, govSpend:36, exports:380, imports:340, inflation:3.5, growth:1.5, debt:55, currency:'AUD', fxRate:1.53, unemployment:3.8, creditScore:10, creditLabel:'AAA', fdi:40, currencyStrength:100, budget:450, resources:{oil:7,gas:8,coal:9,food:7,minerals:10,tech:6,manufacturing:5,pharma:5,finance:7,tourism:8} },
  { id:'mx', name:'Mexico', flag:'🇲🇽', gdp:1500, gdpCap:11500, pop:130, interest:11.25, tax:30, govSpend:25, exports:575, imports:540, inflation:4.7, growth:1.5, debt:50, currency:'MXN', fxRate:17.2, unemployment:2.8, creditScore:7, creditLabel:'BBB-', fdi:36, currencyStrength:100, budget:300, resources:{oil:8,gas:6,coal:4,food:7,minerals:7,tech:4,manufacturing:7,pharma:4,finance:5,tourism:8} },
  { id:'id', name:'Indonesia', flag:'🇮🇩', gdp:1400, gdpCap:5000, pop:278, interest:6.00, tax:22, govSpend:16, exports:260, imports:220, inflation:2.8, growth:5.0, debt:39, currency:'IDR', fxRate:15600, unemployment:5.3, creditScore:7, creditLabel:'BBB', fdi:22, currencyStrength:100, budget:250, resources:{oil:6,gas:7,coal:7,food:9,minerals:8,tech:3,manufacturing:5,pharma:3,finance:4,tourism:7} },
  { id:'tr', name:'Turkey', flag:'🇹🇷', gdp:1250, gdpCap:14500, pop:86, interest:42.50, tax:22, govSpend:32, exports:255, imports:340, inflation:44.0, growth:3.2, debt:34, currency:'TRY', fxRate:32.5, unemployment:8.8, creditScore:5, creditLabel:'B', fdi:13, currencyStrength:100, budget:200, resources:{oil:2,gas:2,coal:5,food:6,minerals:5,tech:4,manufacturing:6,pharma:4,finance:5,tourism:8} },
  { id:'sa', name:'Saudi Arabia', flag:'🇸🇦', gdp:1100, gdpCap:30600, pop:36, interest:6.00, tax:20, govSpend:38, exports:330, imports:200, inflation:2.3, growth:1.8, debt:24, currency:'SAR', fxRate:3.75, unemployment:3.5, creditScore:8, creditLabel:'A', fdi:25, currencyStrength:100, budget:350, resources:{oil:10,gas:10,coal:2,food:2,minerals:5,tech:3,manufacturing:4,pharma:2,finance:6,tourism:5} },
  { id:'ar', name:'Argentina', flag:'🇦🇷', gdp:620, gdpCap:13200, pop:47, interest:40.00, tax:35, govSpend:38, exports:78, imports:60, inflation:140.0, growth:-2.8, debt:89, currency:'ARS', fxRate:870, unemployment:6.9, creditScore:1, creditLabel:'D', fdi:-5, currencyStrength:100, budget:100, resources:{oil:6,gas:7,coal:3,food:9,minerals:6,tech:3,manufacturing:4,pharma:3,finance:3,tourism:6} },
  { id:'za', name:'South Africa', flag:'🇿🇦', gdp:420, gdpCap:6800, pop:62, interest:8.25, tax:27, govSpend:32, exports:110, imports:120, inflation:5.3, growth:1.0, debt:74, currency:'ZAR', fxRate:18.7, unemployment:32.1, creditScore:6, creditLabel:'BB-', fdi:9, currencyStrength:100, budget:150, resources:{oil:3,gas:3,coal:8,food:5,minerals:9,tech:3,manufacturing:5,pharma:4,finance:5,tourism:6} },
  { id:'eu', name:'European Union', flag:'🇪🇺', gdp:19400, gdpCap:37000, pop:449, interest:4.50, tax:22, govSpend:46, exports:2800, imports:2650, inflation:2.3, growth:1.0, debt:82, currency:'EUR', fxRate:0.92, unemployment:6.0, creditScore:9, creditLabel:'AA', fdi:200, currencyStrength:100, budget:1500, resources:{oil:3,gas:4,coal:4,food:6,minerals:5,tech:8,manufacturing:8,pharma:9,finance:9,tourism:9} },
  // ── ASIA ────────────────────────────────────────────────────
  { id:'uz', name:'Uzbekistan', flag:'🇺🇿', gdp:100, gdpCap:2800, pop:36, interest:13.5, tax:12, govSpend:25, exports:22, imports:28, inflation:9.8, growth:5.8, debt:37, currency:'UZS', fxRate:12700, unemployment:9.1, creditScore:6, creditLabel:'BB-', fdi:4, currencyStrength:100, budget:100, resources:{oil:6,gas:8,coal:5,food:7,minerals:8,tech:3,manufacturing:5,pharma:2,finance:2,tourism:5} },
  { id:'pk', name:'Pakistan', flag:'🇵🇰', gdp:340, gdpCap:1500, pop:230, interest:17.0, tax:12, govSpend:22, exports:30, imports:60, inflation:23.0, growth:2.1, debt:74, currency:'PKR', fxRate:278, unemployment:6.3, creditScore:4, creditLabel:'CCC', fdi:2, currencyStrength:100, budget:150, resources:{oil:3,gas:5,coal:5,food:6,minerals:5,tech:4,manufacturing:5,pharma:4,finance:4,tourism:4} },
  { id:'bd', name:'Bangladesh', flag:'🇧🇩', gdp:450, gdpCap:2700, pop:170, interest:8.0, tax:10, govSpend:14, exports:55, imports:70, inflation:9.5, growth:5.8, debt:39, currency:'BDT', fxRate:110, unemployment:5.1, creditScore:6, creditLabel:'BB-', fdi:3, currencyStrength:100, budget:180, resources:{oil:2,gas:6,coal:2,food:7,minerals:2,tech:3,manufacturing:8,pharma:4,finance:3,tourism:3} },
  { id:'vn', name:'Vietnam', flag:'🇻🇳', gdp:430, gdpCap:4300, pop:98, interest:4.5, tax:20, govSpend:17, exports:390, imports:380, inflation:3.5, growth:6.1, debt:37, currency:'VND', fxRate:25000, unemployment:2.3, creditScore:6, creditLabel:'BB+', fdi:18, currencyStrength:100, budget:180, resources:{oil:4,gas:5,coal:5,food:8,minerals:5,tech:5,manufacturing:9,pharma:3,finance:4,tourism:7} },
  { id:'th', name:'Thailand', flag:'🇹🇭', gdp:540, gdpCap:7600, pop:71, interest:2.5, tax:20, govSpend:23, exports:295, imports:280, inflation:1.2, growth:2.8, debt:62, currency:'THB', fxRate:35, unemployment:1.1, creditScore:7, creditLabel:'BBB+', fdi:11, currencyStrength:100, budget:200, resources:{oil:3,gas:4,coal:2,food:8,minerals:5,tech:5,manufacturing:8,pharma:4,finance:6,tourism:9} },
  { id:'my', name:'Malaysia', flag:'🇲🇾', gdp:430, gdpCap:12500, pop:33, interest:3.0, tax:24, govSpend:19, exports:310, imports:270, inflation:2.1, growth:4.3, debt:67, currency:'MYR', fxRate:4.7, unemployment:3.4, creditScore:8, creditLabel:'A-', fdi:13, currencyStrength:100, budget:180, resources:{oil:6,gas:7,coal:3,food:7,minerals:7,tech:6,manufacturing:8,pharma:3,finance:7,tourism:7} },
  { id:'kz', name:'Kazakhstan', flag:'🇰🇿', gdp:260, gdpCap:13000, pop:19, interest:14.5, tax:20, govSpend:22, exports:85, imports:55, inflation:8.5, growth:4.8, debt:25, currency:'KZT', fxRate:460, unemployment:4.8, creditScore:7, creditLabel:'BBB-', fdi:10, currencyStrength:100, budget:150, resources:{oil:8,gas:8,coal:7,food:5,minerals:8,tech:3,manufacturing:5,pharma:2,finance:4,tourism:4} },
  // ── AFRICA ──────────────────────────────────────────────────
  { id:'ng', name:'Nigeria', flag:'🇳🇬', gdp:250, gdpCap:1100, pop:220, interest:27.5, tax:8, govSpend:12, exports:50, imports:65, inflation:33.0, growth:2.9, debt:38, currency:'NGN', fxRate:1600, unemployment:5.3, creditScore:5, creditLabel:'B-', fdi:5, currencyStrength:100, budget:150, resources:{oil:9,gas:8,coal:3,food:5,minerals:6,tech:3,manufacturing:3,pharma:2,finance:5,tourism:4} },
  { id:'eg', name:'Egypt', flag:'🇪🇬', gdp:400, gdpCap:3700, pop:105, interest:27.25, tax:22, govSpend:30, exports:50, imports:85, inflation:28.0, growth:2.7, debt:95, currency:'EGP', fxRate:48, unemployment:7.1, creditScore:5, creditLabel:'B', fdi:8, currencyStrength:100, budget:170, resources:{oil:5,gas:7,coal:2,food:5,minerals:5,tech:4,manufacturing:5,pharma:4,finance:5,tourism:8} },
  { id:'ke', name:'Kenya', flag:'🇰🇪', gdp:120, gdpCap:2200, pop:55, interest:13.0, tax:18, govSpend:24, exports:16, imports:28, inflation:5.1, growth:5.0, debt:72, currency:'KES', fxRate:130, unemployment:5.7, creditScore:5, creditLabel:'B+', fdi:1, currencyStrength:100, budget:110, resources:{oil:2,gas:2,coal:2,food:7,minerals:5,tech:5,manufacturing:4,pharma:3,finance:5,tourism:7} },
  { id:'et', name:'Ethiopia', flag:'🇪🇹', gdp:160, gdpCap:1300, pop:125, interest:7.0, tax:12, govSpend:17, exports:5, imports:20, inflation:28.0, growth:6.2, debt:55, currency:'ETB', fxRate:113, unemployment:3.5, creditScore:5, creditLabel:'B', fdi:2, currencyStrength:100, budget:120, resources:{oil:1,gas:2,coal:2,food:6,minerals:5,tech:3,manufacturing:4,pharma:2,finance:2,tourism:5} },
  { id:'ma', name:'Morocco', flag:'🇲🇦', gdp:140, gdpCap:3700, pop:37, interest:2.75, tax:30, govSpend:26, exports:50, imports:70, inflation:2.5, growth:3.2, debt:70, currency:'MAD', fxRate:10, unemployment:13.0, creditScore:6, creditLabel:'BB+', fdi:2, currencyStrength:100, budget:110, resources:{oil:2,gas:3,coal:2,food:6,minerals:8,tech:3,manufacturing:5,pharma:3,finance:4,tourism:7} },
  // ── EUROPE ──────────────────────────────────────────────────
  { id:'pl', name:'Poland', flag:'🇵🇱', gdp:850, gdpCap:22000, pop:38, interest:5.75, tax:19, govSpend:43, exports:420, imports:400, inflation:4.9, growth:2.9, debt:54, currency:'PLN', fxRate:4.0, unemployment:5.1, creditScore:8, creditLabel:'A-', fdi:15, currencyStrength:100, budget:280, resources:{oil:2,gas:3,coal:7,food:6,minerals:5,tech:6,manufacturing:7,pharma:5,finance:6,tourism:6} },
  { id:'nl', name:'Netherlands', flag:'🇳🇱', gdp:1100, gdpCap:62000, pop:18, interest:4.5, tax:26, govSpend:42, exports:700, imports:650, inflation:2.7, growth:0.6, debt:49, currency:'EUR', fxRate:0.92, unemployment:3.9, creditScore:10, creditLabel:'AAA', fdi:60, currencyStrength:100, budget:350, resources:{oil:3,gas:6,coal:2,food:7,minerals:3,tech:8,manufacturing:6,pharma:7,finance:9,tourism:7} },
  { id:'se', name:'Sweden', flag:'🇸🇪', gdp:560, gdpCap:53000, pop:10, interest:2.5, tax:22, govSpend:47, exports:270, imports:260, inflation:2.3, growth:0.5, debt:33, currency:'SEK', fxRate:10.5, unemployment:8.5, creditScore:10, creditLabel:'AAA', fdi:15, currencyStrength:100, budget:210, resources:{oil:1,gas:2,coal:2,food:5,minerals:7,tech:9,manufacturing:7,pharma:7,finance:7,tourism:6} },
  { id:'no', name:'Norway', flag:'🇳🇴', gdp:550, gdpCap:100000, pop:5.5, interest:4.5, tax:22, govSpend:44, exports:220, imports:115, inflation:3.1, growth:1.2, debt:18, currency:'NOK', fxRate:10.8, unemployment:3.9, creditScore:10, creditLabel:'AAA', fdi:13, currencyStrength:100, budget:250, resources:{oil:9,gas:10,coal:3,food:5,minerals:7,tech:7,manufacturing:5,pharma:5,finance:7,tourism:7} },
  { id:'es', name:'Spain', flag:'🇪🇸', gdp:1600, gdpCap:33000, pop:47, interest:4.5, tax:25, govSpend:46, exports:445, imports:460, inflation:2.8, growth:2.9, debt:105, currency:'EUR', fxRate:0.92, unemployment:11.4, creditScore:8, creditLabel:'A-', fdi:28, currencyStrength:100, budget:450, resources:{oil:2,gas:2,coal:3,food:7,minerals:4,tech:5,manufacturing:6,pharma:6,finance:7,tourism:10} },
  // ── AMERICAS ────────────────────────────────────────────────
  { id:'co', name:'Colombia', flag:'🇨🇴', gdp:370, gdpCap:7200, pop:52, interest:9.75, tax:35, govSpend:30, exports:58, imports:68, inflation:5.3, growth:1.7, debt:55, currency:'COP', fxRate:4200, unemployment:10.2, creditScore:6, creditLabel:'BB+', fdi:14, currencyStrength:100, budget:160, resources:{oil:6,gas:5,coal:7,food:7,minerals:6,tech:3,manufacturing:4,pharma:3,finance:5,tourism:6} },
  { id:'cl', name:'Chile', flag:'🇨🇱', gdp:320, gdpCap:16000, pop:19, interest:5.0, tax:27, govSpend:25, exports:100, imports:90, inflation:4.5, growth:2.3, debt:40, currency:'CLP', fxRate:950, unemployment:8.8, creditScore:8, creditLabel:'A-', fdi:17, currencyStrength:100, budget:150, resources:{oil:2,gas:4,coal:4,food:6,minerals:9,tech:4,manufacturing:5,pharma:3,finance:5,tourism:6} },
  { id:'pe', name:'Peru', flag:'🇵🇪', gdp:270, gdpCap:7900, pop:33, interest:6.75, tax:30, govSpend:18, exports:68, imports:60, inflation:3.2, growth:2.8, debt:34, currency:'PEN', fxRate:3.75, unemployment:7.4, creditScore:7, creditLabel:'BBB', fdi:8, currencyStrength:100, budget:140, resources:{oil:4,gas:5,coal:4,food:6,minerals:8,tech:3,manufacturing:4,pharma:3,finance:4,tourism:6} },
  { id:'ve', name:'Venezuela', flag:'🇻🇪', gdp:85, gdpCap:2900, pop:29, interest:58.0, tax:34, govSpend:45, exports:15, imports:12, inflation:180.0, growth:3.5, debt:160, currency:'VES', fxRate:40, unemployment:7.5, creditScore:1, creditLabel:'D', fdi:-5, currencyStrength:100, budget:90, resources:{oil:10,gas:9,coal:4,food:4,minerals:6,tech:2,manufacturing:3,pharma:2,finance:2,tourism:3} },
  // ── OCEANIA ──────────────────────────────────────────────────
  { id:'nz', name:'New Zealand', flag:'🇳🇿', gdp:250, gdpCap:47000, pop:5, interest:5.25, tax:28, govSpend:32, exports:65, imports:70, inflation:2.5, growth:0.8, debt:44, currency:'NZD', fxRate:1.65, unemployment:4.7, creditScore:9, creditLabel:'AA', fdi:4, currencyStrength:100, budget:150, resources:{oil:3,gas:4,coal:5,food:8,minerals:5,tech:5,manufacturing:4,pharma:4,finance:6,tourism:8} },
  { id:'pg', name:'Papua New Guinea', flag:'🇵🇬', gdp:30, gdpCap:3200, pop:10, interest:3.0, tax:30, govSpend:24, exports:12, imports:7, inflation:5.1, growth:4.2, debt:52, currency:'PGK', fxRate:3.9, unemployment:2.8, creditScore:5, creditLabel:'B+', fdi:2, currencyStrength:100, budget:80, resources:{oil:6,gas:7,coal:4,food:6,minerals:7,tech:2,manufacturing:2,pharma:1,finance:2,tourism:4} },
  // ── MIDDLE EAST ─────────────────────────────────────────────
  { id:'ae', name:'UAE', flag:'🇦🇪', gdp:530, gdpCap:53000, pop:10, interest:5.4, tax:9, govSpend:29, exports:450, imports:395, inflation:2.3, growth:4.0, debt:30, currency:'AED', fxRate:3.67, unemployment:3.1, creditScore:9, creditLabel:'AA-', fdi:24, currencyStrength:100, budget:220, resources:{oil:8,gas:9,coal:1,food:2,minerals:4,tech:5,manufacturing:5,pharma:3,finance:9,tourism:9} },
  { id:'ir', name:'Iran', flag:'🇮🇷', gdp:400, gdpCap:4600, pop:87, interest:23.0, tax:25, govSpend:40, exports:65, imports:60, inflation:40.0, growth:4.2, debt:30, currency:'IRR', fxRate:42000, unemployment:9.1, creditScore:1, creditLabel:'D', fdi:-3, currencyStrength:100, budget:160, resources:{oil:9,gas:10,coal:4,food:5,minerals:7,tech:4,manufacturing:5,pharma:3,finance:3,tourism:5} },
  { id:'il', name:'Israel', flag:'🇮🇱', gdp:550, gdpCap:58000, pop:9.5, interest:4.5, tax:23, govSpend:39, exports:165, imports:135, inflation:3.5, growth:1.5, debt:62, currency:'ILS', fxRate:3.7, unemployment:3.5, creditScore:8, creditLabel:'A+', fdi:20, currencyStrength:100, budget:220, resources:{oil:2,gas:6,coal:1,food:4,minerals:5,tech:10,manufacturing:7,pharma:7,finance:7,tourism:6} },
];

const COMMODITIES = [
  { id:'oil', name:'Oil', icon:'🛢', unit:'barrel', basePrice:85 },
  { id:'gas', name:'Natural Gas', icon:'🔥', unit:'MMBtu', basePrice:3.5 },
  { id:'coal', name:'Coal', icon:'⚫', unit:'metric ton', basePrice:140 },
  { id:'food', name:'Food', icon:'🌾', unit:'metric ton', basePrice:320 },
  { id:'minerals', name:'Minerals', icon:'⛏', unit:'metric ton', basePrice:800 },
  { id:'tech', name:'Technology', icon:'💡', unit:'unit', basePrice:4500 },
  { id:'manufacturing', name:'Manufacturing', icon:'⚙️', unit:'metric ton', basePrice:1200 },
  { id:'pharma', name:'Pharma', icon:'💊', unit:'kg', basePrice:6000 },
  { id:'finance', name:'Finance', icon:'💰', unit:'$B', basePrice:1000 },
  { id:'tourism', name:'Tourism', icon:'✈️', unit:'M visitors', basePrice:2000 }
];

const AI_PERSONALITIES = ['HAWK','DOVE','MERCANTILIST','ISOLATIONIST','OPPORTUNIST'];
const CREDIT_SPREAD = {10:0,9:0.2,8:0.5,7:1.0,6:2.0,5:3.5,4:5.5,3:8.0,2:12.0,1:18.0};
const CREDIT_LABELS = {10:'AAA',9:'AA',8:'A',7:'BBB',6:'BB',5:'B',4:'CCC',3:'CC',2:'C',1:'D'};

// ── ROOMS ────────────────────────────────────────────────────
const rooms = {};
const loanTimeouts = {};

function genCode() { return crypto.randomBytes(3).toString('hex').toUpperCase(); }
function deepClone(o) { return JSON.parse(JSON.stringify(o)); }
function getC(room, id) { return room.countries.find(c => c.id === id); }
function turnLabel(room) { const y=2025+room.turn-1; return `Year ${y}`; }

function sendState(code) {
  const room = rooms[code];
  if (!room) return;
  io.to(code).emit('stateUpdate', {
    code: room.code, phase: room.phase, turn: room.turn, maxTurns: room.maxTurns, turnTimestamps: room.turnTimestamps,
    players: room.players.map(p => ({ name:p.name, countryId:p.countryId, socketId:p.socketId, ready:p.ready, budget:p.budget, inventory:p.inventory, gdpCapStart:p.gdpCapStart, history:p.history, ehs:p.ehs, loans:p.loans })),
    countries: room.countries, commodityPrices: room.commodityPrices,
    marketOffers: room.marketOffers, completedDeals: room.completedDeals,
    eventLog: room.eventLog.slice(-80), chat: room.chat.slice(-50),
    sanctions: room.sanctions, alliances: room.alliances, tradeWars: room.tradeWars,
    loanRequests: room.loanRequests, justifications: room.justifications,
    disasters: room.disasters
  });
}

function sendAdmin(code) {
  const room = rooms[code];
  if (!room) return;
  const adminSocket = room.adminSocket;
  if (!adminSocket) return;
  io.to(adminSocket).emit('adminUpdate', {
    code: room.code, phase: room.phase, turn: room.turn,
    players: room.players, countries: room.countries,
    allDeals: room.completedDeals, allOffers: room.marketOffers,
    eventLog: room.eventLog, justifications: room.justifications,
    loanRequests: room.loanRequests, sanctions: room.sanctions
  });
}

// ── SIMULATION ───────────────────────────────────────────────
function calcEHS(c, startCap) {
  const gdpGrowth = ((c.gdpCap - startCap) / startCap) * 100;
  const g1 = Math.min(100, Math.max(0, (gdpGrowth / 15) * 100));
  const inf = c.inflation;
  const g2 = inf<=2?100:inf<=4?80:inf<=6?60:inf<=10?40:inf<=20?20:0;
  const d = c.debt;
  const g3 = d<40?100:d<60?85:d<80?70:d<100?50:d<130?30:d<160?15:0;
  const u = c.unemployment;
  const g4 = u<3?80:u<5?100:u<7?80:u<10?55:u<15?30:0;
  const g5 = Math.min(100, Math.max(0, (c.currencyStrength-40)/160*100));
  const ne = (c.exports-c.imports)/c.gdp*100;
  const g6 = ne>5?100:ne>2?85:ne>0?70:ne>-2?55:ne>-5?35:15;
  return Math.round(g1*0.30 + g2*0.20 + g3*0.15 + g4*0.15 + g5*0.10 + g6*0.10);
}

function simulateCountry(c, policy, room) {
  const q = turnLabel(room);

  // Influence = sqrt(gdp / 1000) — bigger economies hit harder, benefit more
  const myInfluence = Math.sqrt(Math.max(0.1, c.gdp) / 1000);

  // Weighted sanction effects — iterate per sanction using sanctioner's influence
  const activeSanctions = (room.sanctions||[]).filter(s=>s.target===c.id&&s.active);
  const sanctionCount = activeSanctions.length;
  let totalExportDrop=0, totalFdiDrop=0, totalCurrencyHit=0, totalCreditDrop=0;
  activeSanctions.forEach(s=>{
    const sc = s.from==='ADMIN' ? null : (room.countries||[]).find(co=>co.id===s.from);
    const si = sc ? Math.sqrt(Math.max(0.1, sc.gdp)/1000) : 3; // ADMIN = mid-tier influence
    const ratio = si / myInfluence;
    totalExportDrop  += 0.15 * ratio;
    totalFdiDrop     += 20   * ratio;
    totalCurrencyHit += 5    * ratio;
    totalCreditDrop  += 0.3  * (si / 5);
  });
  totalExportDrop  = Math.min(0.40, totalExportDrop);
  totalFdiDrop     = Math.min(100,  totalFdiDrop);
  totalCurrencyHit = Math.min(20,   totalCurrencyHit);
  totalCreditDrop  = Math.min(1.5,  totalCreditDrop);

  // Weighted alliance effects — larger partners give bigger bonus
  let allyGrowthEff=0, allyTradeDiscount=0;
  (room.alliances||[]).filter(a=>a.active&&(a.a===c.id||a.b===c.id)).forEach(a=>{
    const partnerId = a.a===c.id ? a.b : a.a;
    const partner = (room.countries||[]).find(co=>co.id===partnerId);
    const pi = partner ? Math.sqrt(Math.max(0.1, partner.gdp)/1000) : myInfluence;
    if(pi > myInfluence){
      allyGrowthEff    += Math.min(0.5, 0.1 * (pi / myInfluence));
      allyTradeDiscount += Math.min(0.30, 0.10 + 0.05 * (pi / myInfluence));
    } else {
      allyGrowthEff    += 0.05;
      allyTradeDiscount += 0.10;
    }
  });
  allyGrowthEff    = Math.min(1.0, allyGrowthEff);
  allyTradeDiscount = Math.min(0.30, allyTradeDiscount);

  // Apply policy
  if (policy && policy.interest !== undefined && policy.tax !== undefined && policy.govSpend !== undefined) {
    c.interest   = +policy.interest;
    c.tax        = +policy.tax;
    c.govSpend   = +policy.govSpend;
    c.tradeOpenness  = +(policy.tradeOpenness  ?? 0);
    c.monetaryPolicy = +(policy.monetaryPolicy ?? 0);
    c.infraSpend     = +(policy.infraSpend     ?? 0);
    c.rdSpend        = +(policy.rdSpend        ?? 0);
  } else {
    // AI — personality-driven with universal stress overrides
    const personality = c._personality || 'HAWK';
    if (personality === 'HAWK') {
      // Inflation-fighter: ceiling raised to 40 so high-inflation countries never accidentally get cut
      if (c.inflation > 4) c.interest = Math.min(40, c.interest + 1);
      else if (c.inflation < 2) c.interest = Math.max(1, c.interest - 0.25);
      if (c.debt > 100) c.govSpend = Math.max(20, c.govSpend - 1);
    } else if (personality === 'DOVE') {
      // Growth-first: stimulate hard in downturns, only tighten on severe inflation
      if (c.growth < 1) { c.interest = Math.max(0.5, c.interest - 0.5); c.govSpend = Math.min(55, c.govSpend + 2); }
      else if (c.inflation > 6) c.interest = Math.min(15, c.interest + 0.5);
    } else if (personality === 'MERCANTILIST') {
      // Export-driven: open trade, cut taxes, defend currency weakness
      c.tradeOpenness = Math.min(10, (c.tradeOpenness||0) + 1);
      c.tax = Math.max(15, c.tax - 0.5);
      if (c.currencyStrength < 70) c.interest = Math.min(25, c.interest + 0.5);
    } else if (personality === 'ISOLATIONIST') {
      // Self-sufficient: raise tax and domestic spending, close trade
      c.tradeOpenness = Math.max(0, (c.tradeOpenness||0) - 1);
      c.tax = Math.min(40, c.tax + 0.5);
      c.govSpend = Math.min(50, c.govSpend + 0.5);
      if (c.inflation > 5) c.interest = Math.min(20, c.interest + 0.5);
    } else {
      // OPPORTUNIST: chase FDI and growth, react decisively to inflation shocks
      if (c.creditScore >= 7) c.interest = Math.max(1, c.interest - 0.25);
      if (c.inflation > 5) c.interest = Math.min(25, c.interest + 1);
      if (c.growth < 0) c.govSpend = Math.min(50, c.govSpend + 1);
      c.tradeOpenness = Math.min(10, (c.tradeOpenness||0) + 0.5);
    }
    // Universal stress responses — override personality when in crisis
    if (sanctionCount > 0) c.interest = Math.min(30, c.interest + sanctionCount * 0.5);
    if (c.debt > 140) { c.govSpend = Math.max(20, c.govSpend - 2); c.tax = Math.min(40, c.tax + 1); }
    if (c.growth < -3) c.govSpend = Math.min(50, c.govSpend + 2);
    c.tradeOpenness = c.tradeOpenness || 0;
    c.monetaryPolicy = c.monetaryPolicy || 0;
    c.infraSpend = c.infraSpend || 0;
    c.rdSpend = c.rdSpend || 0;
  }

  const bc = c.interest + (CREDIT_SPREAD[Math.round(c.creditScore)] || 5);
  const intEff = c.interest<1?0.8:c.interest<3?0.4:c.interest<6?0.1:c.interest<10?-0.1:c.interest<20?-0.6:-1.2;
  const taxEff = c.tax<10?0.5:c.tax<20?0.3:c.tax<30?0:c.tax<40?-0.2:-0.5;
  // Very low spending (<10%) penalises growth — no free lunch below a public-goods floor
  const spEff = c.govSpend>60?-0.3:c.govSpend>50?0.1:c.govSpend>35?0.2:c.govSpend>20?0.15:c.govSpend>10?-0.1:-0.3;
  const debtP = c.debt>200?-1.5:c.debt>150?-0.8:c.debt>120?-0.4:c.debt>90?-0.15:0;
  const creditP = -(bc-5)*0.08;
  const tradeEff = (c.tradeOpenness||0)*0.05;
  const fdiEff = Math.min(0.4, Math.max(-0.3, c.fdi/400));
  const unempEff = c.unemployment>25?-1.0:c.unemployment>15?-0.5:c.unemployment>10?-0.2:c.unemployment>7?-0.05:c.unemployment<3?0.2:0;
  const currEff = c.currencyStrength<40?-0.8:c.currencyStrength<60?-0.3:c.currencyStrength<80?-0.1:c.currencyStrength>140?-0.1:0;
  const monEff = (c.monetaryPolicy||0)*0.15;
  const infraEff = (c._infraDelayed||0)*0.05;
  c._infraDelayed = c.infraSpend || 0;

  // Sanctions growth drag (tied to export drop magnitude)
  const sanctionEff = -Math.min(1.5, totalExportDrop * 2);
  // Alliance growth bonus (already computed above as allyGrowthEff)
  const allyEff = allyGrowthEff;

  // Disasters
  const activeDisasters = (room.disasters||[]).filter(d=>d.countryId===c.id&&d.turnsLeft>0);
  let disasterGdpEff = 0;
  activeDisasters.forEach(d => { disasterGdpEff += d.gdpEffect||0; });

  // Unbiased noise — removed the +0.015/turn positive drift
  // R&D: boosts long-run productivity growth (innovation effect)
  const rdEff = (c.rdSpend||0)*0.03;
  const noise = (Math.random()-0.5)*0.5;
  let base = intEff+taxEff+spEff+debtP+creditP+tradeEff+fdiEff+unempEff+currEff+monEff+infraEff+rdEff+sanctionEff+allyEff+disasterGdpEff+noise;
  // Real-world max sustained growth ~10% (China boom); peacetime depression floor ~-10%
  c.growth = Math.max(-10, Math.min(12, c.growth*0.5 + base));
  c.gdp *= (1 + c.growth/100);
  c.gdpCap *= (1 + c.growth/100);

  // Inflation
  const importInfl = c.currencyStrength<50?(50-c.currencyStrength)*0.12:c.currencyStrength<70?(70-c.currencyStrength)*0.06:0;
  const wageInfl = c.unemployment<3?0.6:c.unemployment<4?0.3:0;
  const demandPull = (c.govSpend-30)*0.03 + (c.monetaryPolicy||0)*0.4;
  const disasterInfl = activeDisasters.reduce((s,d)=>s+(d.inflationEffect||0),0);
  c.inflation = Math.max(0, Math.min(200, c.inflation + demandPull + importInfl + wageInfl - (c.interest-3)*0.15 + disasterInfl + (Math.random()-0.5)*0.4));

  // Unemployment — corrected Okun: 1pp growth → −0.4pp unemployment (was −0.1pp, 4× too small)
  // Clamped to ±2pp/turn to prevent extreme single-turn swings
  const okunEff = Math.max(-2, Math.min(1.5, -c.growth * 0.4));
  const phillipsEff = c.inflation>6?-0.2:c.inflation>4?-0.1:c.inflation<2?0.15:0;
  // R&D creates high-skill jobs, reduces structural unemployment
  const rdUnempEff = -(c.rdSpend||0)*0.04;
  const disasterUnemp = activeDisasters.reduce((s,d)=>s+(d.unemploymentEffect||0),0);
  // Mean-revert toward THIS country's own structural rate, not a universal 4.5%
  // (South Africa's natural rate is ~32%, not 4.5%)
  const naturalUnemp = c._naturalUnemp || 4.5;
  c.unemployment = Math.max(1, Math.min(40, c.unemployment + okunEff + phillipsEff + rdUnempEff + (naturalUnemp-c.unemployment)*0.03 + disasterUnemp + (Math.random()-0.5)*0.25));

  // Debt — tax revenue now genuinely offsets spending (taxRev was computed but never used before)
  // fiscalBalance: positive = deficit, negative = surplus; interest cost clamped to ≥0 (low-rate countries shouldn't get a free debt reduction)
  const fiscalBalance = c.govSpend - c.tax * 0.85;
  c.debt = Math.max(0, c.debt + fiscalBalance/4 - c.growth*0.4 + (c.debt>60?Math.max(0,bc-5)*0.02:0));

  // Credit rating
  let cs = c.creditScore;
  if(c.debt>160)cs-=2;else if(c.debt>130)cs-=1;else if(c.debt>100)cs-=0.5;else if(c.debt<40)cs+=0.3;
  if(c.inflation>25)cs-=2;else if(c.inflation>10)cs-=0.8;else if(c.inflation<3)cs+=0.15;
  if(c.growth<-3)cs-=0.8;else if(c.growth>5)cs+=0.3;
  if(c.fdi<-20)cs-=0.5;
  if(c.unemployment>20)cs-=0.4;
  if(totalCreditDrop>0)cs-=totalCreditDrop;
  const oldCS = Math.round(c.creditScore);
  // Rating agencies move slowly: cap at -1 notch down or +0.3 up per turn
  const csChange = cs - c.creditScore;
  c.creditScore = Math.max(1, Math.min(10, c.creditScore + Math.max(-1.0, Math.min(0.3, csChange))));
  const newCS = Math.round(c.creditScore);
  c.creditLabel = CREDIT_LABELS[newCS]||'B';
  if(newCS<oldCS) room.eventLog.push({quarter:q,text:`📉 ${c.flag} ${c.name} downgraded to ${c.creditLabel}`,country:c.id});
  else if(newCS>oldCS) room.eventLog.push({quarter:q,text:`📈 ${c.flag} ${c.name} upgraded to ${c.creditLabel}`,country:c.id});

  // IMF bailout
  if(c.debt>180&&c.creditScore<=3){
    room.eventLog.push({quarter:q,text:`🏦 ${c.flag} IMF BAILOUT — forced austerity imposed on ${c.name}`,global:true});
    c.govSpend=Math.min(c.govSpend,35);c.interest=Math.max(c.interest,8);c.debt-=10;
  }

  // Currency
  const worldAvgRate=5, worldAvgInfl=4;
  // Real interest rate differential drives capital flows (UIP) — not nominal
  // Turkey: nominal 42.5% but real = 42.5-44 = -1.5% → capital LEAVES despite high nominal rates
  const worldRealRate = worldAvgRate - worldAvgInfl;
  const rateEff = ((c.interest - c.inflation) - worldRealRate) * 0.5;
  const tradeBalEff=(c.exports-c.imports)/Math.max(c.gdp,1)*25;
  // PPP effect: high inflation erodes currency value independently of rates (reduced from 0.6 since real rate already captures part of this)
  const inflEff=-(c.inflation-worldAvgInfl)*0.25;
  const ratingEff=(c.creditScore-7)*0.4;
  const fdiCurrEff=c.fdi>0?Math.log(c.fdi+1)*0.25:c.fdi*0.06;
  const monCurrEff=-(c.monetaryPolicy||0)*0.3;
  const sanctCurrEff=-totalCurrencyHit;
  const disasterCurr=activeDisasters.reduce((s,d)=>s+(d.currencyEffect||0),0);
  const oldStr=c.currencyStrength;
  c.currencyStrength=Math.max(15,Math.min(220,c.currencyStrength+rateEff+tradeBalEff+inflEff+ratingEff+fdiCurrEff+monCurrEff+sanctCurrEff+disasterCurr+(Math.random()-0.5)*2));
  c.fxRate=c.fxRate*(oldStr/c.currencyStrength);
  if(c.currencyStrength<35&&oldStr>=35){
    room.eventLog.push({quarter:q,text:`🚨 ${c.flag} CURRENCY CRISIS — ${c.currency} collapsing!`,global:true});
    c.inflation+=20;c.growth-=3;
  }

  // FDI
  const taxAttr=(25-c.tax)*2.5,ratingAttr=(c.creditScore-5)*6,growthAttr=c.growth*4;
  const tradeAttr=(c.tradeOpenness||0)*5,inflRep=c.inflation>12?-(c.inflation-12)*0.6:0;
  const stabAttr=sanctionCount>0?-totalFdiDrop:5;
  c.fdi=Math.max(-60,Math.min(600,c.fdi+(taxAttr+ratingAttr+growthAttr+tradeAttr+inflRep+stabAttr)/10+(Math.random()-0.45)*5));

  // Exports: sanctions shrink them, ally trade discounts boost them.
  const fxExportBoost = Math.max(-0.02, Math.min(0.02, (100-c.currencyStrength)*0.0005));
  const sanctionExportDrag = totalExportDrop * 0.1; // applied per-turn (compounds gradually)
  const allyExportBoost = allyTradeDiscount * 0.01;
  c.exports *= (1 + Math.max(0,c.tradeOpenness||0)*0.005 + fxExportBoost + Math.random()*0.01 - sanctionExportDrag + allyExportBoost);

  // Imports: strong currency makes imports cheaper (more imports); growth raises incomes → more imports.
  // Protectionism (negative tradeOpenness) directly reduces imports.
  const fxImportEff = Math.max(-0.03, Math.min(0.03, (c.currencyStrength-100)*0.0004));
  const protectImportEff = Math.max(0, -(c.tradeOpenness||0)) * 0.003;
  c.imports *= (1 + fxImportEff + Math.max(0,c.growth)*0.002 - protectImportEff + Math.random()*0.008 - 0.002);

  // Tick down disaster turns
  room.disasters.forEach(d=>{if(d.countryId===c.id&&d.turnsLeft>0)d.turnsLeft--;});

  // Events
  if(c.inflation>10) room.eventLog.push({quarter:q,text:`${c.flag} High inflation ${c.inflation.toFixed(1)}%`,country:c.id});
  if(c.growth<-2) room.eventLog.push({quarter:q,text:`${c.flag} Economic contraction ${c.growth.toFixed(1)}%`,country:c.id});
  if(c.unemployment>15) room.eventLog.push({quarter:q,text:`${c.flag} Unemployment crisis ${c.unemployment.toFixed(1)}%`,country:c.id});
}

function fluctuatePrices(room) {
  COMMODITIES.forEach(cm=>{
    const chg=(Math.random()-0.45)*0.15;
    room.commodityPrices[cm.id]=Math.max(cm.basePrice*0.4,room.commodityPrices[cm.id]*(1+chg));
  });
}

function advanceTurn(room) {
  room.players.forEach(p=>{
    const c=getC(room,p.countryId);
    const policy=room.pendingActions[p.socketId]||null;
    simulateCountry(c,policy,room);
    c._history=c._history||[];c._history.push(c.gdpCap);
    p.history.push(c.gdpCap);
    const ehs=calcEHS(c,p.gdpCapStart);
    p.ehs.push(ehs);
    // Process loans
    p.loans.forEach(loan=>{
      if(loan.active&&loan.turnsLeft>0){
        const payment=loan.totalRepayment/loan.repaymentTurns;
        p.budget=Math.max(0,p.budget-payment);
        loan.turnsLeft--;
        if(loan.turnsLeft===0)loan.active=false;
      }
    });
    // Replenish budget
    p.budget+=c.gdp*0.02;
  });
  room.countries.forEach(c=>{
    if(!room.players.find(p=>p.countryId===c.id)){
      simulateCountry(c,null,room);
      c._history=c._history||[];c._history.push(c.gdpCap);
    }
  });
  fluctuatePrices(room);
  room.pendingActions={};
  room.players.forEach(p=>{p.ready=false;});
  room.turn++;
  room.turnTimestamps[room.turn]=new Date().toISOString();
  if(room.turn>room.maxTurns)room.phase='ended';
}

// ── SOCKET.IO ────────────────────────────────────────────────
async function authSocket(socket, cb) {
  const token = socket.handshake.auth.token || socket.handshake.headers.cookie?.split('mef_token=')[1]?.split(';')[0];
  if (!token) return cb(null);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { data: user } = await supabase.from('users').select('*').eq('id', payload.userId).maybeSingle();
    cb(user || null);
  } catch (e) { cb(null); }
}

io.on('connection', socket => {
  authSocket(socket, user => { socket.user = user; });

  socket.on('createRoom', ({ name }, cb) => {
    if (!socket.user) return cb({ success:false, error:'Not logged in' });
    if (!userIsAdmin(socket.user.username)) return cb({ success:false, error:'Only admins can create rooms' });
    const code = genCode();
    rooms[code] = {
      code, hostSocketId:socket.id, phase:'lobby', turn:1, maxTurns:5,
      players:[], countries:COUNTRIES.map(c=>{ const cl=deepClone(c); cl._personality=AI_PERSONALITIES[Math.floor(Math.random()*AI_PERSONALITIES.length)]; cl._history=[c.gdpCap]; cl._infraDelayed=0; cl._naturalUnemp=c.unemployment; return cl; }),
      commodityPrices:Object.fromEntries(COMMODITIES.map(c=>[c.id,c.basePrice])),
      marketOffers:[], completedDeals:[], eventLog:[], chat:[], offerCounter:0,
      pendingActions:{}, sanctions:[], alliances:[], tradeWars:[], loanRequests:[],
      justifications:[], disasters:[], adminSocket: socket.id,
      turnTimestamps:{1:new Date().toISOString()}
    };
    socket.join(code);
    socket.data.roomCode = code;
    cb({ success:true, code, isAdmin:true });
    sendState(code);
  });

  socket.on('joinRoom', ({ code, name }, cb) => {
    if (!socket.user) return cb({ success:false, error:'Not logged in' });
    const room = rooms[code];
    if (!room) return cb({ success:false, error:'Room not found' });
    if (room.phase !== 'lobby') return cb({ success:false, error:'Game already started' });
    const adminUser = userIsAdmin(socket.user.username);
    if (adminUser) {
      room.adminSocket = socket.id;
    } else {
      const existing = room.players.find(p => p.name === socket.user.username);
      if (existing) {
        existing.socketId = socket.id;
      } else {
        room.players.push({ socketId:socket.id, name:socket.user.username, countryId:null, ready:false, budget:0, inventory:Object.fromEntries(COMMODITIES.map(c=>[c.id,0])), gdpCapStart:0, history:[], ehs:[], loans:[] });
        io.to(code).emit('chat', { name:'System', text:`${socket.user.username} joined!`, system:true });
      }
    }
    socket.join(code);
    socket.data.roomCode = code;
    cb({ success:true, code, isAdmin:adminUser });
    sendState(code);
  });

  socket.on('rejoinRoom', ({ code }, cb) => {
    if (!socket.user) return cb({ success: false, error: 'Not logged in' });
    const room = rooms[code];
    if (!room) return cb({ success: false, error: 'Room not found' });
    const adminUser = userIsAdmin(socket.user.username);
    if (adminUser) {
      room.adminSocket = socket.id;
      socket.join(code);
      socket.data.roomCode = code;
      return cb({ success: true, isAdmin: true });
    }
    const player = room.players.find(p => p.name === socket.user.username);
    if (!player) return cb({ success: false, error: 'You are not in this room' });
    const oldSocketId = player.socketId;
    player.socketId = socket.id;
    if (room.pendingActions[oldSocketId] !== undefined) {
      room.pendingActions[socket.id] = room.pendingActions[oldSocketId];
      delete room.pendingActions[oldSocketId];
    }
    room.loanRequests.forEach(l => { if (l.socketId === oldSocketId) l.socketId = socket.id; });
    room.justifications.forEach(j => { if (j.socketId === oldSocketId) j.socketId = socket.id; });
    socket.join(code);
    socket.data.roomCode = code;
    cb({ success: true, isAdmin: false });
    sendState(code);
  });

  socket.on('selectCountry', ({ countryId }) => {
    const room = rooms[socket.data.roomCode]; if (!room) return;
    const p = room.players.find(p=>p.socketId===socket.id); if (!p) return;
    if (room.players.find(p2=>p2.socketId!==socket.id&&p2.countryId===countryId)) return;
    p.countryId = countryId;
    sendState(socket.data.roomCode);
  });

  socket.on('startGame', (_, cb) => {
    const room = rooms[socket.data.roomCode]; if (!room) return cb({ success:false });
    if (room.hostSocketId !== socket.id && room.adminSocket !== socket.id) return cb({ success:false, error:'Only host can start' });
    if (room.players.length === 0) return cb({ success:false, error:'Need at least 1 player' });
    if (room.players.some(p=>!p.countryId)) return cb({ success:false, error:'All players must pick a country' });
    room.phase = 'playing';
    room.players.forEach(p=>{
      const c = getC(room, p.countryId);
      p.gdpCapStart = c.gdpCap; p.history=[c.gdpCap]; p.ehs=[];
      p.budget = c.budget;
      c._inv = Object.fromEntries(COMMODITIES.map(cm=>[cm.id, c.resources[cm.id]*100]));
    });
    room.countries.forEach(c=>{ if(!c._inv)c._inv=Object.fromEntries(COMMODITIES.map(cm=>[cm.id,c.resources[cm.id]*100])); });
    cb({ success:true });
    sendState(socket.data.roomCode);
    io.to(socket.data.roomCode).emit('gameStarted', {});
  });

  socket.on('submitTurn', ({ policy, justification }) => {
    const code=socket.data.roomCode; const room=rooms[code]; if(!room||room.phase!=='playing')return;
    const p=room.players.find(p=>p.socketId===socket.id); if(!p||p.ready)return;
    room.pendingActions[socket.id]=policy;
    if(justification){ room.justifications.push({ turn:room.turn, playerName:p.name, countryId:p.countryId, text:justification, policy, adminScore:null, adminFeedback:null, socketId:socket.id }); }
    p.ready=true;
    io.to(code).emit('playerReady',{name:p.name});
    if(room.players.every(p=>p.ready)){
      advanceTurn(room);
      sendState(code);
      if(room.phase==='ended'){ endGame(code); io.to(code).emit('gameEnded',{}); }
      else io.to(code).emit('turnAdvanced',{turn:room.turn});
    } else { sendState(code); }
    sendAdmin(code);
  });

  socket.on('postOffer', ({comm,volume,price},cb)=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return cb({success:false});
    const p=room.players.find(p=>p.socketId===socket.id);if(!p)return cb({success:false});
    const c=getC(room,p.countryId);
    if((c._inv[comm]||0)<volume)return cb({success:false,error:'Not enough stock'});
    c._inv[comm]-=volume;
    const offer={id:'o'+(++room.offerCounter),sellerSocketId:socket.id,sellerName:p.name,sellerCountryId:p.countryId,sellerFlag:c.flag,comm,volume,price,turn:room.turn};
    room.marketOffers.push(offer);
    const cm=COMMODITIES.find(x=>x.id===comm);
    room.eventLog.push({quarter:turnLabel(room),text:`📤 ${c.flag} ${p.name} listed ${volume} ${cm.name} @ $${price.toLocaleString()}/unit`,global:true});
    cb({success:true});sendState(code);sendAdmin(code);
  });

  socket.on('cancelOffer',({offerId},cb)=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const idx=room.marketOffers.findIndex(o=>o.id===offerId&&o.sellerSocketId===socket.id);if(idx===-1)return;
    const o=room.marketOffers[idx];const c=getC(room,o.sellerCountryId);c._inv[o.comm]+=o.volume;
    room.marketOffers.splice(idx,1);cb&&cb({success:true});sendState(code);
  });

  socket.on('proposeTrade',({offerId,proposedPrice,proposedVolume})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const offer=room.marketOffers.find(o=>o.id===offerId);if(!offer)return;
    const buyer=room.players.find(p=>p.socketId===socket.id);if(!buyer)return;
    io.to(offer.sellerSocketId).emit('tradeProposal',{offerId,buyerName:buyer.name,buyerSocketId:socket.id,buyerCountryId:buyer.countryId,comm:offer.comm,originalPrice:offer.price,originalVolume:offer.volume,proposedPrice,proposedVolume,marketPrice:room.commodityPrices[offer.comm]});
  });

  socket.on('respondTrade',({offerId,buyerSocketId,proposedPrice,proposedVolume,accepted})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    if(!accepted){io.to(buyerSocketId).emit('tradeRejected',{offerId});return;}
    const offer=room.marketOffers.find(o=>o.id===offerId);if(!offer)return;
    const seller=room.players.find(p=>p.socketId===socket.id);
    const buyer=room.players.find(p=>p.socketId===buyerSocketId);
    if(!seller||!buyer)return;
    const volume=Math.min(proposedVolume,offer.volume);
    const total=proposedPrice*volume;
    if(buyer.budget<total){io.to(buyerSocketId).emit('tradeRejected',{offerId,reason:'Insufficient budget'});return;}
    buyer.budget-=total;seller.budget+=total;
    buyer.inventory[offer.comm]=(buyer.inventory[offer.comm]||0)+volume;
    const bc2=getC(room,buyer.countryId);const sc2=getC(room,seller.countryId);
    // Supply-chain boost: commodity matters — tech/finance/pharma > energy > food/tourism
    const SUPPLY_MULT={oil:0.003,gas:0.003,coal:0.002,food:0.001,minerals:0.002,tech:0.006,manufacturing:0.003,pharma:0.004,finance:0.004,tourism:0.001};
    const buyerBoost=Math.min(0.02,SUPPLY_MULT[offer.comm]||0.002);
    bc2.gdpCap*=(1+buyerBoost);bc2.gdp*=(1+buyerBoost);
    sc2.gdpCap*=1.001;sc2.gdp*=1.001;
    const oidx=room.marketOffers.findIndex(o=>o.id===offerId);
    if(oidx!==-1){if(volume>=room.marketOffers[oidx].volume)room.marketOffers.splice(oidx,1);else{room.marketOffers[oidx].volume-=volume;sc2._inv[offer.comm]+=(offer.volume-volume);}}
    const cm=COMMODITIES.find(x=>x.id===offer.comm);
    room.completedDeals.push({comm:offer.comm,volume,price:proposedPrice,buyerSocketId,sellerSocketId:socket.id,buyerName:buyer.name,sellerName:seller.name,buyerFlag:bc2.flag,sellerFlag:sc2.flag,turn:room.turn,total});
    room.eventLog.push({quarter:turnLabel(room),text:`🤝 ${bc2.flag}${buyer.name} ← ${volume} ${cm.name} ← ${sc2.flag}${seller.name} @ $${proposedPrice.toLocaleString()}/unit`,global:true});
    io.to(buyerSocketId).emit('tradeAccepted',{offerId});
    sendState(code);sendAdmin(code);
  });

  socket.on('proposeSanction',({targetId,reason})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const p=room.players.find(p=>p.socketId===socket.id);if(!p)return;
    const c=getC(room,p.countryId);const tc=getC(room,targetId);if(!tc)return;
    room.sanctions.push({from:p.countryId,fromFlag:c.flag,fromName:p.name,target:targetId,targetFlag:tc.flag,targetName:tc.name,reason,active:true,turn:room.turn});
    room.eventLog.push({quarter:turnLabel(room),text:`⚠ ${c.flag}${p.name} imposed sanctions on ${tc.flag}${tc.name}: "${reason}"`,global:true});
    sendState(code);sendAdmin(code);
  });

  socket.on('liftSanction',({targetId})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const p=room.players.find(p=>p.socketId===socket.id);if(!p)return;
    room.sanctions.forEach(s=>{if(s.from===p.countryId&&s.target===targetId)s.active=false;});
    sendState(code);
  });

  socket.on('proposeAlliance',({targetSocketId})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const p=room.players.find(p=>p.socketId===socket.id);if(!p)return;
    io.to(targetSocketId).emit('allianceProposal',{from:p.countryId,fromName:p.name,fromFlag:getC(room,p.countryId).flag,fromSocketId:socket.id});
  });

  socket.on('acceptAlliance',({fromSocketId})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const p=room.players.find(p=>p.socketId===socket.id);
    const fp=room.players.find(p=>p.socketId===fromSocketId);
    if(!p||!fp)return;
    room.alliances.push({a:p.countryId,b:fp.countryId,aName:p.name,bName:fp.name,active:true,turn:room.turn});
    const ca=getC(room,p.countryId);const cb=getC(room,fp.countryId);
    room.eventLog.push({quarter:turnLabel(room),text:`🤝 Alliance formed: ${ca.flag}${p.name} ↔ ${cb.flag}${fp.name}`,global:true});
    sendState(code);
  });

  socket.on('requestLoan',({amount,purpose})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const p=room.players.find(p=>p.socketId===socket.id);if(!p)return;
    const c=getC(room,p.countryId);
    room.loanRequests.push({id:'loan_'+Date.now(),playerName:p.name,countryId:p.countryId,countryFlag:c.flag,creditScore:c.creditScore,creditLabel:c.creditLabel,debtPct:c.debt,amount,purpose,status:'pending',socketId:socket.id,turn:room.turn});
    room.eventLog.push({quarter:turnLabel(room),text:`🏦 ${c.flag}${p.name} requested World Bank loan of $${amount}B`,country:c.id});
    sendAdmin(code);sendState(code);
  });

  // ADMIN EVENTS
  socket.on('adminImposeSanction',({code,countryId,reason})=>{
    const room=rooms[code];if(!room)return;
    if(!userIsAdmin(socket.user?.username))return;
    const c=getC(room,countryId);if(!c)return;
    room.sanctions.push({from:'ADMIN',fromFlag:'🌐',fromName:'Admin',target:countryId,targetFlag:c.flag,targetName:c.name,reason,active:true,turn:room.turn});
    room.eventLog.push({quarter:turnLabel(room),text:`🌐 ADMIN sanction imposed on ${c.flag}${c.name}: "${reason}"`,global:true});
    sendState(code);sendAdmin(code);
  });

  socket.on('adminDisaster',({code,countryId,disasterType})=>{
    const room=rooms[code];if(!room)return;
    if(!userIsAdmin(socket.user?.username))return;
    const c=getC(room,countryId);if(!c)return;
    const DISASTERS={
      earthquake:{name:'Earthquake',gdpEffect:-2.0,inflationEffect:3,unemploymentEffect:2,currencyEffect:-2,turnsLeft:1},
      flood:{name:'Major Flood',gdpEffect:-1.5,inflationEffect:2,unemploymentEffect:1.5,currencyEffect:-1,turnsLeft:1},
      drought:{name:'Severe Drought',gdpEffect:-1.0,inflationEffect:4,unemploymentEffect:1,currencyEffect:-1,turnsLeft:2},
      pandemic:{name:'Pandemic',gdpEffect:-3.0,inflationEffect:-1,unemploymentEffect:5,currencyEffect:-5,turnsLeft:2},
      hurricane:{name:'Hurricane',gdpEffect:-1.8,inflationEffect:2,unemploymentEffect:2,currencyEffect:-2,turnsLeft:1},
      bankingCrisis:{name:'Banking Crisis',gdpEffect:-2.5,inflationEffect:-1,unemploymentEffect:2,currencyEffect:-10,turnsLeft:2},
      hyperinflation:{name:'Hyperinflation Shock',gdpEffect:-1.0,inflationEffect:30,unemploymentEffect:1,currencyEffect:-20,turnsLeft:1},
      energyCrisis:{name:'Energy Crisis',gdpEffect:-1.8,inflationEffect:8,unemploymentEffect:1,currencyEffect:-5,turnsLeft:2},
      foodCrisis:{name:'Food Price Crisis',gdpEffect:-0.5,inflationEffect:10,unemploymentEffect:0.5,currencyEffect:-3,turnsLeft:1},
      stockCrash:{name:'Stock Market Crash',gdpEffect:-2.0,inflationEffect:-2,unemploymentEffect:2,currencyEffect:-8,turnsLeft:1},
    };
    const d=DISASTERS[disasterType];if(!d)return;
    room.disasters.push({...d,countryId,countryFlag:c.flag,imposedAt:room.turn});
    room.eventLog.push({quarter:turnLabel(room),text:`🌪 ADMIN imposed ${d.name} on ${c.flag}${c.name}!`,global:true});
    io.to(code).emit('disasterStruck',{countryId,countryFlag:c.flag,countryName:c.name,disasterName:d.name});
    sendState(code);sendAdmin(code);
  });

  socket.on('adminApproveLoan',({code,loanId,approvedAmount,interestRate,repaymentTurns,note})=>{
    const room=rooms[code];if(!room)return;
    if(!userIsAdmin(socket.user?.username))return;
    const loan=room.loanRequests.find(l=>l.id===loanId);if(!loan)return;
    loan.status='awaiting_player';loan.approvedAmount=approvedAmount;loan.interestRate=interestRate;loan.repaymentTurns=repaymentTurns;loan.note=note;
    // Auto-reject after 5 minutes if player doesn't respond
    if(loanTimeouts[loanId])clearTimeout(loanTimeouts[loanId]);
    loanTimeouts[loanId]=setTimeout(()=>{
      if(loan.status==='awaiting_player'){
        loan.status='auto_rejected';
        io.to(loan.socketId).emit('loanRejected',{note:'Loan offer expired — no response within 5 minutes.'});
        sendAdmin(code);
      }
      delete loanTimeouts[loanId];
    },5*60*1000);
    io.to(loan.socketId).emit('loanCounterOffer',{loanId,approvedAmount,interestRate,repaymentTurns,note});
    sendAdmin(code);
  });

  socket.on('acceptLoan',({loanId})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const loan=room.loanRequests.find(l=>l.id===loanId);if(!loan||loan.status!=='awaiting_player'||loan.socketId!==socket.id)return;
    if(loanTimeouts[loanId]){clearTimeout(loanTimeouts[loanId]);delete loanTimeouts[loanId];}
    loan.status='approved';
    const totalRepayment=loan.approvedAmount*(1+loan.interestRate/100);
    const p=room.players.find(p=>p.socketId===loan.socketId);
    if(p){
      p.budget+=loan.approvedAmount;
      p.loans.push({id:loanId,amount:loan.approvedAmount,interestRate:loan.interestRate,totalRepayment,repaymentTurns:loan.repaymentTurns,turnsLeft:loan.repaymentTurns,active:true});
      const c=getC(room,p.countryId);c.debt+=loan.approvedAmount/c.gdp*100;
    }
    room.eventLog.push({quarter:turnLabel(room),text:`🏦 World Bank approved $${loan.approvedAmount}B loan to ${loan.countryFlag}${loan.playerName} at ${loan.interestRate}% interest`,global:true});
    io.to(loan.socketId).emit('loanApproved',{amount:loan.approvedAmount,interestRate:loan.interestRate,repaymentTurns:loan.repaymentTurns,note:loan.note});
    sendState(code);sendAdmin(code);
  });

  socket.on('rejectLoan',({loanId})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const loan=room.loanRequests.find(l=>l.id===loanId);if(!loan||loan.status!=='awaiting_player'||loan.socketId!==socket.id)return;
    if(loanTimeouts[loanId]){clearTimeout(loanTimeouts[loanId]);delete loanTimeouts[loanId];}
    loan.status='player_rejected';
    io.to(loan.socketId).emit('loanRejected',{note:'You declined the loan offer.'});
    sendAdmin(code);
  });

  socket.on('adminRejectLoan',({code,loanId,note})=>{
    const room=rooms[code];if(!room)return;
    if(!userIsAdmin(socket.user?.username))return;
    const loan=room.loanRequests.find(l=>l.id===loanId);if(!loan)return;
    if(loanTimeouts[loanId]){clearTimeout(loanTimeouts[loanId]);delete loanTimeouts[loanId];}
    loan.status='rejected';loan.note=note;
    io.to(loan.socketId).emit('loanRejected',{note});
    sendAdmin(code);
  });

  socket.on('adminScoreJustification',({code,idx,score,feedback})=>{
    const room=rooms[code];if(!room)return;
    if(!userIsAdmin(socket.user?.username))return;
    const j=room.justifications[idx];if(!j)return;
    j.adminScore=score;j.adminFeedback=feedback;
    io.to(j.socketId).emit('justificationFeedback',{score,feedback,turn:j.turn});
    sendAdmin(code);
  });

  socket.on('adminAdjustIndicator',({code,countryId,field,value})=>{
    const room=rooms[code];if(!room)return;
    if(!userIsAdmin(socket.user?.username))return;
    const c=getC(room,countryId);if(!c)return;
    c[field]=value;
    sendState(code);sendAdmin(code);
  });

  socket.on('chat',({text})=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const msg={name:socket.user?.username||'Unknown',text:text.slice(0,200),ts:Date.now()};
    room.chat.push(msg);io.to(code).emit('chat',msg);
  });

  socket.on('disconnect',()=>{
    const code=socket.data.roomCode;const room=rooms[code];if(!room)return;
    const p=room.players.find(p=>p.socketId===socket.id);
    if(p)io.to(code).emit('chat',{name:'System',text:`${p.name} disconnected`,system:true});
  });
});

// ── END GAME ─────────────────────────────────────────────────
async function endGame(code) {
  const room = rooms[code];
  if (!room) return;
  const sorted = [...room.players].sort((a,b)=>{
    const aEhs=a.ehs.reduce((s,v)=>s+v,0)/Math.max(a.ehs.length,1);
    const bEhs=b.ehs.reduce((s,v)=>s+v,0)/Math.max(b.ehs.length,1);
    return bEhs-aEhs;
  });
  for (const [i, p] of sorted.entries()) {
    const { data: u } = await supabase.from('users').select('*').eq('username', p.name).maybeSingle();
    if (!u) continue;
    const c = getC(room, p.countryId);
    const avgEhs = p.ehs.reduce((s,v)=>s+v,0)/Math.max(p.ehs.length,1);
    const growth = ((c.gdpCap - p.gdpCapStart) / p.gdpCapStart * 100).toFixed(1);
    const match_history = [...(u.match_history || []), { date: new Date().toISOString(), country: p.countryId, final_ehs: Math.round(avgEhs), rank: i+1, growth }].slice(-20);
    await supabase.from('users').update({
      games_played: (u.games_played || 0) + 1,
      games_won: (u.games_won || 0) + (i === 0 ? 1 : 0),
      best_ehs: Math.max(u.best_ehs || 0, Math.round(avgEhs)),
      best_growth: Math.max(u.best_growth || 0, parseFloat(growth)),
      match_history
    }).eq('username', p.name);
  }
}

// ── ADMIN API ────────────────────────────────────────────────
app.get('/api/admin/rooms', requireAdmin, (req, res) => {
  const activeRooms = Object.values(rooms).map(r => ({
    code: r.code,
    phase: r.phase,
    playerCount: r.players.length,
    turn: r.turn,
    maxTurns: r.maxTurns
  }));
  res.json({ rooms: activeRooms });
});

// ── SERVE PAGES ──────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`\n✅ MEF server running → http://localhost:${PORT}\n   Admins: ${ADMIN_USERNAMES.join(', ')} — visit /admin\n`);
});
