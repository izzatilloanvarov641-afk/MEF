require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mef-secret';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

// ── DATABASE ─────────────────────────────────────────────────
const adapter = new FileSync('mef-db.json');
const db = low(adapter);
db.defaults({ users: [], matches: [] }).write();

// ── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ──────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies.mef_token || (req.headers['authorization'] || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.get('users').find({ id: payload.userId }).value();
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = { id: user.id, username: user.username, email: user.email, games_played: user.games_played, games_won: user.games_won };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.username !== ADMIN_USERNAME) return res.status(403).json({ error: 'Admin only' });
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
  if (db.get('users').find({ email }).value()) return res.status(409).json({ error: 'Email already registered' });
  if (db.get('users').find({ username }).value()) return res.status(409).json({ error: 'Username taken' });
  const hash = await bcrypt.hash(password, 12);
  const id = Date.now().toString();
  db.get('users').push({ id, username, email, password_hash: hash, games_played: 0, games_won: 0, best_ehs: 0, best_growth: 0, total_trades: 0, match_history: [], created_at: new Date().toISOString() }).write();
  const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('mef_token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true, user: { id, username, email, games_played: 0, games_won: 0, isAdmin: username === ADMIN_USERNAME } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(401).json({ error: 'No account with that email' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect password' });
  db.get('users').find({ id: user.id }).assign({ last_login: new Date().toISOString() }).write();
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('mef_token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true, user: { id: user.id, username: user.username, email: user.email, games_played: user.games_played, games_won: user.games_won, isAdmin: user.username === ADMIN_USERNAME } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('mef_token');
  res.json({ success: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const u = db.get('users').find({ id: req.user.id }).value();
  res.json({ user: { ...req.user, isAdmin: req.user.username === ADMIN_USERNAME, match_history: u.match_history || [], best_ehs: u.best_ehs || 0, best_growth: u.best_growth || 0, total_trades: u.total_trades || 0 } });
});

app.get('/api/leaderboard', (req, res) => {
  const users = db.get('users').value().map(u => ({ username: u.username, games_played: u.games_played, games_won: u.games_won, best_ehs: u.best_ehs || 0, best_growth: u.best_growth || 0, win_rate: u.games_played > 0 ? Math.round(u.games_won / u.games_played * 100) : 0 }));
  users.sort((a, b) => b.games_won - a.games_won || b.best_ehs - a.best_ehs);
  res.json({ leaderboard: users.slice(0, 50) });
});

// ── GAME DATA ────────────────────────────────────────────────
const G20 = [
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
  { id:'eu', name:'European Union', flag:'🇪🇺', gdp:19400, gdpCap:37000, pop:449, interest:4.50, tax:22, govSpend:46, exports:2800, imports:2650, inflation:2.3, growth:1.0, debt:82, currency:'EUR', fxRate:0.92, unemployment:6.0, creditScore:9, creditLabel:'AA', fdi:200, currencyStrength:100, budget:1500, resources:{oil:3,gas:4,coal:4,food:6,minerals:5,tech:8,manufacturing:8,pharma:9,finance:9,tourism:9} }
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

function genCode() { return crypto.randomBytes(3).toString('hex').toUpperCase(); }
function deepClone(o) { return JSON.parse(JSON.stringify(o)); }
function getC(room, id) { return room.countries.find(c => c.id === id); }
function turnLabel(room) { const y=2025+room.turn-1; return `Year ${y}`; }

function sendState(code) {
  const room = rooms[code];
  if (!room) return;
  io.to(code).emit('stateUpdate', {
    code: room.code, phase: room.phase, turn: room.turn, maxTurns: room.maxTurns,
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
  // Apply policy
  if (policy) {
    c.interest = policy.interest;
    c.tax = policy.tax;
    c.govSpend = policy.govSpend;
    c.tradeOpenness = policy.tradeOpenness || 0;
    c.monetaryPolicy = policy.monetaryPolicy || 0;
    c.infraSpend = policy.infraSpend || 0;
    c.rdSpend = policy.rdSpend || 0;
  } else {
    // AI
    const personality = c._personality || 'HAWK';
    if (personality === 'HAWK') {
      if (c.inflation > 4) c.interest = Math.min(25, c.interest + 0.5);
      else c.interest = Math.max(1, c.interest - 0.25);
    } else if (personality === 'DOVE') {
      c.interest = Math.max(0.5, c.interest - 0.25);
      c.govSpend = Math.min(55, c.govSpend + 1);
    } else if (personality === 'MERCANTILIST') {
      c.tradeOpenness = Math.min(10, (c.tradeOpenness||0) + 1);
      c.tax = Math.max(15, c.tax - 0.5);
    } else {
      // default adaptive
      if (c.inflation > 5) c.interest = Math.min(30, c.interest + 0.5);
      if (c.growth < 1) c.govSpend = Math.min(50, c.govSpend + 1);
    }
    c.tradeOpenness = c.tradeOpenness || 0;
    c.monetaryPolicy = c.monetaryPolicy || 0;
    c.infraSpend = c.infraSpend || 0;
    c.rdSpend = c.rdSpend || 0;
  }

  const bc = c.interest + (CREDIT_SPREAD[Math.round(c.creditScore)] || 5);
  const intEff = c.interest<1?0.8:c.interest<3?0.4:c.interest<6?0.1:c.interest<10?-0.1:c.interest<20?-0.6:-1.2;
  const taxEff = c.tax<10?0.5:c.tax<20?0.3:c.tax<30?0:c.tax<40?-0.2:-0.5;
  const spEff = c.govSpend>60?-0.3:c.govSpend>50?0.1:c.govSpend>35?0.2:c.govSpend>20?0.15:0;
  const debtP = c.debt>200?-1.5:c.debt>150?-0.8:c.debt>120?-0.4:c.debt>90?-0.15:0;
  const creditP = -(bc-5)*0.08;
  const tradeEff = (c.tradeOpenness||0)*0.05;
  const fdiEff = Math.min(0.4, Math.max(-0.3, c.fdi/400));
  const unempEff = c.unemployment>25?-1.0:c.unemployment>15?-0.5:c.unemployment>10?-0.2:c.unemployment>7?-0.05:c.unemployment<3?0.2:0;
  const currEff = c.currencyStrength<40?-0.8:c.currencyStrength<60?-0.3:c.currencyStrength<80?-0.1:c.currencyStrength>140?-0.1:0;
  const monEff = (c.monetaryPolicy||0)*0.15;
  const infraEff = (c._infraDelayed||0)*0.05;
  c._infraDelayed = c.infraSpend || 0;

  // Sanctions
  const sanctionCount = (room.sanctions||[]).filter(s=>s.target===c.id&&s.active).length;
  const sanctionEff = sanctionCount>2?-0.6:sanctionCount>0?-0.2:0;

  // Alliances
  const allyCount = (room.alliances||[]).filter(a=>a.active&&(a.a===c.id||a.b===c.id)).length;
  const allyEff = Math.min(0.3, allyCount*0.05);

  // Disasters
  const activeDisasters = (room.disasters||[]).filter(d=>d.countryId===c.id&&d.turnsLeft>0);
  let disasterGdpEff = 0;
  activeDisasters.forEach(d => { disasterGdpEff += d.gdpEffect||0; });

  const noise = (Math.random()-0.47)*0.5;
  let base = intEff+taxEff+spEff+debtP+creditP+tradeEff+fdiEff+unempEff+currEff+monEff+infraEff+sanctionEff+allyEff+disasterGdpEff+noise;
  c.growth = Math.max(-12, Math.min(16, c.growth*0.5 + base));
  c.gdp *= (1 + c.growth/100);
  c.gdpCap *= (1 + c.growth/100);

  // Inflation
  const importInfl = c.currencyStrength<50?(50-c.currencyStrength)*0.12:c.currencyStrength<70?(70-c.currencyStrength)*0.06:0;
  const wageInfl = c.unemployment<3?0.6:c.unemployment<4?0.3:0;
  const demandPull = (c.govSpend-30)*0.03 + (c.monetaryPolicy||0)*0.4;
  const disasterInfl = activeDisasters.reduce((s,d)=>s+(d.inflationEffect||0),0);
  c.inflation = Math.max(0, Math.min(200, c.inflation + demandPull + importInfl + wageInfl - (c.interest-3)*0.15 + disasterInfl + (Math.random()-0.5)*0.4));

  // Unemployment (Okun + Phillips)
  const okunEff = -(c.growth/4)*0.4;
  const phillipsEff = c.inflation>5?-0.15:c.inflation<1.5?0.2:0;
  const disasterUnemp = activeDisasters.reduce((s,d)=>s+(d.unemploymentEffect||0),0);
  c.unemployment = Math.max(1, Math.min(40, c.unemployment + okunEff + phillipsEff + (4.5-c.unemployment)*0.06 + disasterUnemp + (Math.random()-0.5)*0.25));

  // Debt
  const taxRev = c.tax*c.gdp*0.0015;
  c.debt = Math.max(0, c.debt + (c.govSpend-20)/4 - c.growth*0.4 + (c.debt>60?(bc-5)*0.02:0));

  // Credit rating
  let cs = c.creditScore;
  if(c.debt>160)cs-=2;else if(c.debt>130)cs-=1;else if(c.debt>100)cs-=0.5;else if(c.debt<40)cs+=0.3;
  if(c.inflation>25)cs-=2;else if(c.inflation>10)cs-=0.8;else if(c.inflation<3)cs+=0.15;
  if(c.growth<-3)cs-=0.8;else if(c.growth>5)cs+=0.3;
  if(c.fdi<-20)cs-=0.5;
  if(c.unemployment>20)cs-=0.4;
  if(sanctionCount>0)cs-=0.3*sanctionCount;
  const oldCS = Math.round(c.creditScore);
  c.creditScore = Math.max(1, Math.min(10, cs));
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
  const rateEff=(c.interest-worldAvgRate)*1.2;
  const tradeBalEff=(c.exports-c.imports)/Math.max(c.gdp,1)*25;
  const inflEff=-(c.inflation-worldAvgInfl)*0.6;
  const ratingEff=(c.creditScore-7)*0.4;
  const fdiCurrEff=c.fdi>0?Math.log(c.fdi+1)*0.25:c.fdi*0.06;
  const monCurrEff=-(c.monetaryPolicy||0)*0.3;
  const sanctCurrEff=sanctionCount>0?-3*sanctionCount:0;
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
  const stabAttr=sanctionCount>0?-10:5;
  c.fdi=Math.max(-60,Math.min(600,c.fdi+(taxAttr+ratingAttr+growthAttr+tradeAttr+inflRep+stabAttr)/10+(Math.random()-0.45)*5));

  // Exports/imports
  c.exports*=(1+(c.tradeOpenness||0)*0.01+Math.random()*0.01);
  c.imports*=(1+Math.random()*0.008-0.002);

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
  if(room.turn>room.maxTurns)room.phase='ended';
}

// ── SOCKET.IO ────────────────────────────────────────────────
function authSocket(socket, cb) {
  const token = socket.handshake.auth.token || socket.handshake.headers.cookie?.split('mef_token=')[1]?.split(';')[0];
  if (!token) return cb(null);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.get('users').find({ id: payload.userId }).value();
    cb(user || null);
  } catch (e) { cb(null); }
}

io.on('connection', socket => {
  authSocket(socket, user => { socket.user = user; });

  socket.on('createRoom', ({ name }, cb) => {
    if (!socket.user) return cb({ success:false, error:'Not logged in' });
    const code = genCode();
    const isAdmin = socket.user.username === ADMIN_USERNAME;
    rooms[code] = {
      code, hostSocketId:socket.id, phase:'lobby', turn:1, maxTurns:5,
      players:[], countries:G20.map(c=>{ const cl=deepClone(c); cl._personality=AI_PERSONALITIES[Math.floor(Math.random()*AI_PERSONALITIES.length)]; cl._history=[c.gdpCap]; cl._infraDelayed=0; return cl; }),
      commodityPrices:Object.fromEntries(COMMODITIES.map(c=>[c.id,c.basePrice])),
      marketOffers:[], completedDeals:[], eventLog:[], chat:[], offerCounter:0,
      pendingActions:{}, sanctions:[], alliances:[], tradeWars:[], loanRequests:[],
      justifications:[], disasters:[], adminSocket: isAdmin ? socket.id : null
    };
    if (!isAdmin) {
      rooms[code].players.push({ socketId:socket.id, name:socket.user.username, countryId:null, ready:false, budget:0, inventory:Object.fromEntries(COMMODITIES.map(c=>[c.id,0])), gdpCapStart:0, history:[], ehs:[], loans:[] });
    } else {
      rooms[code].adminSocket = socket.id;
    }
    socket.join(code);
    socket.data.roomCode = code;
    cb({ success:true, code, isAdmin });
    sendState(code);
  });

  socket.on('joinRoom', ({ code, name }, cb) => {
    if (!socket.user) return cb({ success:false, error:'Not logged in' });
    const room = rooms[code];
    if (!room) return cb({ success:false, error:'Room not found' });
    if (room.phase !== 'lobby') return cb({ success:false, error:'Game already started' });
    const isAdmin = socket.user.username === ADMIN_USERNAME;
    if (!isAdmin && room.players.length >= 4) return cb({ success:false, error:'Room full' });
    if (isAdmin) { room.adminSocket = socket.id; }
    else { room.players.push({ socketId:socket.id, name:socket.user.username, countryId:null, ready:false, budget:0, inventory:Object.fromEntries(COMMODITIES.map(c=>[c.id,0])), gdpCapStart:0, history:[], ehs:[], loans:[] }); }
    socket.join(code);
    socket.data.roomCode = code;
    cb({ success:true, code, isAdmin });
    sendState(code);
    io.to(code).emit('chat', { name:'System', text:`${socket.user.username} joined!`, system:true });
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
    room.pendingActions[socket.id]={policy};
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
    bc2.gdpCap*=1.001;bc2.gdp*=1.001;sc2.gdpCap*=1.001;sc2.gdp*=1.001;
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
    if(socket.user?.username!==ADMIN_USERNAME)return;
    const c=getC(room,countryId);if(!c)return;
    room.sanctions.push({from:'ADMIN',fromFlag:'🌐',fromName:'Admin',target:countryId,targetFlag:c.flag,targetName:c.name,reason,active:true,turn:room.turn});
    room.eventLog.push({quarter:turnLabel(room),text:`🌐 ADMIN sanction imposed on ${c.flag}${c.name}: "${reason}"`,global:true});
    sendState(code);sendAdmin(code);
  });

  socket.on('adminDisaster',({code,countryId,disasterType})=>{
    const room=rooms[code];if(!room)return;
    if(socket.user?.username!==ADMIN_USERNAME)return;
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
    if(socket.user?.username!==ADMIN_USERNAME)return;
    const loan=room.loanRequests.find(l=>l.id===loanId);if(!loan)return;
    loan.status='approved';loan.approvedAmount=approvedAmount;loan.interestRate=interestRate;loan.repaymentTurns=repaymentTurns;loan.note=note;
    const totalRepayment=approvedAmount*(1+interestRate/100);
    const p=room.players.find(p=>p.socketId===loan.socketId);
    if(p){
      p.budget+=approvedAmount;
      p.loans.push({id:loanId,amount:approvedAmount,interestRate,totalRepayment,repaymentTurns,turnsLeft:repaymentTurns,active:true});
      const c=getC(room,p.countryId);c.debt+=approvedAmount/c.gdp*100;
    }
    room.eventLog.push({quarter:turnLabel(room),text:`🏦 World Bank approved $${approvedAmount}B loan to ${loan.countryFlag}${loan.playerName} at ${interestRate}% interest`,global:true});
    io.to(loan.socketId).emit('loanApproved',{amount:approvedAmount,interestRate,repaymentTurns,note});
    sendState(code);sendAdmin(code);
  });

  socket.on('adminRejectLoan',({code,loanId,note})=>{
    const room=rooms[code];if(!room)return;
    if(socket.user?.username!==ADMIN_USERNAME)return;
    const loan=room.loanRequests.find(l=>l.id===loanId);if(!loan)return;
    loan.status='rejected';loan.note=note;
    io.to(loan.socketId).emit('loanRejected',{note});
    sendAdmin(code);
  });

  socket.on('adminScoreJustification',({code,idx,score,feedback})=>{
    const room=rooms[code];if(!room)return;
    if(socket.user?.username!==ADMIN_USERNAME)return;
    const j=room.justifications[idx];if(!j)return;
    j.adminScore=score;j.adminFeedback=feedback;
    io.to(j.socketId).emit('justificationFeedback',{score,feedback,turn:j.turn});
    sendAdmin(code);
  });

  socket.on('adminAdjustIndicator',({code,countryId,field,value})=>{
    const room=rooms[code];if(!room)return;
    if(socket.user?.username!==ADMIN_USERNAME)return;
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
function endGame(code) {
  const room = rooms[code];
  if (!room) return;
  const sorted = [...room.players].sort((a,b)=>{
    const aEhs=a.ehs.reduce((s,v)=>s+v,0)/Math.max(a.ehs.length,1);
    const bEhs=b.ehs.reduce((s,v)=>s+v,0)/Math.max(b.ehs.length,1);
    return bEhs-aEhs;
  });
  sorted.forEach((p,i)=>{
    const u=db.get('users').find({username:p.name}).value();
    if(!u)return;
    const c=getC(room,p.countryId);
    const avgEhs=p.ehs.reduce((s,v)=>s+v,0)/Math.max(p.ehs.length,1);
    const growth=((c.gdpCap-p.gdpCapStart)/p.gdpCapStart*100).toFixed(1);
    db.get('users').find({username:p.name}).assign({
      games_played:(u.games_played||0)+1,
      games_won:(u.games_won||0)+(i===0?1:0),
      best_ehs:Math.max(u.best_ehs||0,Math.round(avgEhs)),
      best_growth:Math.max(u.best_growth||0,parseFloat(growth)),
      match_history:[...(u.match_history||[]),{date:new Date().toISOString(),country:p.countryId,final_ehs:Math.round(avgEhs),rank:i+1,growth}].slice(-20)
    }).write();
  });
}

// ── SERVE PAGES ──────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`\n✅ MEF server running → http://localhost:${PORT}\n   Admin: login as "${ADMIN_USERNAME}" then visit /admin\n`);
});
