
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const fetch = require('node-fetch');
const { nanoid } = require('nanoid');

const User = require('./models/User');
const Machine = require('./models/Machine');
const Purchase = require('./models/Purchase');
const Deposit = require('./models/Deposit');
const Withdrawal = require('./models/Withdrawal');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1/hightech', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=>console.log('MongoDB connected')).catch(err=>console.error(err));

// Azure OIDC disabled — using simple email/password admin instead.
console.log("Azure Admin OAuth disabled (switched to basic admin login)");


app.use(session({ secret: process.env.JWT_SECRET || 'change_me', resave: false, saveUninitialized: true }));
app.use(passport.initialize()); app.use(passport.session());
passport.serializeUser((u, done)=> done(null, u)); passport.deserializeUser((u, done)=> done(null, u));

async function seedMachines(){
  const count = await Machine.countDocuments();
  if (count === 0){
    const machines = [
      { key: 'm1', name: 'Starter', price: 5000, dailyPercent: 10 },
      { key: 'm2', name: 'Bronze', price: 10000, dailyPercent: 10 },
      { key: 'm3', name: 'Silver', price: 25000, dailyPercent: 10 },
      { key: 'm4', name: 'Gold', price: 50000, dailyPercent: 10 },
      { key: 'm5', name: 'Platinum', price: 100000, dailyPercent: 10 }
    ];
    await Machine.insertMany(machines);
    console.log('Seeded machines');
  }
}
seedMachines().catch(console.error);

// ----- Admin auth middleware (basic JWT admin + legacy ADMIN_API_KEY support) -----
const JWT = require('jsonwebtoken');

// =============================
// USER AUTH JWT MIDDLEWARES
// =============================

// Used for endpoints that need simple user auth
function adminAuth(req, res, next){
  try {
    // 1) passport session (if still active)
    if (req.isAuthenticated && req.isAuthenticated()) {
      return next();
    }

    // 2) legacy API key header or query param
    const headerKey = req.headers['x-admin-key'] || req.query.adminKey;
    const envKey = process.env.ADMIN_API_KEY || process.env.ADMIN_KEY;
    if (envKey && headerKey && headerKey === envKey) {
      return next();
    }

    // 3) Bearer admin JWT
    const auth = req.headers['authorization'] || '';
    if (auth.startsWith('Bearer ')) {
      const token = auth.split(' ')[1];
      try {
        const payload = JWT.verify(token, process.env.JWT_SECRET || 'change_me');
        if (payload && payload.isAdmin) {
          req.admin = payload; // attach admin info
          return next();
        }
      } catch (err) {
        // invalid token -> fallthrough to unauthorized
      }
    }

    // otherwise unauthorized
    return res.status(401).json({ error: 'Admin auth required' });
  } catch (err) {
    return res.status(401).json({ error: 'Admin auth required' });
  }
}
function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer '))
      return res.status(401).json({ error: 'No token provided' });

    const token = auth.split(" ")[1];
    const decoded = JWT.verify(token, process.env.JWT_SECRET || "change_me");

    req.userId = decoded.id;  // Key part needed by your code
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Legacy compatibility – some routes use "userAuth"
function userAuth(req, res, next) {
  return authMiddleware(req, res, next);
}

// ----- Simple admin login (email + password) -----
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  // Basic validation
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  // Compare with env values (this is simple and fits the "basic admin" request)
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminEmail || !adminPassword) {
    return res.status(500).json({ error: 'Admin credentials not configured on server' });
  }

  if (email !== adminEmail || password !== adminPassword) {
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }

  // Issue JWT for admin UI
  const token = JWT.sign({ email: adminEmail, isAdmin: true }, process.env.JWT_SECRET || 'change_me', { expiresIn: '12h' });

  res.json({ token, expiresIn: '12h' });
});


// Auth
app.post('/api/auth/register', async (req,res)=>{
  const { name, email, password, referralCode } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ error: 'Email already exists' });
  const hashed = bcrypt.hashSync(password, 8);
  const user = new User({ name, email, password: hashed, balance: 0, referralCode: nanoid(6), referredBy: referralCode || null });
  await user.save();
  const token = JWT.sign({ id: user._id }, process.env.JWT_SECRET || 'change_me', { expiresIn: '30d' });
  res.json({ token, user: { id: user._id, name: user.name, email: user.email, balance: user.balance, referralCode: user.referralCode } });
});

app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  const token = JWT.sign({ id: user._id }, process.env.JWT_SECRET || 'change_me', { expiresIn: '30d' });
  res.json({ token, user: { id: user._id, name: user.name, email: user.email, balance: user.balance, referralCode: user.referralCode } });
});

// Azure admin login
app.get('/auth/azure', passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }));
app.post('/auth/azure/callback', passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }), (req,res)=> { res.send('<h3>Admin login successful. You can close this window.</h3>'); });

// Machines endpoints
app.get('/api/machines', async (req,res)=>{ const machines = await Machine.find().lean(); res.json(machines); });

app.post('/api/purchase', userAuth, async (req,res)=>{
  const { machineKey } = req.body;
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const machine = await Machine.findOne({ key: machineKey });
  if (!machine) return res.status(400).json({ error: 'Invalid machine' });
  if (user.balance < machine.price) return res.status(400).json({ error: 'Insufficient balance' });
  user.balance -= machine.price; await user.save();
  const purchase = new Purchase({ user: user._id, machine: machine._id, price: machine.price, startAt: Date.now(), lastClaim: Date.now(), active: true });
  await purchase.save();
  res.json({ success: true, purchase });
});

app.post('/api/claim', authMiddleware, async (req,res)=>{
  const user = await User.findById(req.userId);
  const purchases = await Purchase.find({ user: user._id, active: true }).populate('machine').lean();
  let total = 0; const now = Date.now();
  for (const p of purchases){
    const last = p.lastClaim || p.startAt;
    const days = Math.floor((now - last) / (1000*60*60*24));
    if (days <= 0) continue;
    const daily = p.machine.price * (p.machine.dailyPercent/100);
    const amount = daily * days;
    total += amount;
    await Purchase.findByIdAndUpdate(p._id, { lastClaim: now });
  }
  user.balance = (user.balance || 0) + total; await user.save();
  res.json({ claimed: total, newBalance: user.balance });
});

app.get('/api/me', authMiddleware, async (req,res)=>{ const user = await User.findById(req.userId).lean(); const purchases = await Purchase.find({ user: req.userId }).populate('machine').lean(); res.json({ user, purchases }); });

// Deposit - Flutterwave integration (creates payment link)
app.post('/api/deposit/create', authMiddleware, async (req,res)=>{
  const { amount } = req.body;
  if (!amount || amount < 5000) return res.status(400).json({ error: 'Minimum deposit is 5000' });
  const tx_ref = 'HT-' + nanoid(10);
  const payload = { tx_ref, amount: amount.toString(), currency: "NGN", redirect_url: `${process.env.BASE_URL || 'http://localhost:4000'}/api/deposit/callback`, customer: { email: (await User.findById(req.userId)).email, name: 'Hightech User' }, customizations: { title: "Hightech Deposit", description: "Account deposit" } };
  if (!process.env.FLW_SECRET_KEY){
    const fakeLink = `${process.env.BASE_URL || 'http://localhost:4000'}/simulate-pay?tx_ref=${tx_ref}&amount=${amount}`;
    const d = new Deposit({ user: req.userId, amount, tx_ref, status: 'pending' }); await d.save();
    return res.json({ payment_link: fakeLink, tx_ref });
  }
  try {
    const resp = await fetch('https://api.flutterwave.com/v3/payments', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` }, body: JSON.stringify(payload) });
    const data = await resp.json();
    if (data.status === 'success' && data.data && data.data.link){ const d = new Deposit({ user: req.userId, amount, tx_ref, status: 'pending' }); await d.save(); return res.json({ payment_link: data.data.link, tx_ref }); } else { return res.status(500).json({ error: 'Failed to create payment', details: data }); }
  } catch(e){ console.error(e); return res.status(500).json({ error: 'Payment link creation failed', details: e.message }); }
});

app.post('/api/deposit/callback', async (req,res)=>{
  const payload = req.body || req.query || {}; const tx_ref = payload.tx_ref || req.query.tx_ref; const status = payload.status || 'successful'; const amount = Number(payload.amount || req.query.amount || 0);
  if (!tx_ref) return res.status(400).json({ error: 'Missing tx_ref' });
  const deposit = await Deposit.findOne({ tx_ref });
  if (!deposit){ const d = new Deposit({ user: null, amount, tx_ref, status }); await d.save(); return res.json({ success: true }); }
  if (status === 'successful' || status === 'completed'){ deposit.status = 'completed'; deposit.completedAt = Date.now(); await deposit.save(); if (deposit.user){ const user = await User.findById(deposit.user); user.balance = (user.balance || 0) + Number(deposit.amount); await user.save(); if (user.referredBy){ const ref = await User.findById(user.referredBy); if (ref){ const bonus = Number(deposit.amount) * 0.10; ref.balance = (ref.balance || 0) + bonus; await ref.save(); const refDep = new Deposit({ user: ref._id, amount: bonus, tx_ref: 'ref-' + tx_ref, status: 'completed', type: 'referral', note: `10% of ${user._id}` }); await refDep.save(); } } } return res.json({ success: true }); } else { deposit.status = status; await deposit.save(); return res.json({ success: true }); }
});

app.get('/simulate-pay', (req,res)=>{ const { tx_ref, amount } = req.query; res.send(`<html><body><h3>Simulated payment</h3><p>tx_ref: ${tx_ref} amount: ${amount}</p><form method="POST" action="/api/deposit/callback"><input type="hidden" name="tx_ref" value="${tx_ref}"/><input type="hidden" name="status" value="successful"/><input type="hidden" name="amount" value="${amount}"/><button type="submit">Simulate successful payment (POST webhook)</button></form><p>Or GET <a href="/api/deposit/callback?tx_ref=${tx_ref}&status=successful&amount=${amount}">callback link</a></p></body></html>`); });

app.post('/api/withdraw/request', authMiddleware, async (req,res)=>{
  const { amount, bank, accountNumber, accountName } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  const w = new Withdrawal({ user: user._id, amount, bank, accountNumber, accountName, status: 'pending' }); await w.save();
  res.json({ success: true, withdrawal: w });
});

app.get('/api/banks', async (req,res)=>{ const banks = require('./data/banks.json'); res.json(banks); });

app.get('/api/admin/withdrawals', adminAuth, async (req,res)=>{ const list = await Withdrawal.find().populate('user').lean(); res.json(list); });

app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req,res)=>{ const id = req.params.id; const w = await Withdrawal.findById(id); if (!w) return res.status(404).json({ error: 'Not found' }); if (w.status !== 'pending') return res.status(400).json({ error: 'Not pending' }); const user = await User.findById(w.user); if (!user) return res.status(404).json({ error: 'User not found' }); user.balance -= Number(w.amount); await user.save(); w.status = 'approved'; w.approvedAt = Date.now(); w.adminNote = req.body.note || ''; await w.save(); res.json({ success: true, withdrawal: w }); });

app.get('/api/admin/dashboard', adminAuth, async (req,res)=>{ const users = await User.countDocuments(); const deposits = await Deposit.countDocuments({ status: 'completed' }); const withdrawals = await Withdrawal.countDocuments({ status: 'pending' }); res.json({ users, deposits, pendingWithdrawals: withdrawals }); });

const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=> console.log('Hightech backend listening on', PORT));
