require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const path = require('path');
const { Resend } = require('resend');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'lions-academy-2024-secret-key-change-in-production';
const MPESA_BASE = process.env.MPESA_ENV === 'production'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';

let resendClient = null;
if (process.env.RESEND_API_KEY) {
    try { resendClient = new Resend(process.env.RESEND_API_KEY); } catch (e) { console.log('Resend init error:', e.message); }
}

// ── MongoDB Connection ──
mongoose.connect(process.env.MONGODB_URI)
    .then(function() { console.log('MongoDB connected'); })
    .catch(function(err) { console.error('MongoDB error:', err.message); process.exit(1); });

// ── Database Models ──
const User = mongoose.model('User', new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, sparse: true },
    phone: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'member' },
    emailVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
}));

const Player = mongoose.model('Player', new mongoose.Schema({
    name: String, age: Number, team: String, category: String,
    position: String, photo: String,
    createdAt: { type: Date, default: Date.now }
}));

const Contribution = mongoose.model('Contribution', new mongoose.Schema({
    memberId: mongoose.Schema.Types.ObjectId,
    memberName: String,
    amount: Number,
    category: String,
    date: { type: Date, default: Date.now },
    status: { type: String, default: 'pending' },
    verifiedBy: mongoose.Schema.Types.ObjectId,
    verifiedAt: Date,
    mpesaCheckoutId: String,
    mpesaReceipt: String,
    rejectReason: String
}));

const Loan = mongoose.model('Loan', new mongoose.Schema({
    memberId: mongoose.Schema.Types.ObjectId,
    memberName: String,
    amount: Number,
    reason: String,
    date: { type: Date, default: Date.now },
    status: { type: String, default: 'pending' },
    approvals: [mongoose.Schema.Types.ObjectId],
    rejectReason: String
}));

const Gallery = mongoose.model('Gallery', new mongoose.Schema({
    url: String,
    caption: String,
    uploadedBy: mongoose.Schema.Types.ObjectId,
    date: { type: Date, default: Date.now },
    comments: [{
        userId: mongoose.Schema.Types.ObjectId,
        userName: String,
        text: String,
        date: Date
    }]
}));

const PaymentMethod = mongoose.model('PaymentMethod', new mongoose.Schema({
    type: String,
    label: String,
    name: String,
    number: String,
    instructions: String,
    active: { type: Boolean, default: true }
}));

const Settings = mongoose.model('Settings', new mongoose.Schema({
    key: { type: String, unique: true },
    value: mongoose.Schema.Types.Mixed
}));

// ── Helper Functions ──
function hashPassword(pw) { return bcrypt.hashSync(pw, 10); }
function comparePassword(pw, hashed) { return bcrypt.compareSync(pw, hashed); }
function generateToken(user) { return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' }); }

function formatPhone(phone, withPlus) {
    phone = String(phone).replace(/[\s\-]/g, '');
    if (phone.startsWith('+')) phone = phone.slice(1);
    if (phone.startsWith('0') && phone.length >= 10) phone = '254' + phone.slice(1);
    return withPlus ? '+' + phone : phone;
}

// ── Auth Middleware ──
function requireAuth(req, res, next) {
    var header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Login required' });
    }
    try {
        req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Session expired. Please login again.' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access only' });
    }
    next();
}

// ── Send Email ──
async function sendEmail(to, subject, html) {
    if (!resendClient) {
        console.log('Email skipped (Resend not configured):', to);
        return;
    }
    try {
        await resendClient.emails.send({
            from: process.env.RESEND_FROM || 'onboarding@resend.dev',
            to: to,
            subject: subject,
            html: html
        });
        console.log('Email sent to', to);
    } catch (err) {
        console.error('Email error:', err.message);
    }
}

// ── Send SMS via Africa's Talking ──
async function sendSMS(phone, message) {
    if (!process.env.AT_API_KEY) {
        console.log('SMS skipped (AT not configured):', phone);
        return;
    }
    try {
        await axios.post('https://api.africastalking.com/v1/messaging', {
            username: process.env.AT_USERNAME || 'sandbox',
            to: [formatPhone(phone, true)],
            message: message,
            from: process.env.AT_SENDER || '12345'
        }, {
            headers: {
                'apiKey': process.env.AT_API_KEY,
                'Content-Type': 'application/json'
            }
        });
        console.log('SMS sent to', phone);
    } catch (err) {
        console.error('SMS error:', err.message);
    }
}

// ── M-Pesa STK Push ──
var mpesaToken = null;
var mpesaTokenExpiry = 0;

async function getMpesaToken() {
    if (mpesaToken && Date.now() < mpesaTokenExpiry) return mpesaToken;
    var auth = Buffer.from(process.env.MPESA_CONSUMER_KEY + ':' + process.env.MPESA_CONSUMER_SECRET).toString('base64');
    var res = await axios.get(MPESA_BASE + '/oauth/v1/generate?grant_type=client_credentials', {
        headers: { Authorization: 'Basic ' + auth }
    });
    mpesaToken = res.data.access_token;
    mpesaTokenExpiry = Date.now() + 3500000;
    return mpesaToken;
}

async function initiateSTKPush(phone, amount, accountRef, description) {
    var token = await getMpesaToken();
    var timestamp = new Date().toISOString().replace(/[-:.]/g, '').slice(0, 14);
    var password = Buffer.from(process.env.MPESA_SHORTCODE + process.env.MPESA_PASSKEY + timestamp).toString('base64');

    var res = await axios.post(MPESA_BASE + '/mpesa/stkpush/v1/processrequest', {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: Math.round(amount),
        PartyA: formatPhone(phone),
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: formatPhone(phone),
        CallBackURL: process.env.MPESA_CALLBACK_URL,
        AccountReference: (accountRef || 'LIONS').slice(0, 12),
        TransactionDesc: (description || 'Payment').slice(0, 13)
    }, {
        headers: { Authorization: 'Bearer ' + token }
    });

    return res.data;
}

// ── Seed Default Data ──
async function seedDatabase() {
    var adminCount = await User.countDocuments({ role: 'admin' });
    if (adminCount === 0) {
        await User.create([
            {
                name: 'Amos Gechanga',
                email: 'admin@lionsacademy.ke',
                phone: '0113512127',
                password: hashPassword('admin123'),
                role: 'admin'
            },
            {
                name: 'Admin Two',
                email: 'admin2@lionsacademy.ke',
                phone: '0700000000',
                password: hashPassword('admin123'),
                role: 'admin'
            }
        ]);
        await PaymentMethod.create({
            type: 'mpesa',
            label: 'M-Pesa',
            name: 'Amos Gechanga',
            number: '0113512127',
            instructions: 'Go to M-Pesa > Lipa na M-Pesa > Enter Till Number 174379 > Enter amount > Account: LIONSACAD > Confirm',
            active: true
        });
        await Settings.create({ key: 'academyName', value: 'Lions Soccer Academy Rongai' });
        await Player.insertMany([
            { name: 'Kipchoge Baraka', age: 10, team: 'junior', category: 'U11', position: 'Forward' },
            { name: 'Mwangi Brian', age: 9, team: 'junior', category: 'U10', position: 'Midfielder' },
            { name: 'Otieno Derrick', age: 8, team: 'junior', category: 'U9', position: 'Defender' },
            { name: 'Kamau Ian', age: 7, team: 'junior', category: 'U8', position: 'Goalkeeper' },
            { name: 'Wanjiku Faith', age: 6, team: 'junior', category: 'U7', position: 'Midfielder' },
            { name: 'Adhiambo Lily', age: 5, team: 'junior', category: 'U6', position: 'Forward' },
            { name: 'Ochieng Kevin', age: 12, team: 'pioneer', category: 'U12', position: 'Forward' },
            { name: 'Njeri Grace', age: 13, team: 'pioneer', category: 'U13', position: 'Midfielder' },
            { name: 'Muthoni Alice', age: 14, team: 'pioneer', category: 'U14', position: 'Defender' },
            { name: 'Kiprop Samuel', age: 15, team: 'pioneer', category: 'U15', position: 'Goalkeeper' },
            { name: 'Wambui Diana', age: 16, team: 'pioneer', category: 'U16', position: 'Forward' },
            { name: 'Chebet Sharon', age: 17, team: 'pioneer', category: 'U17', position: 'Midfielder' }
        ]);
        console.log('Database seeded with default data');
    }
}


// ══════════════════════════════════════
//            API ROUTES
// ══════════════════════════════════════

// ── REGISTER ──
app.post('/api/auth/register', async function(req, res) {
    try {
        var name = req.body.name;
        var email = req.body.email || '';
        var phone = req.body.phone;
        var password = req.body.password;

        if (!name || !phone || !password) {
            return res.status(400).json({ message: 'Name, phone and password are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }
        if (await User.findOne({ phone: phone })) {
            return res.status(400).json({ message: 'Phone number already registered' });
        }
        if (email && await User.findOne({ email: email })) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        var user = await User.create({
            name: name,
            email: email,
            phone: phone,
            password: hashPassword(password)
        });

        var token = generateToken(user);

        // Send welcome SMS
        sendSMS(phone, 'Welcome to Lions Soccer Academy, ' + name + '! Your account has been created. Login at our website to start contributing.');

        // Send verification email if provided
        if (email) {
            var verifyToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '24h' });
            var baseUrl = process.env.BASE_URL || 'http://localhost:5000';
            sendEmail(email, 'Verify Your Lions Academy Account',
                '<h2>Welcome to Lions Soccer Academy!</h2>' +
                '<p>Hi ' + name + ',</p>' +
                '<p>Click below to verify your email:</p>' +
                '<p><a href="' + baseUrl + '/verify-email?token=' + verifyToken + '" style="background:#d4a017;color:#000;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold">Verify Email</a></p>' +
                '<p>If you did not register, ignore this email.</p>'
            );
        }

        res.json({
            token: token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(400).json({ message: 'Phone or email already exists' });
        }
        res.status(500).json({ message: err.message });
    }
});

// ── VERIFY EMAIL ──
app.get('/verify-email', async function(req, res) {
    try {
        var decoded = jwt.verify(req.query.token, JWT_SECRET);
        await User.findByIdAndUpdate(decoded.id, { emailVerified: true });
        res.send('<h2 style="color:#22c55e;font-family:sans-serif;text-align:center;margin-top:40px">Email verified successfully! You can now log in.</h2>');
    } catch (err) {
        res.send('<h2 style="color:#ef4444;font-family:sans-serif;text-align:center;margin-top:40px">Invalid or expired link.</h2>');
    }
});

// ── LOGIN ──
app.post('/api/auth/login', async function(req, res) {
    try {
        var identifier = req.body.identifier;
        var password = req.body.password;

        if (!identifier || !password) {
            return res.status(400).json({ message: 'Email/phone and password required' });
        }

        var user = await User.findOne({
            $or: [{ email: identifier }, { phone: identifier }]
        });

        if (!user || !comparePassword(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        var token = generateToken(user);
        res.json({
            token: token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── GET CURRENT USER (for session restore) ──
app.get('/api/auth/me', requireAuth, async function(req, res) {
    try {
        var user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ user: user });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── DASHBOARD STATS ──
app.get('/api/dashboard', requireAuth, async function(req, res) {
    try {
        if (req.user.role === 'admin') {
            var allContribs = await Contribution.find();
            var verified = allContribs.filter(function(c) { return c.status === 'verified'; });
            var total = verified.reduce(function(s, c) { return s + c.amount; }, 0);
            var pending = allContribs.filter(function(c) { return c.status === 'pending'; }).length;
            var pendingLoans = await Loan.countDocuments({ status: { $in: ['pending', 'partial'] } });
            var members = await User.countDocuments({ role: 'member' });
            var players = await Player.countDocuments();
            var recentContrib = await Contribution.find().sort({ date: -1 }).limit(5);
            var recentLoans = await Loan.find().sort({ date: -1 }).limit(5);
            res.json({ total: total, pending: pending, pendingLoans: pendingLoans, members: members, players: players, recentContrib: recentContrib, recentLoans: recentLoans });
        } else {
            var myContribs = await Contribution.find({ memberId: req.user.id });
            var myTotal = myContribs.filter(function(c) { return c.status === 'verified'; }).reduce(function(s, c) { return s + c.amount; }, 0);
            var activeLoans = await Loan.countDocuments({ memberId: req.user.id, status: { $in: ['approved', 'disbursed'] } });
            res.json({ myTotal: myTotal, contribCount: myContribs.length, activeLoans: activeLoans });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── PLAYERS ──
app.get('/api/players', requireAuth, async function(req, res) {
    try {
        var players = await Player.find().sort({ team: 1, age: 1 });
        res.json(players);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/players', requireAuth, requireAdmin, async function(req, res) {
    try {
        var player = await Player.create(req.body);
        res.json(player);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/players/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        var player = await Player.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!player) return res.status(404).json({ message: 'Player not found' });
        res.json(player);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/players/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        await Player.findByIdAndDelete(req.params.id);
        res.json({ message: 'Deleted' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── GALLERY ──
app.get('/api/gallery', requireAuth, async function(req, res) {
    try {
        var gallery = await Gallery.find().sort({ date: -1 });
        res.json(gallery);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/gallery', requireAuth, requireAdmin, async function(req, res) {
    try {
        var item = await Gallery.create({
            url: req.body.url,
            caption: req.body.caption,
            uploadedBy: req.user.id
        });
        res.json(item);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/gallery/:id/comment', requireAuth, async function(req, res) {
    try {
        var item = await Gallery.findByIdAndUpdate(req.params.id, {
            $push: {
                comments: {
                    userId: req.user.id,
                    userName: req.user.name,
                    text: req.body.text,
                    date: new Date()
                }
            }
        }, { new: true });
        if (!item) return res.status(404).json({ message: 'Not found' });
        res.json(item);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── CONTRIBUTIONS ──
app.get('/api/contributions', requireAuth, async function(req, res) {
    try {
        if (req.user.role === 'admin') {
            var all = await Contribution.find().sort({ date: -1 });
            var verified = all.filter(function(c) { return c.status === 'verified'; });
            var total = verified.reduce(function(s, c) { return s + c.amount; }, 0);
            var pending = all.filter(function(c) { return c.status === 'pending'; });
            var cats = { medical: 0, camps: 0, trips: 0, emergency: 0, general: 0 };
            verified.forEach(function(c) { if (cats[c.category] !== undefined) cats[c.category] += c.amount; });
            res.json({ all: all, total: total, pendingCount: pending.length, categories: cats });
        } else {
            var mine = await Contribution.find({ memberId: req.user.id }).sort({ date: -1 });
            var myTotal = mine.filter(function(c) { return c.status === 'verified'; }).reduce(function(s, c) { return s + c.amount; }, 0);
            res.json({ mine: mine, myTotal: myTotal });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/contributions/:id', requireAuth, async function(req, res) {
    try {
        var c = await Contribution.findById(req.params.id);
        if (!c) return res.status(404).json({ message: 'Not found' });
        if (c.memberId.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        res.json({ contribution: c });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/contributions', requireAuth, async function(req, res) {
    try {
        var amount = req.body.amount;
        var category = req.body.category;

        if (!amount || amount < 100) {
            return res.status(400).json({ message: 'Minimum amount is KES 100' });
        }

        var user = await User.findById(req.user.id);
        var contrib = await Contribution.create({
            memberId: user._id,
            memberName: user.name,
            amount: amount,
            category: category,
            status: 'pending'
        });

        // Send SMS with payment instructions
        sendSMS(user.phone,
            'Lions Soccer Academy: Payment of KES ' + amount.toLocaleString() + ' for ' + category + '.\n' +
            'M-Pesa > Lipa na M-Pesa > Till: ' + (process.env.MPESA_SHORTCODE || '174379') + '\n' +
            'Account: LIONSACAD\n' +
            'Amount: ' + amount + '\n' +
            'Enter your PIN to confirm.'
        );

        // Try M-Pesa STK Push
        var stkSent = false;
        if (process.env.MPESA_CONSUMER_KEY && process.env.MPESA_CONSUMER_SECRET && process.env.MPESA_PASSKEY) {
            try {
                var stk = await initiateSTKPush(user.phone, amount, 'LIONS-' + contrib._id, category);
                if (stk.ResponseCode === '0') {
                    contrib.mpesaCheckoutId = stk.CheckoutRequestID;
                    contrib.status = 'pending_payment';
                    await contrib.save();
                    stkSent = true;
                } else {
                    console.log('STK Push error:', stk.ResponseDescription);
                }
            } catch (stkErr) {
                console.error('STK Push failed:', stkErr.message);
            }
        }

        res.json({ contribution: contrib, stkSent: stkSent });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/contributions/:id/verify', requireAuth, requireAdmin, async function(req, res) {
    try {
        var c = await Contribution.findByIdAndUpdate(req.params.id, {
            status: 'verified',
            verifiedBy: req.user.id,
            verifiedAt: new Date()
        }, { new: true });
        if (!c) return res.status(404).json({ message: 'Not found' });
        res.json(c);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/contributions/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        await Contribution.findByIdAndDelete(req.params.id);
        res.json({ message: 'Removed' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── M-PESA CALLBACK (No auth - called by Safaricom) ──
app.post('/api/mpesa/callback', async function(req, res) {
    try {
        var body = req.body;
        var stkCallback = body && body.Body && body.Body.stkCallback;

        if (!stkCallback) {
            return res.status(200).json({ ResultCode: 0 });
        }

        var checkoutId = stkCallback.CheckoutRequestID;
        var resultCode = stkCallback.ResultCode;
        var resultDesc = stkCallback.ResultDesc;

        var contrib = await Contribution.findOne({ mpesaCheckoutId: checkoutId });
        if (!contrib) {
            return res.status(200).json({ ResultCode: 0 });
        }

        if (resultCode === 0) {
            var metadata = stkCallback.CallbackMetadata ? stkCallback.CallbackMetadata.Item : [];
            var amount = 0;
            var receipt = '';
            var phone = '';

            for (var i = 0; i < metadata.length; i++) {
                if (metadata[i].Name === 'Amount') amount = metadata[i].Value;
                if (metadata[i].Name === 'MpesaReceiptNumber') receipt = metadata[i].Value;
                if (metadata[i].Name === 'PhoneNumber') phone = metadata[i].Value;
            }

            contrib.status = 'verified';
            contrib.mpesaReceipt = receipt;
            contrib.verifiedAt = new Date();
            await contrib.save();

            console.log('Payment verified: KES ' + amount + ', Receipt: ' + receipt);

            // Send confirmation SMS
            var formattedPhone = '';
            if (phone) {
                formattedPhone = '0' + String(phone).slice(-9);
            } else {
                var member = await User.findById(contrib.memberId);
                if (member) formattedPhone = member.phone;
            }

            if (formattedPhone) {
                sendSMS(formattedPhone,
                    'Lions Soccer Academy: Payment of KES ' + amount + ' received! Receipt: ' + receipt + '. Thank you for your contribution.'
                );
            }
        } else {
            contrib.status = 'failed';
            contrib.rejectReason = resultDesc;
            await contrib.save();
            console.log('Payment failed: ' + resultDesc);
        }

        res.status(200).json({ ResultCode: 0 });
    } catch (err) {
        console.error('Callback error:', err.message);
        res.status(200).json({ ResultCode: 0 });
    }
});

// ── LOANS ──
app.get('/api/loans', requireAuth, async function(req, res) {
    try {
        if (req.user.role === 'admin') {
            var loans = await Loan.find().sort({ date: -1 });
            res.json(loans);
        } else {
            var myLoans = await Loan.find({ memberId: req.user.id }).sort({ date: -1 });
            res.json(myLoans);
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/loans', requireAuth, async function(req, res) {
    try {
        var user = await User.findById(req.user.id);
        var loan = await Loan.create({
            memberId: user._id,
            memberName: user.name,
            amount: req.body.amount,
            reason: req.body.reason,
            status: 'pending',
            approvals: [],
            rejectReason: ''
        });

        // Notify admins via SMS
        var admins = await User.find({ role: 'admin' });
        for (var i = 0; i < admins.length; i++) {
            sendSMS(admins[i].phone,
                'Lions Academy: New loan request of KES ' + req.body.amount + ' from ' + user.name + '. Login to approve.'
            );
        }

        res.json(loan);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/loans/:id/approve', requireAuth, requireAdmin, async function(req, res) {
    try {
        var loan = await Loan.findById(req.params.id);
        if (!loan) return res.status(404).json({ message: 'Not found' });

        if (loan.approvals.indexOf(req.user.id) >= 0) {
            return res.status(400).json({ message: 'You already approved this' });
        }

        loan.approvals.push(req.user.id);

        if (loan.approvals.length >= 2) {
            loan.status = 'approved';
            var member = await User.findById(loan.memberId);
            if (member) {
                sendSMS(member.phone,
                    'Lions Academy: Your loan of KES ' + loan.amount + ' has been APPROVED by both admins. Contact the office for disbursement.'
                );
            }
        } else {
            loan.status = 'partial';
        }

        await loan.save();
        res.json(loan);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/loans/:id/reject', requireAuth, requireAdmin, async function(req, res) {
    try {
        var loan = await Loan.findByIdAndUpdate(req.params.id, {
            status: 'rejected',
            rejectReason: req.body.reason
        }, { new: true });

        if (!loan) return res.status(404).json({ message: 'Not found' });

        var member = await User.findById(loan.memberId);
        if (member) {
            sendSMS(member.phone,
                'Lions Academy: Your loan of KES ' + loan.amount + ' was rejected. Reason: ' + req.body.reason
            );
        }

        res.json(loan);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/loans/:id/disburse', requireAuth, requireAdmin, async function(req, res) {
    try {
        var loan = await Loan.findByIdAndUpdate(req.params.id, { status: 'disbursed' }, { new: true });
        if (!loan) return res.status(404).json({ message: 'Not found' });

        var member = await User.findById(loan.memberId);
        if (member) {
            sendSMS(member.phone,
                'Lions Academy: Your loan of KES ' + loan.amount + ' has been disbursed. Check your M-Pesa.'
            );
        }

        res.json(loan);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── PAYMENT METHODS ──
app.get('/api/payment-methods', requireAuth, async function(req, res) {
    try {
        var methods = await PaymentMethod.find();
        res.json(methods);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/payment-methods', requireAuth, requireAdmin, async function(req, res) {
    try {
        var pm = await PaymentMethod.create(req.body);
        res.json(pm);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/payment-methods/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        var pm = await PaymentMethod.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!pm) return res.status(404).json({ message: 'Not found' });
        res.json(pm);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/payment-methods/:id/toggle', requireAuth, requireAdmin, async function(req, res) {
    try {
        var pm = await PaymentMethod.findById(req.params.id);
        if (!pm) return res.status(404).json({ message: 'Not found' });
        pm.active = !pm.active;
        await pm.save();
        res.json(pm);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/payment-methods/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        await PaymentMethod.findByIdAndDelete(req.params.id);
        res.json({ message: 'Deleted' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── MEMBERS (Admin) ──
app.get('/api/members', requireAuth, requireAdmin, async function(req, res) {
    try {
        var members = await User.find({ role: 'member' }).sort({ createdAt: -1 });
        var enriched = [];
        for (var i = 0; i < members.length; i++) {
            var m = members[i];
            var contribs = await Contribution.find({ memberId: m._id, status: 'verified' });
            var loans = await Loan.find({ memberId: m._id });
            enriched.push({
                _id: m._id,
                name: m.name,
                email: m.email,
                phone: m.phone,
                createdAt: m.createdAt,
                totalContrib: contribs.reduce(function(s, c) { return s + c.amount; }, 0),
                loanCount: loans.length
            });
        }
        res.json(enriched);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/members/:id/reset-password', requireAuth, requireAdmin, async function(req, res) {
    try {
        var user = await User.findByIdAndUpdate(req.params.id, {
            password: hashPassword(req.body.password)
        });
        if (user) {
            sendSMS(user.phone, 'Lions Academy: Your password has been reset by admin. Login with your new password.');
        }
        res.json({ message: 'Password reset' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── SETTINGS ──
app.get('/api/settings', requireAuth, requireAdmin, async function(req, res) {
    try {
        var settings = await Settings.find();
        var obj = {};
        settings.forEach(function(s) { obj[s.key] = s.value; });
        res.json(obj);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/settings', requireAuth, requireAdmin, async function(req, res) {
    try {
        var keys = Object.keys(req.body);
        for (var i = 0; i < keys.length; i++) {
            await Settings.findOneAndUpdate({ key: keys[i] }, { value: req.body[keys[i]] }, { upsert: true });
        }
        res.json({ message: 'Saved' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── ADMIN PROFILE ──
app.put('/api/admin/profile', requireAuth, requireAdmin, async function(req, res) {
    try {
        var user = await User.findByIdAndUpdate(req.user.id, {
            name: req.body.name,
            email: req.body.email,
            phone: req.body.phone
        }, { new: true });
        res.json({
            id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/admin/password', requireAuth, requireAdmin, async function(req, res) {
    try {
        var user = await User.findById(req.user.id);
        if (!comparePassword(req.body.currentPassword, user.password)) {
            return res.status(400).json({ message: 'Current password is incorrect' });
        }
        if (req.body.newPassword !== req.body.confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }
        if (req.body.newPassword.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }
        user.password = hashPassword(req.body.newPassword);
        await user.save();
        res.json({ message: 'Password changed' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── RESET ALL DATA ──
app.post('/api/reset-data', requireAuth, requireAdmin, async function(req, res) {
    try {
        await Player.deleteMany({});
        await Contribution.deleteMany({});
        await Loan.deleteMany({});
        await Gallery.deleteMany({});
        await PaymentMethod.deleteMany({});
        await User.deleteMany({ role: 'member' });
        await Settings.deleteMany({});
        await seedDatabase();
        res.json({ message: 'Data reset complete' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── SERVE FRONTEND (catch-all) ──
app.get('*', function(req, res) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── START SERVER ──
var PORT = process.env.PORT || 5000;
seedDatabase().then(function() {
    app.listen(PORT, function() {
        console.log('Lions Soccer Academy running on port ' + PORT);
    });
});
