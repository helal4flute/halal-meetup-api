/**
 * ============================================================
 *  HALAL-MEETUP  |  REST API  (Node.js + Express + mssql)
 *  Admin    : mdhelal.ahamed@gmail.com
 *  Notify   : infohalalmeetup@gmail.com
 *  Version  : 1.0
 * ============================================================
 *
 *  Setup:
 *    npm install express mssql bcryptjs jsonwebtoken
 *                multer dotenv cors helmet express-rate-limit
 *
 *  .env file:
 *    DB_SERVER=your-server.database.windows.net
 *    DB_NAME=HalalMeetUp
 *    DB_USER=your_db_user
 *    DB_PASSWORD=your_db_password
 *    DB_PORT=1433
 *    JWT_SECRET=your_super_secret_key_here
 *    JWT_EXPIRES_IN=7d
 *    PORT=3000
 *    STRIPE_SECRET_KEY=sk_live_xxx
 *    SENDGRID_API_KEY=SG.xxx
 *    FROM_EMAIL=infohalalmeetup@gmail.com
 *    ADMIN_EMAIL=mdhelal.ahamed@gmail.com
 *    STORAGE_BASE_URL=https://your-storage.r2.dev
 *
 *  Start:
 *    node server.js
 * ============================================================
 */

'use strict';

require('dotenv').config();
const express      = require('express');
const sql          = require('mssql');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const multer       = require('multer');
const path         = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── DB CONFIG ───────────────────────────────────────────────
const dbConfig = {
    server:   process.env.DB_SERVER,
    database: process.env.DB_NAME,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port:     parseInt(process.env.DB_PORT || '1433'),
    options: {
        encrypt:                  true,   // required for Azure SQL
        enableArithAbort:         true,
        trustServerCertificate:   false,
    },
    pool: {
        max: 20, min: 2, idleTimeoutMillis: 30000
    }
};

let pool;
async function getPool() {
    if (!pool) {
        pool = await sql.connect(dbConfig);
        console.log('✅ SQL Server connected');
    }
    return pool;
}

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','PATCH'] }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Global rate limit
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200,
    message: { error: 'Too many requests. Please try again later.' } }));

// Stricter limit for auth routes
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20,
    message: { error: 'Too many login attempts. Try again in 15 minutes.' } });

// ─── FILE UPLOAD (in-memory; swap for S3/R2 in prod) ─────────
const upload = multer({
    storage: multer.memoryStorage(),
    limits:  { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['.jpg','.jpeg','.png','.webp'];
        const ext     = path.extname(file.originalname).toLowerCase();
        cb(null, allowed.includes(ext));
    }
});

// ─── HELPERS ─────────────────────────────────────────────────
const BCRYPT_ROUNDS = 12;

function signToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
}

function sendSuccess(res, data, status = 200) {
    return res.status(status).json({ success: true, data });
}

function sendError(res, message, status = 400) {
    return res.status(status).json({ success: false, error: message });
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return sendError(res, 'Authentication required.', 401);
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        return sendError(res, 'Invalid or expired token.', 401);
    }
}

function requireAdmin(req, res, next) {
    if (req.user?.role !== 'admin')
        return sendError(res, 'Admin access required.', 403);
    next();
}

// ─── EMAIL HELPER (SendGrid / log stub) ──────────────────────
async function sendEmail(toEmail, type, subject, body) {
    // Swap this block for actual SendGrid call in production:
    // const sgMail = require('@sendgrid/mail');
    // sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    // await sgMail.send({ to: toEmail, from: process.env.FROM_EMAIL, subject, text: body });

    console.log(`[EMAIL] From: ${process.env.FROM_EMAIL} | To: ${toEmail} | ${subject}`);

    try {
        const db = await getPool();
        await db.request()
            .input('to_email', sql.NVarChar(255), toEmail)
            .input('type',     sql.NVarChar(20),  type)
            .input('subject',  sql.NVarChar(255), subject)
            .input('status',   sql.NVarChar(10),  'sent')
            .execute('dbo.sp_LogEmail');
    } catch (e) {
        console.error('Email log failed:', e.message);
    }
}

// ─────────────────────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) =>
    res.json({ status: 'ok', app: 'Halal-MeetUp API', version: '1.0' }));

// ============================================================
//  AUTH  ─  POST /api/auth/register
//           POST /api/auth/login
//           POST /api/auth/verify-otp
// ============================================================

app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const {
            first_name, last_name, email, password, phone, dob,
            gender, sect, marital_status, education, country, city,
            nationality, languages, occupation, bio, interests,
            photo_1, photo_2, photo_3
        } = req.body;

        // Basic validation
        const required = { first_name, last_name, email, password, phone, dob,
                           gender, sect, marital_status, education, country, city,
                           nationality, languages, occupation, bio, interests };
        for (const [k, v] of Object.entries(required)) {
            if (!v) return sendError(res, `${k} is required.`);
        }
        if (password.length < 8)
            return sendError(res, 'Password must be at least 8 characters.');
        if (bio.trim().length < 30)
            return sendError(res, 'Bio must be at least 30 characters.');

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const db = await getPool();
        const result = await db.request()
            .input('first_name',     sql.NVarChar(100), first_name)
            .input('last_name',      sql.NVarChar(100), last_name)
            .input('email',          sql.NVarChar(255), email.toLowerCase())
            .input('password_hash',  sql.NVarChar(255), passwordHash)
            .input('phone',          sql.NVarChar(20),  phone)
            .input('dob',            sql.Date,          new Date(dob))
            .input('gender',         sql.NVarChar(10),  gender)
            .input('sect',           sql.NVarChar(100), sect)
            .input('marital_status', sql.NVarChar(30),  marital_status)
            .input('education',      sql.NVarChar(100), education)
            .input('country',        sql.NVarChar(100), country)
            .input('city',           sql.NVarChar(100), city)
            .input('nationality',    sql.NVarChar(100), nationality)
            .input('languages',      sql.NVarChar(255), languages)
            .input('occupation',     sql.NVarChar(150), occupation)
            .input('bio',            sql.NVarChar(sql.MAX), bio)
            .input('interests',      sql.NVarChar(sql.MAX), interests)
            .input('photo_1',        sql.NVarChar(500), photo_1 || '')
            .input('photo_2',        sql.NVarChar(500), photo_2 || '')
            .input('photo_3',        sql.NVarChar(500), photo_3 || '')
            .execute('dbo.sp_RegisterUser');

        const user  = result.recordset[0];
        const token = signToken(user);

        // Welcome email
        await sendEmail(
            email,
            'welcome',
            'Welcome to Halal-MeetUp — Your Journey Begins! 🌙',
            `Assalamu Alaikum ${first_name},\n\nWelcome to Halal-MeetUp!\n\nYour account has been created.\nComplete your ID verification to go live.\n\nJazakAllah khayr,\nThe Halal-MeetUp Team\n${process.env.FROM_EMAIL}`
        );

        sendSuccess(res, { user, token }, 201);
    } catch (err) {
        if (err.message?.includes('already registered'))
            return sendError(res, 'Email address is already registered.');
        if (err.message?.includes('18 years'))
            return sendError(res, 'You must be at least 18 years old.');
        console.error('Register error:', err);
        sendError(res, 'Registration failed. Please try again.', 500);
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return sendError(res, 'Email and password are required.');

        const db     = await getPool();
        const result = await db.request()
            .input('email',         sql.NVarChar(255), email.toLowerCase())
            .input('password_hash', sql.NVarChar(255), '') // placeholder
            .execute('dbo.sp_AuthenticateUser');

        // sp_AuthenticateUser returns user by email; we verify password in Node
        // Re-run a simple select to get password_hash separately
        const pwResult = await db.request()
            .input('email', sql.NVarChar(255), email.toLowerCase())
            .query(`SELECT id, password_hash, is_banned, role
                    FROM dbo.users WHERE email = @email`);

        if (!pwResult.recordset.length)
            return sendError(res, 'No account found with that email. Please sign up first.', 401);

        const row = pwResult.recordset[0];
        if (row.is_banned)
            return sendError(res, 'This account has been suspended. Contact support.', 403);

        const valid = await bcrypt.compare(password, row.password_hash);
        if (!valid)
            return sendError(res, 'Incorrect password. Please try again.', 401);

        // Get full user profile
        const userResult = await db.request()
            .input('id', sql.NVarChar(36), row.id)
            .query(`SELECT id, first_name, last_name, email, phone, gender, sect,
                           marital_status, education, country, city, nationality,
                           languages, occupation, bio, interests,
                           photo_1, photo_2, photo_3, age,
                           id_verified, premium, sub_status, sub_renews_at,
                           online, last_seen, role, created_at
                    FROM dbo.users WHERE id = @id`);

        const user  = userResult.recordset[0];
        const token = signToken(user);

        // Update last_seen
        await db.request()
            .input('id', sql.NVarChar(36), user.id)
            .query(`UPDATE dbo.users SET online = 1, last_seen = SYSUTCDATETIME() WHERE id = @id`);

        sendSuccess(res, { user, token });
    } catch (err) {
        console.error('Login error:', err);
        sendError(res, 'Login failed. Please try again.', 500);
    }
});

// OTP send (stub — wire to Twilio in prod)
app.post('/api/auth/send-otp', authLimiter, async (req, res) => {
    const { phone, type } = req.body;   // type = 'sms' | 'email'
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // TODO: store OTP in a Redis cache (TTL 10 min) and send via Twilio
    console.log(`[OTP] To: ${phone} Code: ${otp}`);
    sendSuccess(res, { message: 'OTP sent.' });
});

// ============================================================
//  USERS  ─  GET /api/users/me
//             PUT /api/users/me
//             GET /api/users/:id
// ============================================================

app.get('/api/users/me', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('id', sql.NVarChar(36), req.user.id)
            .query(`SELECT id, first_name, last_name, email, phone, gender, sect,
                           marital_status, education, country, city, nationality,
                           languages, occupation, bio, interests,
                           photo_1, photo_2, photo_3, age,
                           id_verified, premium, sub_status, sub_renews_at,
                           online, last_seen, role, created_at
                    FROM dbo.users WHERE id = @id`);
        if (!result.recordset.length)
            return sendError(res, 'User not found.', 404);
        sendSuccess(res, result.recordset[0]);
    } catch (err) {
        console.error(err);
        sendError(res, 'Failed to fetch profile.', 500);
    }
});

app.put('/api/users/me', requireAuth, async (req, res) => {
    try {
        const allowed = ['first_name','last_name','occupation','city','country',
                         'sect','interests','nationality','education','bio','marital_status'];
        const updates = [];
        const req2    = (await getPool()).request().input('id', sql.NVarChar(36), req.user.id);

        for (const field of allowed) {
            if (req.body[field] !== undefined) {
                updates.push(`${field} = @${field}`);
                req2.input(field, sql.NVarChar(sql.MAX), req.body[field]);
            }
        }
        if (!updates.length) return sendError(res, 'No valid fields to update.');

        updates.push('updated_at = SYSUTCDATETIME()');
        await req2.query(`UPDATE dbo.users SET ${updates.join(', ')} WHERE id = @id`);

        sendSuccess(res, { message: 'Profile updated.' });
    } catch (err) {
        console.error(err);
        sendError(res, 'Failed to update profile.', 500);
    }
});

app.get('/api/users/:id', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('id', sql.NVarChar(36), req.params.id)
            .query(`SELECT id, first_name, last_name, age, gender, sect,
                           marital_status, education, country, city, nationality,
                           languages, occupation, bio, interests,
                           photo_1, photo_2, photo_3, id_verified, online, last_seen
                    FROM dbo.vw_PublicProfiles WHERE id = @id`);
        if (!result.recordset.length) return sendError(res, 'User not found.', 404);
        sendSuccess(res, result.recordset[0]);
    } catch (err) {
        sendError(res, 'Failed to fetch user.', 500);
    }
});

// ============================================================
//  DISCOVER  ─  GET /api/discover
// ============================================================

app.get('/api/discover', requireAuth, async (req, res) => {
    try {
        const page     = parseInt(req.query.page || '0');
        const pageSize = parseInt(req.query.page_size || '20');
        const db       = await getPool();
        const result   = await db.request()
            .input('user_id',   sql.NVarChar(36), req.user.id)
            .input('page_size', sql.Int, pageSize)
            .input('offset',    sql.Int, page * pageSize)
            .execute('dbo.sp_DiscoverProfiles');
        sendSuccess(res, result.recordset);
    } catch (err) {
        console.error(err);
        sendError(res, 'Failed to load discover profiles.', 500);
    }
});

// ============================================================
//  SEARCH  ─  GET /api/search
// ============================================================

app.get('/api/search', requireAuth, async (req, res) => {
    try {
        const { country, sect, marital_status, verified_only, min_age, max_age } = req.query;
        const db = await getPool();
        const r  = db.request().input('user_id', sql.NVarChar(36), req.user.id);

        let where = `id <> @user_id AND is_banned = 0`;
        if (country)      { where += ` AND (city LIKE @country OR country LIKE @country)`;
                            r.input('country', sql.NVarChar(100), `%${country}%`); }
        if (sect)         { where += ` AND sect LIKE @sect`;
                            r.input('sect', sql.NVarChar(100), `%${sect}%`); }
        if (marital_status){ where += ` AND marital_status = @marital_status`;
                             r.input('marital_status', sql.NVarChar(30), marital_status); }
        if (verified_only === 'true') { where += ` AND id_verified = 1`; }
        if (min_age)      { where += ` AND age >= @min_age`; r.input('min_age', sql.Int, parseInt(min_age)); }
        if (max_age)      { where += ` AND age <= @max_age`; r.input('max_age', sql.Int, parseInt(max_age)); }

        const result = await r.query(
            `SELECT id, first_name, last_name, age, city, country, sect,
                    marital_status, photo_1, id_verified, online
             FROM dbo.vw_PublicProfiles
             WHERE ${where}
             ORDER BY id_verified DESC, online DESC
             OFFSET 0 ROWS FETCH NEXT 50 ROWS ONLY`
        );
        sendSuccess(res, result.recordset);
    } catch (err) {
        console.error(err);
        sendError(res, 'Search failed.', 500);
    }
});

// ============================================================
//  LIKES & MATCHES
// ============================================================

// Like a profile
app.post('/api/likes', requireAuth, async (req, res) => {
    try {
        const { to_user_id } = req.body;
        if (!to_user_id) return sendError(res, 'to_user_id is required.');
        if (to_user_id === req.user.id)
            return sendError(res, 'You cannot like yourself.');

        const db     = await getPool();
        const result = await db.request()
            .input('from_user_id', sql.NVarChar(36), req.user.id)
            .input('to_user_id',   sql.NVarChar(36), to_user_id)
            .execute('dbo.sp_LikeUser');

        const row = result.recordset[0];
        sendSuccess(res, { result: row.result, match_id: row.match_id });
    } catch (err) {
        console.error(err);
        sendError(res, 'Failed to like profile.', 500);
    }
});

// Get my matches
app.get('/api/matches', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('user_id', sql.NVarChar(36), req.user.id)
            .execute('dbo.sp_GetMatches');
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch matches.', 500);
    }
});

// Delete a match
app.delete('/api/matches/:matchId', requireAuth, async (req, res) => {
    try {
        const db = await getPool();
        await db.request()
            .input('match_id', sql.NVarChar(36), req.params.matchId)
            .input('user_id',  sql.NVarChar(36), req.user.id)
            .query(`DELETE FROM dbo.matches
                    WHERE id = @match_id
                      AND (user1_id = @user_id OR user2_id = @user_id)`);
        sendSuccess(res, { message: 'Match removed.' });
    } catch (err) {
        sendError(res, 'Failed to remove match.', 500);
    }
});

// ============================================================
//  MESSAGES
// ============================================================

// Get messages for a match
app.get('/api/matches/:matchId/messages', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('match_id',        sql.NVarChar(36), req.params.matchId)
            .input('requesting_user', sql.NVarChar(36), req.user.id)
            .execute('dbo.sp_GetMessages');
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch messages.', 500);
    }
});

// Send a message
app.post('/api/matches/:matchId/messages', requireAuth, async (req, res) => {
    try {
        const { text, to_user_id, blocked_reason } = req.body;
        if (!text || !text.trim()) return sendError(res, 'Message text is required.');
        if (!to_user_id)           return sendError(res, 'to_user_id is required.');

        const db     = await getPool();
        const result = await db.request()
            .input('match_id',       sql.NVarChar(36),      req.params.matchId)
            .input('from_user_id',   sql.NVarChar(36),      req.user.id)
            .input('to_user_id',     sql.NVarChar(36),      to_user_id)
            .input('text',           sql.NVarChar(sql.MAX), text.trim())
            .input('blocked_reason', sql.NVarChar(20),      blocked_reason || null)
            .execute('dbo.sp_SendMessage');
        sendSuccess(res, result.recordset[0], 201);
    } catch (err) {
        if (err.message?.includes('Match not found'))
            return sendError(res, 'Match not found or you are not part of this match.', 403);
        sendError(res, 'Failed to send message.', 500);
    }
});

// Soft-delete own message
app.delete('/api/messages/:msgId', requireAuth, async (req, res) => {
    try {
        const db = await getPool();
        await db.request()
            .input('msg_id',  sql.NVarChar(36), req.params.msgId)
            .input('user_id', sql.NVarChar(36), req.user.id)
            .query(`UPDATE dbo.messages
                    SET is_deleted = 1
                    WHERE id = @msg_id AND from_user_id = @user_id`);
        sendSuccess(res, { message: 'Message deleted.' });
    } catch (err) {
        sendError(res, 'Failed to delete message.', 500);
    }
});

// Add reaction
app.patch('/api/messages/:msgId/react', requireAuth, async (req, res) => {
    try {
        const { emoji } = req.body;
        if (!emoji) return sendError(res, 'emoji is required.');
        const db = await getPool();
        // Simple approach: fetch current reactions JSON and update
        const r = await db.request()
            .input('id', sql.NVarChar(36), req.params.msgId)
            .query(`SELECT reactions FROM dbo.messages WHERE id = @id`);
        if (!r.recordset.length) return sendError(res, 'Message not found.', 404);
        let reactions = JSON.parse(r.recordset[0].reactions || '[]');
        const idx = reactions.indexOf(emoji);
        if (idx >= 0) reactions.splice(idx, 1); else reactions.push(emoji);
        await db.request()
            .input('id',        sql.NVarChar(36),      req.params.msgId)
            .input('reactions', sql.NVarChar(sql.MAX), JSON.stringify(reactions))
            .query(`UPDATE dbo.messages SET reactions = @reactions WHERE id = @id`);
        sendSuccess(res, { reactions });
    } catch (err) {
        sendError(res, 'Failed to update reaction.', 500);
    }
});

// ============================================================
//  INTRO MESSAGES
// ============================================================

app.post('/api/intro-messages', requireAuth, async (req, res) => {
    try {
        const { to_user_id, text } = req.body;
        if (!to_user_id || !text?.trim())
            return sendError(res, 'to_user_id and text are required.');

        const db = await getPool();

        // Check only 1 intro per pair
        const exists = await db.request()
            .input('from', sql.NVarChar(36), req.user.id)
            .input('to',   sql.NVarChar(36), to_user_id)
            .query(`SELECT 1 FROM dbo.intro_messages WHERE from_user_id=@from AND to_user_id=@to`);
        if (exists.recordset.length)
            return sendError(res, 'You already sent an intro to this person.');

        await db.request()
            .input('from_user_id', sql.NVarChar(36),      req.user.id)
            .input('to_user_id',   sql.NVarChar(36),      to_user_id)
            .input('text',         sql.NVarChar(sql.MAX), text.trim())
            .query(`INSERT INTO dbo.intro_messages (from_user_id, to_user_id, text)
                    VALUES (@from_user_id, @to_user_id, @text)`);

        // Mark like as intro_sent
        await db.request()
            .input('from', sql.NVarChar(36), req.user.id)
            .input('to',   sql.NVarChar(36), to_user_id)
            .query(`UPDATE dbo.likes SET intro_sent=1 WHERE from_user_id=@from AND to_user_id=@to`);

        sendSuccess(res, { message: 'Intro message sent.' }, 201);
    } catch (err) {
        sendError(res, 'Failed to send intro.', 500);
    }
});

app.get('/api/intro-messages', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('user_id', sql.NVarChar(36), req.user.id)
            .query(`SELECT im.id, im.from_user_id, im.text, im.is_read, im.created_at,
                           u.first_name, u.last_name, u.photo_1, u.id_verified
                    FROM   dbo.intro_messages im
                    JOIN   dbo.users u ON u.id = im.from_user_id
                    WHERE  im.to_user_id = @user_id
                    ORDER  BY im.created_at DESC`);
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch intros.', 500);
    }
});

// ============================================================
//  SUBSCRIPTIONS
// ============================================================

app.post('/api/subscriptions', requireAuth, async (req, res) => {
    try {
        const { stripe_sub_id, stripe_customer_id, action } = req.body;
        const validActions = ['subscribe','resubscribe','cancel','renew'];
        if (!validActions.includes(action))
            return sendError(res, `action must be one of: ${validActions.join(', ')}`);

        const db     = await getPool();
        const result = await db.request()
            .input('user_id',             sql.NVarChar(36),  req.user.id)
            .input('stripe_sub_id',       sql.NVarChar(100), stripe_sub_id       || '')
            .input('stripe_customer_id',  sql.NVarChar(100), stripe_customer_id  || '')
            .input('action',              sql.NVarChar(15),  action)
            .execute('dbo.sp_UpdateSubscription');

        const user = result.recordset[0];

        // Email notifications
        const userResult = await db.request()
            .input('id', sql.NVarChar(36), req.user.id)
            .query(`SELECT email, first_name, sub_renews_at FROM dbo.users WHERE id = @id`);
        const u = userResult.recordset[0];

        if (action === 'subscribe') {
            await sendEmail(u.email, 'subscribe',
                'Welcome to Halal-MeetUp Premium!',
                `Dear ${u.first_name},\n\nYour Premium subscription is active.\nNext renewal: ${u.sub_renews_at}\n\nJazakAllah khayr,\nHalal-MeetUp Team`);
        } else if (action === 'resubscribe') {
            await sendEmail(u.email, 'resubscribe',
                'Halal-MeetUp Premium — Welcome Back!',
                `Dear ${u.first_name},\n\nYour Premium subscription has been re-activated.\nNext renewal: ${u.sub_renews_at}\n\nJazakAllah khayr,\nHalal-MeetUp Team`);
        } else if (action === 'cancel') {
            await sendEmail(u.email, 'cancel',
                'Halal-MeetUp Subscription Cancelled',
                `Dear ${u.first_name},\n\nYour Premium subscription has been cancelled.\nRe-subscribe anytime from My Profile.\n\nJazakAllah khayr,\nHalal-MeetUp Team`);
        }

        sendSuccess(res, user);
    } catch (err) {
        console.error(err);
        sendError(res, 'Subscription update failed.', 500);
    }
});

app.get('/api/subscriptions/me', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('user_id', sql.NVarChar(36), req.user.id)
            .query(`SELECT id, stripe_sub_id, amount_cents, currency, [status],
                           current_period_start, current_period_end, cancelled_at, created_at
                    FROM dbo.subscriptions
                    WHERE user_id = @user_id
                    ORDER BY created_at DESC`);
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch subscriptions.', 500);
    }
});

// ============================================================
//  CALL LOGS
// ============================================================

app.post('/api/calls', requireAuth, async (req, res) => {
    try {
        const { match_id, receiver_id, call_type, status, duration_seconds } = req.body;
        if (!match_id || !receiver_id || !call_type || !status)
            return sendError(res, 'match_id, receiver_id, call_type, and status are required.');

        const db = await getPool();
        await db.request()
            .input('match_id',          sql.NVarChar(36), match_id)
            .input('caller_id',         sql.NVarChar(36), req.user.id)
            .input('receiver_id',       sql.NVarChar(36), receiver_id)
            .input('call_type',         sql.NVarChar(10), call_type)
            .input('status',            sql.NVarChar(15), status)
            .input('duration_seconds',  sql.Int,          duration_seconds || 0)
            .query(`INSERT INTO dbo.call_logs
                        (match_id, caller_id, receiver_id, call_type, [status], duration_seconds)
                    VALUES
                        (@match_id, @caller_id, @receiver_id, @call_type, @status, @duration_seconds)`);
        sendSuccess(res, { message: 'Call logged.' }, 201);
    } catch (err) {
        sendError(res, 'Failed to log call.', 500);
    }
});

app.get('/api/calls', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('user_id', sql.NVarChar(36), req.user.id)
            .query(`SELECT cl.id, cl.call_type, cl.[status], cl.duration_seconds,
                           cl.started_at, cl.ended_at,
                           u1.first_name AS caller_name, u2.first_name AS receiver_name
                    FROM   dbo.call_logs cl
                    JOIN   dbo.users u1 ON u1.id = cl.caller_id
                    JOIN   dbo.users u2 ON u2.id = cl.receiver_id
                    WHERE  cl.caller_id = @user_id OR cl.receiver_id = @user_id
                    ORDER  BY cl.started_at DESC`);
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch call logs.', 500);
    }
});

// ============================================================
//  REPORTS
// ============================================================

app.post('/api/reports', requireAuth, async (req, res) => {
    try {
        const { reported_id, reason, details } = req.body;
        if (!reported_id || !reason) return sendError(res, 'reported_id and reason are required.');

        const db     = await getPool();
        const result = await db.request()
            .input('reporter_id', sql.NVarChar(36),      req.user.id)
            .input('reported_id', sql.NVarChar(36),      reported_id)
            .input('reason',      sql.NVarChar(100),     reason)
            .input('details',     sql.NVarChar(sql.MAX), details || null)
            .execute('dbo.sp_SubmitReport');
        sendSuccess(res, result.recordset[0], 201);
    } catch (err) {
        sendError(res, 'Failed to submit report.', 500);
    }
});

// ============================================================
//  NOTIFICATIONS
// ============================================================

app.get('/api/notifications', requireAuth, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .input('user_id', sql.NVarChar(36), req.user.id)
            .query(`SELECT TOP 50 id, [type], title, body, related_user_id,
                           related_match_id, is_read, created_at
                    FROM dbo.notifications
                    WHERE user_id = @user_id
                    ORDER BY created_at DESC`);
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch notifications.', 500);
    }
});

app.patch('/api/notifications/:id/read', requireAuth, async (req, res) => {
    try {
        const db = await getPool();
        await db.request()
            .input('id',      sql.NVarChar(36), req.params.id)
            .input('user_id', sql.NVarChar(36), req.user.id)
            .query(`UPDATE dbo.notifications SET is_read=1 WHERE id=@id AND user_id=@user_id`);
        sendSuccess(res, { message: 'Marked as read.' });
    } catch (err) {
        sendError(res, 'Failed to mark notification.', 500);
    }
});

// ============================================================
//  ADMIN ROUTES
// ============================================================

app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request().execute('dbo.sp_AdminStats');
        sendSuccess(res, result.recordset[0]);
    } catch (err) {
        sendError(res, 'Failed to fetch stats.', 500);
    }
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .query(`SELECT * FROM dbo.vw_AdminUserList ORDER BY created_at DESC`);
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch users.', 500);
    }
});

app.patch('/api/admin/users/:id/ban', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { ban, reason } = req.body;
        const db = await getPool();
        await db.request()
            .input('id',         sql.NVarChar(36),      req.params.id)
            .input('is_banned',  sql.Bit,               ban ? 1 : 0)
            .input('ban_reason', sql.NVarChar(sql.MAX), reason || null)
            .query(`UPDATE dbo.users SET is_banned=@is_banned, ban_reason=@ban_reason WHERE id=@id`);
        sendSuccess(res, { message: ban ? 'User banned.' : 'User unbanned.' });
    } catch (err) {
        sendError(res, 'Failed to update ban status.', 500);
    }
});

app.patch('/api/admin/users/:id/verify', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { approved } = req.body;
        const db = await getPool();
        await db.request()
            .input('id',          sql.NVarChar(36), req.params.id)
            .input('id_verified', sql.Bit,          approved ? 1 : 0)
            .query(`UPDATE dbo.users SET id_verified=@id_verified WHERE id=@id`);
        sendSuccess(res, { message: approved ? 'User verified.' : 'Verification rejected.' });
    } catch (err) {
        sendError(res, 'Failed to update verification.', 500);
    }
});

app.get('/api/admin/reports', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db     = await getPool();
        const result = await db.request()
            .query(`SELECT r.id, r.reason, r.details, r.[status], r.created_at,
                           u1.first_name AS reporter_name, u1.email AS reporter_email,
                           u2.first_name AS reported_name, u2.email AS reported_email
                    FROM dbo.reports r
                    JOIN dbo.users u1 ON u1.id = r.reporter_id
                    JOIN dbo.users u2 ON u2.id = r.reported_id
                    ORDER BY r.created_at DESC`);
        sendSuccess(res, result.recordset);
    } catch (err) {
        sendError(res, 'Failed to fetch reports.', 500);
    }
});

app.patch('/api/admin/reports/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { status, admin_notes } = req.body;
        const db = await getPool();
        await db.request()
            .input('id',          sql.NVarChar(36),      req.params.id)
            .input('status',      sql.NVarChar(20),      status)
            .input('admin_notes', sql.NVarChar(sql.MAX), admin_notes || null)
            .input('resolved_at', sql.DateTime2,         status === 'resolved' ? new Date() : null)
            .query(`UPDATE dbo.reports
                    SET [status]=@status, admin_notes=@admin_notes,
                        resolved_at=CASE WHEN @status='resolved' THEN @resolved_at ELSE resolved_at END
                    WHERE id=@id`);
        sendSuccess(res, { message: 'Report updated.' });
    } catch (err) {
        sendError(res, 'Failed to update report.', 500);
    }
});

// ============================================================
//  LOGOUT (client-side token invalidation)
// ============================================================

app.post('/api/auth/logout', requireAuth, async (req, res) => {
    try {
        const db = await getPool();
        await db.request()
            .input('id', sql.NVarChar(36), req.user.id)
            .query(`UPDATE dbo.users SET online=0, last_seen=SYSUTCDATETIME() WHERE id=@id`);
        sendSuccess(res, { message: 'Logged out.' });
    } catch (err) {
        sendSuccess(res, { message: 'Logged out.' }); // always succeed
    }
});

// ─── 404 handler ─────────────────────────────────────────────
app.use((req, res) =>
    res.status(404).json({ success: false, error: `Route ${req.method} ${req.path} not found.` }));

// ─── Global error handler ────────────────────────────────────
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, error: 'Internal server error.' });
});

// ─── START ───────────────────────────────────────────────────
async function start() {
    await getPool();
    app.listen(PORT, () => {
        console.log(`\n🚀 Halal-MeetUp API running on port ${PORT}`);
        console.log(`   Admin  : ${process.env.ADMIN_EMAIL || 'mdhelal.ahamed@gmail.com'}`);
        console.log(`   Notify : ${process.env.FROM_EMAIL  || 'infohalalmeetup@gmail.com'}\n`);
    });
}

start().catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});

module.exports = app;
