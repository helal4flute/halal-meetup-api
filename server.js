'use strict';
require('dotenv').config();
const express = require('express');
const sql     = require('mssql');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const helmet  = require('helmet');

const app  = express();
const PORT = process.env.PORT || 3000;

// Strip any accidental spaces, equals signs, or quotes from env vars
function cleanEnv(val, fallback) {
  if (!val) return fallback || '';
  // Remove leading/trailing whitespace, equals signs, quotes
  return val.replace(/^[\s='"]+|[\s='"]+$/g, '').trim();
}

const dbConfig = {
  server:   cleanEnv(process.env.DB_SERVER),
  database: cleanEnv(process.env.DB_NAME, 'HalalMeetUp'),
  user:     cleanEnv(process.env.DB_USER),
  password: cleanEnv(process.env.DB_PASSWORD),
  port:     parseInt(cleanEnv(process.env.DB_PORT, '1433'), 10),
  options:  { encrypt: true, enableArithAbort: true, trustServerCertificate: false },
  pool:     { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// Log cleaned config on startup (password hidden)
console.log('[DB Config]');
console.log('  server  :', dbConfig.server);
console.log('  database:', dbConfig.database);
console.log('  user    :', dbConfig.user);
console.log('  port    :', dbConfig.port);

let pool = null;

// ── General purpose email sender ────────────────────────────────
async function sendEmail(toEmail, type, subject, body) {
  const htmlBody = '<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px;">'
    + '<div style="background:#0d7377;padding:16px 24px;border-radius:10px 10px 0 0;">'
    + '<h1 style="color:#fff;margin:0;font-size:22px;">Halal-MeetUp</h1></div>'
    + '<div style="background:#f9f9f9;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e0e0e0;">'
    + '<p style="color:#333;white-space:pre-line;line-height:1.6;">' + body.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</p>'
    + '<hr style="border:none;border-top:1px solid #eee;margin:20px 0;">'
    + '<p style="color:#aaa;font-size:12px;">Halal-MeetUp Team · infohalalmeetup@gmail.com</p>'
    + '</div></div>';
  try {
    await sendVerificationEmail(toEmail, '', '', subject, body, htmlBody);
  } catch(e) {
    console.error('sendEmail failed:', e.message);
  }
}

// ── Verification email sender ────────────────────────────────────
async function sendVerificationEmail(email, name, code, subject, emailBody, htmlBody) {
  // Try SendGrid first
  if (cleanEnv(process.env.SENDGRID_API_KEY)) {
    try {
      const https = require('https');
      const sgPayload = JSON.stringify({
        personalizations: [{ to: [{ email, name: name || '' }] }],
        from: { email: cleanEnv(process.env.FROM_EMAIL, 'infohalalmeetup@gmail.com'), name: 'Halal-MeetUp' },
        subject,
        content: [
          { type: 'text/plain', value: emailBody },
          { type: 'text/html',  value: htmlBody  },
        ],
      });
      await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.sendgrid.com', path: '/v3/mail/send', method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + cleanEnv(process.env.SENDGRID_API_KEY),
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(sgPayload),
          },
        }, (res) => {
          res.on('data', () => {});
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) resolve();
            else reject(new Error('SendGrid ' + res.statusCode));
          });
        });
        req.on('error', reject);
        req.write(sgPayload);
        req.end();
      });
      console.log('[EMAIL SENT via SendGrid] To:', email, '| Code:', code);
      return true;
    } catch (e) {
      console.error('[SendGrid failed]:', e.message);
    }
  }
  return false;
}
async function getPool() {
  if (!pool) { pool = await sql.connect(dbConfig); }
  return pool;
}

app.use(helmet());
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => res.json({ app: 'Halal-MeetUp API', status: 'ok', version: '1.0' }));
app.get('/api/health', (req, res) => res.json({ app: 'Halal-MeetUp API', status: 'ok', version: '1.0' }));

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role },
    cleanEnv(process.env.JWT_SECRET) || 'dev-secret', { expiresIn: '7d' });
}
function ok(res, data, status=200) { return res.status(status).json({ success: true, data }); }
function err(res, msg, status=400) { return res.status(status).json({ success: false, error: msg }); }

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return err(res, 'Authentication required.', 401);
  try { req.user = jwt.verify(token, cleanEnv(process.env.JWT_SECRET) || 'dev-secret'); next(); }
  catch { return err(res, 'Invalid or expired token.', 401); }
}

// ── AUTH ─────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone, dob,
            gender, sect, marital_status, education, country, city,
            nationality, languages, occupation, bio, interests,
            photo_1='', photo_2='', photo_3='' } = req.body;
    // Validate core required fields individually for clear error messages
    if (!first_name||!first_name.trim()) return err(res, 'First name is required.');
    if (!last_name||!last_name.trim())   return err(res, 'Last name is required.');
    if (!email||!email.trim())           return err(res, 'Email is required.');
    if (!password)                       return err(res, 'Password is required.');
    if (password.length < 8)            return err(res, 'Password must be at least 8 characters.');
    if (!phone||!phone.trim())           return err(res, 'Phone number is required.');
    if (!dob)                            return err(res, 'Date of birth is required.');
    const hash = await bcrypt.hash(password, 12);

    // Sanitise CHECK-constrained fields — default to valid values
    const safeGender  = ['Male','Female'].includes(gender) ? gender : 'Male';
    const safeStatus  = ['Never Married','Divorced','Widowed'].includes(marital_status)
                        ? marital_status : 'Never Married';
    // Parse DOB safely
    let safeDob;
    try {
      safeDob = new Date(dob);
      if (isNaN(safeDob.getTime())) throw new Error('Invalid date');
    } catch {
      return err(res, 'Invalid date of birth. Please use YYYY-MM-DD format.');
    }

    const db   = await getPool();
    const r    = await db.request()
      .input('first_name',     sql.NVarChar(100), first_name)
      .input('last_name',      sql.NVarChar(100), last_name)
      .input('email',          sql.NVarChar(255), email.toLowerCase())
      .input('password_hash',  sql.NVarChar(255), hash)
      .input('phone',          sql.NVarChar(20),  phone)
      .input('dob',            sql.Date,          safeDob)
      .input('gender',         sql.NVarChar(10),  safeGender)
      .input('sect',           sql.NVarChar(100), sect||''||'')
      .input('marital_status', sql.NVarChar(30),  safeStatus)
      .input('education',      sql.NVarChar(100), education||''||'')
      .input('country',        sql.NVarChar(100), country||''||'')
      .input('city',           sql.NVarChar(100), city||''||'')
      .input('nationality',    sql.NVarChar(100), nationality||''||'')
      .input('languages',      sql.NVarChar(255), languages||''||'')
      .input('occupation',     sql.NVarChar(150), occupation||''||'')
      .input('bio',            sql.NVarChar(sql.MAX), bio||'')
      .input('interests',      sql.NVarChar(sql.MAX), interests||'')
      .input('photo_1',        sql.NVarChar(500), photo_1)
      .input('photo_2',        sql.NVarChar(500), photo_2)
      .input('photo_3',        sql.NVarChar(500), photo_3)
      .execute('dbo.sp_RegisterUser');
    const user  = r.recordset[0];
    const token = signToken(user);

    // Send welcome email
    const welcomeBody = [
      'Assalamu Alaikum '+first_name+',',
      '',
      'Welcome to Halal-MeetUp! Your account has been created successfully.',
      '',
      'GETTING STARTED',
      '1. Complete your profile — upload photos and write a genuine bio.',
      '2. Discover matches — swipe right to like.',
      '3. Chat — text chat is free with all your matches.',
      '',
      'PREMIUM ($10/month): Audio & Video calls · Ludo game · Live photos',
      'Cancel anytime from My Profile > Settings.',
      '',
      'SAFETY: All profiles are ID-verified. Complete yours in the app.',
      '',
      'Need help? infohalalmeetup@gmail.com',
      '',
      'JazakAllah khayr,',
      'The Halal-MeetUp Team'
    ].join('\n');
    sendEmail(email,'welcome','Welcome to Halal-MeetUp! 🌙',welcomeBody)
      .catch(e=>console.error('Welcome email failed:',e.message));

    return ok(res, { user, token }, 201);
  } catch(e) {
    if (e.message?.includes('already registered')) return err(res,'Email already registered.');
    if (e.message?.includes('18 years'))           return err(res,'You must be at least 18 years old.');
    if (e.message?.includes('CHECK constraint'))   return err(res,'Invalid profile data: ' + e.message);
    if (e.message?.includes('NOT NULL'))           return err(res,'Missing required field: ' + e.message);
    console.error('Register error:', e.message);
    // Return the actual error message in development for easier debugging
    const isDev = process.env.NODE_ENV !== 'production';
    return err(res, isDev ? ('Registration failed: ' + e.message) : 'Registration failed. Please try again.', 500);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email||!password) return err(res,'Email and password required.');
    const db = await getPool();
    const r  = await db.request()
      .input('email', sql.NVarChar(255), email.toLowerCase())
      .query(`SELECT id, first_name, last_name, email, password_hash,
                     gender, sect, marital_status, education, country, city,
                     nationality, languages, occupation, bio, interests,
                     photo_1, photo_2, photo_3, age,
                     id_verified, premium, sub_status, sub_renews_at,
                     online, last_seen, CASE WHEN email IN ('mdhelal.ahamed@gmail.com','admin@halal-meetup.com') THEN 'admin' ELSE role END AS role, is_banned, created_at
              FROM dbo.users WHERE email = @email`);
    if (!r.recordset.length) return err(res,'No account found. Please sign up first.',401);
    const u = r.recordset[0];
    if (u.is_banned) return err(res,'Account suspended. Contact support.',403);
    const valid = await bcrypt.compare(password, u.password_hash);
    if (!valid) return err(res,'Incorrect password.',401);
    await db.request().input('id',sql.NVarChar(36),u.id)
      .query(`UPDATE dbo.users SET online=1, last_seen=SYSUTCDATETIME() WHERE id=@id`);
    delete u.password_hash;
    return ok(res, { user: u, token: signToken(u) });
  } catch(e) {
    console.error('Login:', e.message);
    return err(res,'Login failed.',500);
  }
});

// ── In-memory verification code store (use Redis in production) ──
const verificationCodes = new Map(); // email -> {code, expires, name}

// Send email verification code
app.post('/api/auth/send-verification', async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email || !email.includes('@')) return err(res, 'Valid email is required.');

    // Check email not already registered (non-blocking — DB might be slow)
    try {
      const db = await getPool();
      const existing = await db.request()
        .input('email', sql.NVarChar(255), email.toLowerCase())
        .query('SELECT id FROM dbo.users WHERE email = @email');
      if (existing.recordset.length)
        return err(res, 'This email is already registered. Please log in instead.');
    } catch (dbErr) {
      console.error('DB check failed (continuing):', dbErr.message);
      // Continue — don't block sign-up if DB is slow
    }

    // Generate 6-digit code, store in memory (10 min expiry)
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000;
    verificationCodes.set(email.toLowerCase(), { code, expires, name });

    // Build the verification email
    const subject = 'Your Halal-MeetUp verification code: ' + code;
    const emailBody = [
      'Assalamu Alaikum ' + (name || 'Member') + ',',
      '',
      'Your Halal-MeetUp email verification code is:',
      '',
      '    ' + code,
      '',
      'Enter this code in the app to complete your registration.',
      'This code expires in 10 minutes.',
      '',
      'If you did not sign up for Halal-MeetUp, please ignore this email.',
      '',
      'JazakAllah khayr,',
      'The Halal-MeetUp Team',
      'infohalalmeetup@gmail.com',
    ].join('\n');

    // ── Build HTML email ─────────────────────────────────────────
    const htmlBody = '<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px;">'
      + '<div style="background:#0d7377;padding:16px 24px;border-radius:10px 10px 0 0;">'
      + '<h1 style="color:#fff;margin:0;font-size:22px;">Halal-MeetUp</h1></div>'
      + '<div style="background:#f9f9f9;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e0e0e0;">'
      + '<p style="color:#333;font-size:16px;">Assalamu Alaikum <strong>' + (name||'Member') + '</strong>,</p>'
      + '<p style="color:#555;">Your email verification code is:</p>'
      + '<div style="background:#fff;border:2px solid #0d7377;border-radius:12px;padding:24px;text-align:center;margin:20px 0;">'
      + '<span style="font-size:40px;font-weight:bold;letter-spacing:10px;color:#0d7377;">' + code + '</span>'
      + '</div>'
      + '<p style="color:#888;font-size:13px;">This code expires in <strong>10 minutes</strong>.</p>'
      + '<p style="color:#888;font-size:13px;">If you did not sign up for Halal-MeetUp, please ignore this email.</p>'
      + '<hr style="border:none;border-top:1px solid #eee;margin:20px 0;">'
      + '<p style="color:#aaa;font-size:12px;">JazakAllah khayr,<br><strong>The Halal-MeetUp Team</strong><br>infohalalmeetup@gmail.com</p>'
      + '</div></div>';

    // ── Send via SendGrid ─────────────────────────────────────────
    const emailSent = await sendVerificationEmail(email, name, code, subject, emailBody, htmlBody);
    // ── Log to console regardless ────────────────────────────
    if (!emailSent) {
      console.log('============================================');
      console.log('[VERIFICATION CODE - check Railway logs]');
      console.log('  To:   ', email);
      console.log('  Name: ', name);
      console.log('  Code: ', code);
      console.log('  Exp:  ', new Date(expires).toLocaleString());
      console.log('============================================');
    }

    // ── Log to DB (non-blocking) ─────────────────────────────
    getPool().then(db => db.request()
      .input('to_email', sql.NVarChar(255), email.toLowerCase())
      .input('type',     sql.NVarChar(20),  'verification')
      .input('subject',  sql.NVarChar(255), subject)
      .input('status',   sql.NVarChar(10),  emailSent ? 'sent' : 'failed')
      .execute('dbo.sp_LogEmail')
    ).catch(e => console.error('Email log to DB failed (non-critical):', e.message));

    // Always return success with the code (for testing without SendGrid)
    return ok(res, {
      message: emailSent
        ? 'Verification code sent to ' + email
        : 'Verification code generated. Check Railway logs for the code.',
      emailSent: emailSent,
      // Return code in response when no SendGrid — so app can show it
      code: !emailSent ? code : undefined,
    }, 200);

  } catch (e) {
    console.error('send-verification critical error:', e.message);
    return err(res, 'Server error. Please try again.', 500);
  }
});

// Verify the email code
app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return err(res, 'Email and code are required.');

    const stored = verificationCodes.get(email.toLowerCase());
    if (!stored)
      return err(res, 'No verification code found. Please request a new one.');
    if (Date.now() > stored.expires)
      return err(res, 'Code has expired. Please request a new one.');
    if (stored.code !== code.toString().trim())
      return err(res, 'Incorrect code. Please try again.');

    // Code is valid — mark as verified
    verificationCodes.delete(email.toLowerCase());
    return ok(res, { verified: true, message: 'Email verified successfully.' });

  } catch (e) {
    console.error('verify-email error:', e.message);
    return err(res, 'Verification failed. Please try again.', 500);
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, new_password } = req.body;
    if (!email || !code || !new_password)
      return err(res, 'Email, code and new password are required.');
    if (new_password.length < 8)
      return err(res, 'Password must be at least 8 characters.');

    // Verify code is still valid
    const stored = verificationCodes.get(email.toLowerCase());
    if (!stored)
      return err(res, 'Reset code has expired. Please request a new one.');
    if (Date.now() > stored.expires)
      return err(res, 'Reset code has expired. Please request a new one.');
    if (stored.code !== code.toString().trim())
      return err(res, 'Incorrect reset code.');

    // Hash new password and update user
    const hash = await bcrypt.hash(new_password, 12);
    const db   = await getPool();
    const result = await db.request()
      .input('email', sql.NVarChar(255), email.toLowerCase())
      .input('hash',  sql.NVarChar(255), hash)
      .query(`UPDATE dbo.users SET password_hash=@hash, updated_at=SYSUTCDATETIME()
              WHERE email=@email`);

    if (result.rowsAffected[0] === 0)
      return err(res, 'No account found with that email.');

    // Invalidate the code
    verificationCodes.delete(email.toLowerCase());

    // Send confirmation email
    sendEmail(email, 'system', 'Halal-MeetUp: Password Reset Successful',
      ['Assalamu Alaikum,','','Your password has been reset successfully.',
       'If you did not do this contact: infohalalmeetup@gmail.com',
       '','JazakAllah khayr,','The Halal-MeetUp Team'].join('\n')
    ).catch(e => console.error('Reset email failed:', e.message));

    return ok(res, { message: 'Password reset successfully. Please sign in with your new password.' });
  } catch (e) {
    console.error('reset-password error:', e.message);
    return err(res, 'Password reset failed. Please try again.', 500);
  }
});


// Old OTP stub — keep for backward compatibility
app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.request().input('id',sql.NVarChar(36),req.user.id)
      .query(`UPDATE dbo.users SET online=0, last_seen=SYSUTCDATETIME() WHERE id=@id`);
    return ok(res,{message:'Logged out.'});
  } catch { return ok(res,{message:'Logged out.'}); }
});

// ── USERS ─────────────────────────────────────────────────────
app.get('/api/users/me', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('id',sql.NVarChar(36),req.user.id)
      .query(`SELECT u.id,u.first_name,u.last_name,u.email,u.phone,u.gender,u.sect,
                     u.marital_status,u.education,u.country,u.city,u.nationality,
                     u.languages,u.occupation,u.bio,u.interests,
                     u.photo_1,u.photo_2,u.photo_3,
                     DATEDIFF(YEAR,u.dob,GETDATE()) AS age,
                     u.id_verified,u.premium,u.sub_status,u.sub_renews_at,
                     u.online,u.last_seen,u.role,u.created_at,
                     (SELECT COUNT(*) FROM dbo.matches WHERE user1_id=u.id OR user2_id=u.id) AS match_count,
                     (SELECT COUNT(*) FROM dbo.likes WHERE to_user_id=u.id) AS like_count
              FROM dbo.users u WHERE u.id=@id`);
    if (!r.recordset.length) return err(res,'Not found.',404);
    return ok(res, r.recordset[0]);
  } catch(e) { return err(res,'Failed.',500); }
});

app.put('/api/users/me', auth, async (req, res) => {
  try {
    const fields = ['first_name','last_name','occupation','city','country',
                    'sect','interests','nationality','education','bio','marital_status',
                    'photo_1','photo_2','photo_3'];
    const db = await getPool();
    const rq = db.request().input('id',sql.NVarChar(36),req.user.id);
    const sets = ['updated_at=SYSUTCDATETIME()'];
    for (const f of fields) {
      if (req.body[f]!==undefined) { sets.push(`${f}=@${f}`); rq.input(f,sql.NVarChar(sql.MAX),req.body[f]); }
    }
    await rq.query(`UPDATE dbo.users SET ${sets.join(',')} WHERE id=@id`);
    return ok(res,{message:'Profile updated.'});
  } catch(e) { return err(res,'Update failed.',500); }
});

app.get('/api/users/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('id',sql.NVarChar(36),req.params.id)
      .query(`SELECT id,first_name,last_name,age,gender,sect,marital_status,
                     education,country,city,nationality,languages,occupation,
                     bio,interests,photo_1,photo_2,photo_3,id_verified,online,last_seen
              FROM dbo.vw_PublicProfiles WHERE id=@id`);
    if (!r.recordset.length) return err(res,'Not found.',404);
    return ok(res,r.recordset[0]);
  } catch(e) { return err(res,'Failed.',500); }
});

// ── DISCOVER ──────────────────────────────────────────────────
app.get('/api/discover', auth, async (req, res) => {
  try {
    const db = await getPool();
    const page     = parseInt(req.query.page||'0');
    const pageSize = parseInt(req.query.page_size||'20');
    // Get user's gender for opposite-gender matching
    const meR = await db.request()
      .input('uid', sql.NVarChar(36), req.user.id)
      .query('SELECT gender FROM dbo.users WHERE id=@uid');
    const myGender = meR.recordset[0]?.gender || '';
    const oppGender = myGender === 'Male' ? 'Female' : myGender === 'Female' ? 'Male' : '';
    // Build discover query — no id_verified requirement for pilot
    const r = await db.request()
      .input('uid',      sql.NVarChar(36), req.user.id)
      .input('offset',   sql.Int, page * pageSize)
      .input('pageSize', sql.Int, pageSize)
      .input('oppGender',sql.NVarChar(10), oppGender)
      .query(`SELECT u.id, u.first_name, u.last_name,
                     DATEDIFF(YEAR,u.dob,GETDATE()) AS age,
                     u.city, u.country, u.sect, u.marital_status,
                     u.bio, u.occupation, u.interests,
                     u.photo_1, u.photo_2, u.photo_3,
                     u.id_verified, u.online, u.premium
              FROM dbo.users u
              WHERE u.id <> @uid
                AND u.is_banned = 0
                AND (@oppGender = '' OR u.gender = @oppGender)
                AND u.id NOT IN (
                  SELECT to_user_id FROM dbo.likes WHERE from_user_id=@uid
                )
                AND u.id NOT IN (
                  SELECT CASE WHEN user1_id=@uid THEN user2_id ELSE user1_id END
                  FROM dbo.matches WHERE user1_id=@uid OR user2_id=@uid
                )
              ORDER BY u.premium DESC, u.id_verified DESC, u.created_at DESC
              OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY`);
    return ok(res, r.recordset);
  } catch(e) { console.error('Discover:',e.message); return err(res,'Failed to load profiles.',500); }
});

// ── SEARCH ────────────────────────────────────────────────────
app.get('/api/search', auth, async (req, res) => {
  try {
    const { name, country, sect, marital_status, verified_only, min_age, max_age } = req.query;
    const db = await getPool();
    const rq = db.request().input('uid',sql.NVarChar(36),req.user.id);
    let where = 'u.id<>@uid AND u.is_banned=0';
    if (name)            { where+=` AND (u.first_name LIKE @nm OR u.last_name LIKE @nm)`;
                           rq.input('nm',sql.NVarChar(100),`%${name}%`); }
    if (country)         { where+=` AND (u.city LIKE @c OR u.country LIKE @c)`;
                           rq.input('c',sql.NVarChar(100),`%${country}%`); }
    if (sect)            { where+=` AND u.sect LIKE @s`;
                           rq.input('s',sql.NVarChar(100),`%${sect}%`); }
    if (marital_status)  { where+=` AND u.marital_status=@ms`;
                           rq.input('ms',sql.NVarChar(30),marital_status); }
    if (verified_only==='true') where+=' AND u.id_verified=1';
    if (min_age)         { where+=` AND DATEDIFF(YEAR,u.dob,GETDATE())>=@mina`;
                           rq.input('mina',sql.Int,parseInt(min_age)); }
    if (max_age)         { where+=` AND DATEDIFF(YEAR,u.dob,GETDATE())<=@maxa`;
                           rq.input('maxa',sql.Int,parseInt(max_age)); }
    const q = 'SELECT u.id, u.first_name, u.last_name,'
            + ' DATEDIFF(YEAR,u.dob,GETDATE()) AS age,'
            + ' u.city, u.country, u.sect, u.marital_status,'
            + ' u.photo_1, u.id_verified, u.online, u.bio'
            + ' FROM dbo.users u'
            + ' WHERE ' + where
            + ' ORDER BY u.id_verified DESC, u.online DESC, u.created_at DESC'
            + ' OFFSET 0 ROWS FETCH NEXT 50 ROWS ONLY';
    const r = await rq.query(q);
    return ok(res, r.recordset);
  } catch(e) { console.error('Search:',e.message); return err(res,'Search failed.',500); }
});

// ── LIKES & MATCHES ───────────────────────────────────────────
app.post('/api/likes', auth, async (req, res) => {
  try {
    const { to_user_id } = req.body;
    if (!to_user_id) return err(res,'to_user_id required.');
    if (to_user_id === req.user.id) return err(res,'Cannot like yourself.');
    const db = await getPool();

    // Get sender's name for notification
    const senderR = await db.request()
      .input('uid', sql.NVarChar(36), req.user.id)
      .query('SELECT first_name, last_name FROM dbo.users WHERE id=@uid');
    const sender = senderR.recordset[0] || {};
    const senderName = (sender.first_name || 'Someone') + ' ' + (sender.last_name ? sender.last_name[0] + '.' : '');

    // Execute like + match check
    const r = await db.request()
      .input('from_user_id', sql.NVarChar(36), req.user.id)
      .input('to_user_id',   sql.NVarChar(36), to_user_id)
      .execute('dbo.sp_LikeUser');
    const result = r.recordset[0] || {};

    if (result.result !== 'MATCHED') {
      // Single like — notify the liked user
      await db.request()
        .input('to_uid',   sql.NVarChar(36),  to_user_id)
        .input('from_uid', sql.NVarChar(36),  req.user.id)
        .input('title',    sql.NVarChar(200),  senderName + ' liked your profile! 💚')
        .input('body',     sql.NVarChar(500),  "If you like them back, you'll match and can start chatting.")
        .query(`INSERT INTO dbo.notifications (user_id,type,title,body,related_user_id,is_read)
                VALUES (@to_uid,'like',@title,@body,@from_uid,0)`)
        .catch(e => console.error('Like notification failed:', e.message));
    }

    return ok(res, result);
  } catch(e) { console.error('Like error:', e.message); return err(res, 'Failed.', 500); }
});

app.get('/api/matches', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('user_id',sql.NVarChar(36),req.user.id).execute('dbo.sp_GetMatches');
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

app.delete('/api/matches/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.request().input('mid',sql.NVarChar(36),req.params.id).input('uid',sql.NVarChar(36),req.user.id)
      .query(`DELETE FROM dbo.matches WHERE id=@mid AND (user1_id=@uid OR user2_id=@uid)`);
    return ok(res,{message:'Removed.'});
  } catch(e) { return err(res,'Failed.',500); }
});

// ── MESSAGES ──────────────────────────────────────────────────
app.get('/api/matches/:id/messages', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request()
      .input('match_id',        sql.NVarChar(36),req.params.id)
      .input('requesting_user', sql.NVarChar(36),req.user.id)
      .execute('dbo.sp_GetMessages');
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

app.post('/api/matches/:id/messages', auth, async (req, res) => {
  try {
    const { text, to_user_id, blocked_reason=null } = req.body;
    if (!text?.trim()) return err(res,'text required.');
    if (!to_user_id)   return err(res,'to_user_id required.');
    const db = await getPool();
    const r  = await db.request()
      .input('match_id',      sql.NVarChar(36),     req.params.id)
      .input('from_user_id',  sql.NVarChar(36),     req.user.id)
      .input('to_user_id',    sql.NVarChar(36),     to_user_id)
      .input('text',          sql.NVarChar(sql.MAX),text.trim())
      .input('blocked_reason',sql.NVarChar(20),     blocked_reason)
      .execute('dbo.sp_SendMessage');
    return ok(res, r.recordset[0], 201);
  } catch(e) {
    if (e.message?.includes('Match not found')) return err(res,'Match not found.',403);
    return err(res,'Failed.',500);
  }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.request().input('mid',sql.NVarChar(36),req.params.id).input('uid',sql.NVarChar(36),req.user.id)
      .query(`UPDATE dbo.messages SET is_deleted=1 WHERE id=@mid AND from_user_id=@uid`);
    return ok(res,{message:'Deleted.'});
  } catch(e) { return err(res,'Failed.',500); }
});

app.patch('/api/messages/:id/react', auth, async (req, res) => {
  try {
    const { emoji } = req.body;
    if (!emoji) return err(res,'emoji required.');
    const db = await getPool();
    const r  = await db.request().input('id',sql.NVarChar(36),req.params.id)
      .query(`SELECT reactions FROM dbo.messages WHERE id=@id`);
    if (!r.recordset.length) return err(res,'Not found.',404);
    let rx = JSON.parse(r.recordset[0].reactions||'[]');
    const i = rx.indexOf(emoji); if(i>=0) rx.splice(i,1); else rx.push(emoji);
    await db.request().input('id',sql.NVarChar(36),req.params.id)
      .input('rx',sql.NVarChar(sql.MAX),JSON.stringify(rx))
      .query(`UPDATE dbo.messages SET reactions=@rx WHERE id=@id`);
    return ok(res,{reactions:rx});
  } catch(e) { return err(res,'Failed.',500); }
});

// ── INTRO MESSAGES ────────────────────────────────────────────
app.post('/api/intro-messages', auth, async (req, res) => {
  try {
    const { to_user_id, text } = req.body;
    if (!to_user_id||!text?.trim()) return err(res,'to_user_id and text required.');
    const db = await getPool();
    const ex = await db.request().input('f',sql.NVarChar(36),req.user.id).input('t',sql.NVarChar(36),to_user_id)
      .query(`SELECT 1 FROM dbo.intro_messages WHERE from_user_id=@f AND to_user_id=@t`);
    if (ex.recordset.length) return err(res,'Intro already sent.');
    await db.request().input('f',sql.NVarChar(36),req.user.id).input('t',sql.NVarChar(36),to_user_id)
      .input('tx',sql.NVarChar(sql.MAX),text.trim())
      .query(`INSERT INTO dbo.intro_messages(from_user_id,to_user_id,text) VALUES(@f,@t,@tx)`);
    await db.request().input('f',sql.NVarChar(36),req.user.id).input('t',sql.NVarChar(36),to_user_id)
      .query(`UPDATE dbo.likes SET intro_sent=1 WHERE from_user_id=@f AND to_user_id=@t`);
    return ok(res,{message:'Intro sent.'},201);
  } catch(e) { return err(res,'Failed.',500); }
});

app.get('/api/intro-messages', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('uid',sql.NVarChar(36),req.user.id)
      .query(`SELECT im.id,im.from_user_id,im.text,im.is_read,im.created_at,
                     u.first_name,u.last_name,u.photo_1,u.id_verified
              FROM dbo.intro_messages im JOIN dbo.users u ON u.id=im.from_user_id
              WHERE im.to_user_id=@uid ORDER BY im.created_at DESC`);
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

// ── SUBSCRIPTIONS ─────────────────────────────────────────────
app.post('/api/subscriptions', auth, async (req, res) => {
  try {
    const { stripe_sub_id='', stripe_customer_id='', action } = req.body;
    if (!['subscribe','resubscribe','cancel','renew'].includes(action))
      return err(res,'Invalid action.');
    const db = await getPool();
    const r  = await db.request()
      .input('user_id',            sql.NVarChar(36), req.user.id)
      .input('stripe_sub_id',      sql.NVarChar(100),stripe_sub_id)
      .input('stripe_customer_id', sql.NVarChar(100),stripe_customer_id)
      .input('action',             sql.NVarChar(15), action)
      .execute('dbo.sp_UpdateSubscription');
    return ok(res, r.recordset[0]);
  } catch(e) { return err(res,'Failed.',500); }
});

app.get('/api/subscriptions/me', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('uid',sql.NVarChar(36),req.user.id)
      .query(`SELECT id,stripe_sub_id,amount_cents,currency,status,
                     current_period_start,current_period_end,cancelled_at,created_at
              FROM dbo.subscriptions WHERE user_id=@uid ORDER BY created_at DESC`);
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

// ── CALL LOGS ─────────────────────────────────────────────────
app.post('/api/calls', auth, async (req, res) => {
  try {
    const { to_user_id, call_type, sdp_offer } = req.body;
    if (!to_user_id || !call_type) return err(res, 'to_user_id and call_type required.');
    const db  = await getPool();
    const cR  = await db.request().input('uid',sql.NVarChar(36),req.user.id)
      .query("SELECT first_name,last_name FROM dbo.users WHERE id=@uid");
    const cr  = cR.recordset[0]||{};
    const callId = require('crypto').randomBytes(16).toString('hex');
    const callerName = (cr.first_name||'')+(cr.last_name?' '+cr.last_name[0]+'.':'');
    await db.request()
      .input('id',          sql.NVarChar(36),      callId)
      .input('cid',         sql.NVarChar(36),      req.user.id)
      .input('rid',         sql.NVarChar(36),      to_user_id)
      .input('ctype',       sql.NVarChar(10),      call_type)
      .input('stat',        sql.NVarChar(15),      'ringing')
      .input('sdp',         sql.NVarChar(sql.MAX), sdp_offer||'')
      .input('cname',       sql.NVarChar(200),     callerName)
      .query("INSERT INTO dbo.call_logs(id,caller_id,receiver_id,call_type,status,sdp_offer,caller_name,duration_seconds) VALUES(@id,@cid,@rid,@ctype,@stat,@sdp,@cname,0)");
    return ok(res, { call_id: callId, status: 'ringing' }, 201);
  } catch(e) { console.error('Call POST:', e.message); return err(res,'Failed: '+e.message,500); }
});

// Get single call (for polling)
app.get('/api/calls/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request()
      .input('id',  sql.NVarChar(36), req.params.id)
      .input('uid', sql.NVarChar(36), req.user.id)
      .query("SELECT id,caller_id,receiver_id,call_type,status,sdp_offer,sdp_answer,caller_name,created_at FROM dbo.call_logs WHERE id=@id AND (caller_id=@uid OR receiver_id=@uid)");
    if (!r.recordset.length) return err(res, 'Call not found.', 404);
    return ok(res, r.recordset[0]);
  } catch(e) { return err(res, 'Failed.', 500); }
});

// Answer/update call status + SDP answer
app.patch('/api/calls/:id/answer', auth, async (req, res) => {
  try {
    const { status, sdp_answer } = req.body;
    const db = await getPool();
    const sets = ["status=@status"];
    const rq   = db.request()
      .input('id',     sql.NVarChar(36), req.params.id)
      .input('uid',    sql.NVarChar(36), req.user.id)
      .input('status', sql.NVarChar(15), status || 'ended');
    if (sdp_answer) { sets.push("sdp_answer=@sdp"); rq.input('sdp', sql.NVarChar(sql.MAX), sdp_answer); }
    if (status === 'ended' || status === 'declined') {
      sets.push("ended_at=SYSUTCDATETIME()");
    }
    await rq.query("UPDATE dbo.call_logs SET " + sets.join(',') + " WHERE id=@id AND (caller_id=@uid OR receiver_id=@uid)");
    return ok(res, { updated: true });
  } catch(e) { return err(res, 'Failed.', 500); }
});


app.get('/api/calls', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('uid',sql.NVarChar(36),req.user.id)
      .query(`SELECT cl.id,cl.call_type,cl.status,cl.duration_seconds,cl.started_at,
                     u1.first_name AS caller_name,u2.first_name AS receiver_name
              FROM dbo.call_logs cl
              JOIN dbo.users u1 ON u1.id=cl.caller_id
              JOIN dbo.users u2 ON u2.id=cl.receiver_id
              WHERE cl.caller_id=@uid OR cl.receiver_id=@uid
              ORDER BY cl.started_at DESC`);
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

// ── REPORTS ───────────────────────────────────────────────────
app.post('/api/reports', auth, async (req, res) => {
  try {
    const { reported_id, reason, details=null } = req.body;
    if (!reported_id||!reason) return err(res,'reported_id and reason required.');
    const db = await getPool();
    const r  = await db.request()
      .input('reporter_id',sql.NVarChar(36),     req.user.id)
      .input('reported_id',sql.NVarChar(36),     reported_id)
      .input('reason',     sql.NVarChar(100),    reason)
      .input('details',    sql.NVarChar(sql.MAX),details)
      .execute('dbo.sp_SubmitReport');
    return ok(res, r.recordset[0], 201);
  } catch(e) { return err(res,'Failed.',500); }
});

// ── NOTIFICATIONS ─────────────────────────────────────────────
app.
// Send notification (used by call system)
app.post('/api/notifications', auth, async (req, res) => {
  try {
    const { to_user_id, type, title, body, related_match_id, call_id, call_type } = req.body;
    if (!to_user_id || !title) return err(res, 'to_user_id and title required.');
    const db = await getPool();
    await db.request()
      .input('uid',   sql.NVarChar(36),  to_user_id)
      .input('type',  sql.NVarChar(20),  type || 'system')
      .input('title', sql.NVarChar(200), title)
      .input('body',  sql.NVarChar(500), body || '')
      .input('fuid',  sql.NVarChar(36),  req.user.id)
      .input('cid',   sql.NVarChar(36),  call_id || null)
      .query("INSERT INTO dbo.notifications(user_id,type,title,body,related_user_id,call_id,is_read) VALUES(@uid,@type,@title,@body,@fuid,@cid,0)");
    return ok(res, { sent: true }, 201);
  } catch(e) {
    // call_id column may not exist yet — retry without it
    try {
      const db2 = await getPool();
      await db2.request()
        .input('uid',   sql.NVarChar(36),  to_user_id)
        .input('type',  sql.NVarChar(20),  type || 'system')
        .input('title', sql.NVarChar(200), title)
        .input('body',  sql.NVarChar(500), body || '')
        .input('fuid',  sql.NVarChar(36),  req.user.id)
        .query("INSERT INTO dbo.notifications(user_id,type,title,body,related_user_id,is_read) VALUES(@uid,@type,@title,@body,@fuid,0)");
      return ok(res, { sent: true }, 201);
    } catch(e2) { return err(res, 'Failed.', 500); }
  }
});

get('/api/notifications', auth, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().input('uid',sql.NVarChar(36),req.user.id)
      .query(`SELECT TOP 50 id,type,title,body,related_user_id,related_match_id,is_read,created_at
              FROM dbo.notifications WHERE user_id=@uid ORDER BY created_at DESC`);
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

app.patch('/api/notifications/read-all', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.request()
      .input('uid', sql.NVarChar(36), req.user.id)
      .query("UPDATE dbo.notifications SET is_read=1 WHERE user_id=@uid");
    return ok(res, { done: true });
  } catch(e) { return err(res, 'Failed.', 500); }
});

app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.request().input('id',sql.NVarChar(36),req.params.id).input('uid',sql.NVarChar(36),req.user.id)
      .query("UPDATE dbo.notifications SET is_read=1 WHERE id=@id AND user_id=@uid");
    return ok(res,{message:'Marked read.'});
  } catch(e) { return err(res,'Failed.',500); }
});

// ── ADMIN ─────────────────────────────────────────────────────
function admin(req,res,next){ if(req.user?.role!=='admin') return err(res,'Admin only.',403); next(); }

app.get('/api/admin/stats', auth, admin, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().execute('dbo.sp_AdminStats');
    return ok(res, r.recordset[0]);
  } catch(e) { return err(res,'Failed.',500); }
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request().query(`SELECT * FROM dbo.vw_AdminUserList ORDER BY created_at DESC`);
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

app.patch('/api/admin/users/:id/ban', auth, admin, async (req, res) => {
  try {
    const { ban, reason=null } = req.body;
    const db = await getPool();
    await db.request().input('id',sql.NVarChar(36),req.params.id)
      .input('b',sql.Bit,ban?1:0).input('r',sql.NVarChar(sql.MAX),reason)
      .query(`UPDATE dbo.users SET is_banned=@b,ban_reason=@r WHERE id=@id`);
    return ok(res,{message:ban?'Banned.':'Unbanned.'});
  } catch(e) { return err(res,'Failed.',500); }
});

app.patch('/api/admin/users/:id/verify', auth, admin, async (req, res) => {
  try {
    const { approved } = req.body;
    const db = await getPool();
    await db.request().input('id',sql.NVarChar(36),req.params.id).input('v',sql.Bit,approved?1:0)
      .query(`UPDATE dbo.users SET id_verified=@v WHERE id=@id`);
    return ok(res,{message:approved?'Verified.':'Rejected.'});
  } catch(e) { return err(res,'Failed.',500); }
});

app.get('/api/admin/reports', auth, admin, async (req, res) => {
  try {
    const db = await getPool();
    const r  = await db.request()
      .query(`SELECT r.id,r.reason,r.details,r.status,r.created_at,
                     u1.first_name AS reporter_name,u2.first_name AS reported_name
              FROM dbo.reports r
              JOIN dbo.users u1 ON u1.id=r.reporter_id
              JOIN dbo.users u2 ON u2.id=r.reported_id
              ORDER BY r.created_at DESC`);
    return ok(res, r.recordset);
  } catch(e) { return err(res,'Failed.',500); }
});

app.patch('/api/admin/reports/:id', auth, admin, async (req, res) => {
  try {
    const { status, admin_notes=null } = req.body;
    const db = await getPool();
    await db.request().input('id',sql.NVarChar(36),req.params.id)
      .input('s',sql.NVarChar(20),status).input('n',sql.NVarChar(sql.MAX),admin_notes)
      .query(`UPDATE dbo.reports SET status=@s,admin_notes=@n,
              resolved_at=CASE WHEN @s='resolved' THEN SYSUTCDATETIME() ELSE resolved_at END
              WHERE id=@id`);
    return ok(res,{message:'Updated.'});
  } catch(e) { return err(res,'Failed.',500); }
});

// ── 404 / ERROR ───────────────────────────────────────────────
app.use((req,res) => res.status(404).json({success:false,error:`${req.method} ${req.path} not found.`}));
app.use((e,req,res,next) => { console.error(e); res.status(500).json({success:false,error:'Internal error.'}); });

// ── START ─────────────────────────────────────────────────────
async function start() {
  try {
    await getPool();
    console.log('✅ SQL Server connected');
  } catch(e) {
    console.error('⚠️  DB connect failed (will retry on first request):', e.message);
  }
  
// Run DB migration for call_logs (add WebRTC columns if not exists)
async function migrateCallLogs() {
  try {
    const db = await getPool();
    const cols = await db.request().query(
      "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='call_logs'"
    );
    const existing = cols.recordset.map(r => r.COLUMN_NAME.toLowerCase());
    const toAdd = [];
    if (!existing.includes('sdp_offer'))   toAdd.push("ALTER TABLE dbo.call_logs ADD sdp_offer NVARCHAR(MAX) NULL");
    if (!existing.includes('sdp_answer'))  toAdd.push("ALTER TABLE dbo.call_logs ADD sdp_answer NVARCHAR(MAX) NULL");
    if (!existing.includes('caller_name')) toAdd.push("ALTER TABLE dbo.call_logs ADD caller_name NVARCHAR(200) NULL");
    if (!existing.includes('ended_at'))    toAdd.push("ALTER TABLE dbo.call_logs ADD ended_at DATETIME2 NULL");
    if (!existing.includes('id'))          toAdd.push("ALTER TABLE dbo.call_logs ADD id NVARCHAR(36) DEFAULT NEWID()");
    for (const sql_stmt of toAdd) {
      await db.request().query(sql_stmt);
      console.log('Migration:', sql_stmt);
    }
    if (toAdd.length > 0) console.log('[DB] call_logs migrated:', toAdd.length, 'columns added');
  } catch(e) {
    console.error('[DB Migration] call_logs:', e.message);
  }
}

migrateCallLogs();

app.listen(PORT, () => {
    console.log('\n🚀 Halal-MeetUp API on port ' + PORT);
    console.log('   Admin : ' + cleanEnv(process.env.ADMIN_EMAIL, 'mdhelal.ahamed@gmail.com'));
    console.log('   Email : ' + cleanEnv(process.env.FROM_EMAIL,  'infohalalmeetup@gmail.com') + '\n');
  });
}
start();
module.exports = app;
