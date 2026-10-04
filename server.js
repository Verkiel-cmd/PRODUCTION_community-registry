import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Admin from './models/admin.js';
import fs from 'fs';
import path from 'path';
require('dotenv').config();
import rateLimit from 'express-rate-limit';
import Entry from './models/entry.js';

const app = express();
const PORT = process.env.PORT || 3000;

//Mongodb configuration
const DB_URL = process.env.ATLAS_URL;
mongoose.connect(DB_URL);
const conn = mongoose.connection;

// ============================================================
// CORS (CROSS-ORIGIN RESOURCE SHARING) CONFIGURATION
// ============================================================
//
// WHAT IS CORS?
// -------------
// When a browser loads a page from one domain (e.g. community-registry.netlify.app)
// and that page tries to make a request to a DIFFERENT domain (e.g.
// production-baranggay-registry.onrender.com), the browser considers this a
// "cross-origin request." By default, browsers BLOCK cross-origin requests
// for security reasons — this is called the "Same-Origin Policy."
//
// CORS is the mechanism that lets a server SAY which other domains ARE allowed
// to make requests to it. Without CORS, your Netlify frontend could never
// call your Render API — the browser would block every request.
//
// HOW IT WORKS UNDER THE HOOD (THE PREFLIGHT):
// ---------------------------------------------
// For "complex" requests (anything with custom headers like Authorization,
// or non-GET/POST methods like PATCH/DELETE), the browser doesn't just send
// the request directly. It does this:
//
//   1. BROWSER sends an "OPTIONS" request (called a "preflight") to the server
//      with these headers:
//        Origin: https://community-registry.netlify.app
//        Access-Control-Request-Method: PATCH
//        Access-Control-Request-Headers: Content-Type, Authorization
//
//   2. SERVER checks: Is this origin allowed? Is this method allowed? Are
//      these headers allowed?
//
//   3. If YES → server responds with:
//        Access-Control-Allow-Origin: https://community-registry.netlify.app
//        Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS
//        Access-Control-Allow-Headers: Content-Type, Authorization
//
//   4. BROWSER sees the "yes" → sends the actual PATCH/POST request.
//
// If the server says "no" or doesn't respond with the right headers,
// the browser blocks the request and your JavaScript gets a CORS error.
//
// WHY DO YOU SEE CORS ERRORS IN THE CONSOLE?
// -------------------------------------------
// If your frontend tries to call the API and the server doesn't have CORS
// configured (or the origin isn't in the allowlist), the browser blocks
// the response. Your JavaScript .catch() or error handler fires with a
// message like:
//   "Access to fetch at 'https://production-baranggay-registry.onrender.com/api/entries'
//    from origin 'https://community-registry.netlify.app' has been blocked by CORS policy"
//
// This means: your server needs to explicitly say "Netlify, you're allowed."
//
//
// ============================================================
// THE ACTUAL CODE — LINE BY LINE
// ============================================================
//
// Here is exactly what the CORS setup does, with each piece explained:
//

// LINE 1: Import the cors npm package.
// This package is a helper that creates the CORS middleware for Express.
// Without it, you'd have to manually set all the headers yourself.
//
//const cors = require('cors');

// LINE 2: Define the list of domains that ARE allowed to call your API.
// Only requests coming from these exact URLs will be permitted.
// Any other domain gets blocked with "Not allowed by CORS."
//
// RULES:
//   - No trailing slashes (browsers send "https://example.com", not "https://example.com/")
//   - Must match EXACTLY — "https://netlify.app" and "https://community-registry.netlify.app" are different
//   - Include the Netlify domain because that's where your frontend lives and requests originate FROM
//   - Include the Render domain if you ever serve the frontend from there too
//
//const allowedOrigins = [
    //'https://community-registry.netlify.app',
    //'https://production-baranggay-registry.onrender.com',
//];

// LINE 3: Register the CORS middleware with Express.
// This middleware runs BEFORE every route handler. It checks every incoming
// request and either allows it (adds CORS headers) or blocks it.
//
// app.use(cors({...})) means: "For every request that comes in, run this
// CORS check FIRST, before it reaches any route handler (GET, POST, PATCH, etc.)."
//
//app.use(cors({

  // THE "origin" FUNCTION:
  // ----------------------
  // This function is called by the cors middleware for EVERY incoming request.
  // It receives two arguments:
  //
  //   origin (string | undefined)
  //     - The value of the "Origin" header sent by the browser.
  //     - Example: "https://community-registry.netlify.app"
  //     - Can be UNDEFINED if:
  //         a) The request is same-origin (same domain as the server)
  //         b) The request comes from a tool like Postman or curl (no browser)
  //         c) The request is a server-to-server call (no browser involved)
  //
  //   callback (function)
  //     - A function you MUST call at the end.
  //     - callback(null, true)  → ALLOW the request (add CORS headers)
  //     - callback(error)       → BLOCK the request (no CORS headers → browser rejects it)
  //
  // WHY CHECK FOR !origin?
  //   - If origin is undefined (Postman, curl, same-domain), we allow it
  //     because these are not cross-origin requests. CORS only matters
  //     when a BROWSER is making a cross-origin request.
  //   - If we blocked requests with no origin, you couldn't test your API
  //     with Postman or make server-to-server calls.
  //
  // WHY CHECK allowedOrigins.includes(origin)?
  //   - This is the actual security check. We look at where the request
  //     came from and compare it against our allowlist.
  //   - If the origin is in the list → allow it.
  //   - If it's NOT in the list → block it.
  //   - This prevents any random website from calling your API.
  //     For example, if someone made "evil-hacker.com" and tried to
  //     call your API from there, the browser would send
  //     Origin: https://evil-hacker.com, which is NOT in our list,
  //     so the request gets blocked.
  //
  //origin: function (origin, callback) {
    //if (!origin || allowedOrigins.includes(origin)) {
      //callback(null, true);
    //} else {
      //allback(new Error('Not allowed by CORS'));
    //}
  //}
//}))

// ============================================================
// COMMON CORS MISTAKES TO AVOID
// ============================================================
//
// 1. DO NOT call cors() with no arguments:
//      app.use(cors())   // ← WRONG — allows ALL origins
//    This is like having a bouncer who lets everyone in. It defeats
//    the purpose of having an allowlist.
//
// 2. DO NOT define allowedOrigins AFTER the cors() middleware:
//      app.use(cors({ origin: function that uses allowedOrigins }))
//      const allowedOrigins = ['...']  // ← WRONG — defined too late
//    The variable must be defined BEFORE the middleware uses it.
//
// 3. DO NOT add trailing slashes to URLs:
//      'https://community-registry.netlify.app/'  // ← WRONG
//    Browsers send the Origin header WITHOUT a trailing slash.
//    Your check will never match.
//
// 4. DO NOT forget that requests come from the BROWSER (Netlify),
//    not from your server (Render). Your allowlist needs the
//    frontend domain, not just the backend domain.
//
// 5. DO NOT use two cors middlewares:
//      app.use(cors({ restricted config }))
//      app.use(cors())  // ← WRONG — overrides the restricted one
//    The second one opens everything back up.
//
// ============================================================
// SUMMARY: WHAT THIS CODE DOES
// ============================================================
//
// When a request comes in:
//
//   1. Browser sends: "Hey, I'm from community-registry.netlify.app"
//   2. Cors middleware checks: Is that in allowedOrigins? → YES
//   3. Response includes: Access-Control-Allow-Origin: https://community-registry.netlify.app
//   4. Browser allows the JavaScript to read the response.
//
// When a request comes from a random site:
//
//   1. Browser sends: "Hey, I'm from evil-hacker.com"
//   2. Cors middleware checks: Is that in allowedOrigins? → NO
//   3. Response does NOT include CORS headers (or includes an error)
//   4. Browser blocks the response. JavaScript gets a CORS error.
//
// ============================================================

const cors = require('cors');
app.use(express.static('public'));
app.use(express.json());

const allowedOrigins = [
    'https://community-registry.netlify.app',
    'https://production-baranggay-registry.onrender.com',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}))

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { error: 'Too many requests, please try again later.'},
    standardHeaders: true,
    legacyHeaders: false,
});

conn.once('open', () => {
  console.log('Successfully connected to the database!');
});

function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  // "Bearer eyJhbG..."

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
   
    req.admin = decoded;  
    next();               
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.post('/api/admin/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    // bcrypt.compare('admin123', '$2a$10$xYz...') → true or false

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    /*TOKEN*/
    const token = jwt.sign(
      { username: admin.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

//const DATA_FILE = path.join(__dirname, 'data.json');

let refCounter = 232;

//const DEFAULT_ENTRIES = [
    //{ref:'MLY-2026-0231', title:'Streetlight out along Purok 4', category:'Infrastructure repair', purok:'Purok 4', date:'Jul 12, 2026', status:'pending'},
    //{ref:'MLY-2026-0230', title:'Barangay clearance for employment', category:'Document request', purok:'Purok 2', date:'Jul 11, 2026', status:'released'},
    //{ref:'MLY-2026-0229', title:'Loose dog roaming near school', category:'Peace & order', purok:'Purok 1', date:'Jul 10, 2026', status:'progress'},
    //{ref:'MLY-2026-0228', title:'Clogged drainage causing flooding', category:'Infrastructure repair', purok:'Purok 6', date:'Jul 9, 2026', status:'urgent'},
    //{ref:'MLY-2026-0227', title:'Request for indigency certificate', category:'Document request', purok:'Purok 3', date:'Jul 8, 2026', status:'released'},
  //];

//function loadEntries() {
  //try {
    //if (fs.existsSync(DATA_FILE)) {
      //const raw = fs.readFileSync(DATA_FILE, 'utf-8');
      //const parsed = JSON.parse(raw);
      //if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    //}
  //} catch (e) {
    //console.error('Failed to load data.json, using defaults:', e.message);
  //}
  //return DEFAULT_ENTRIES.slice();
//}

//function saveEntries() {
  //try {
    //fs.writeFileSync(DATA_FILE, JSON.stringify(entries, null, 2));
  //} catch (e) {
    //console.error('Failed to save data.json:', e.message);
  //}
//}

//let entries = loadEntries();

app.get('/api/entries', authLimiter, async (req, res) => {
         try {
           const entries = await Entry.find().sort({ date: -1 });
           res.json(entries);
         } catch (e) {
           res.status(500).json({ error: 'Failed to load entries' });
         }
       });

//app.get('/api/entries', async (req, res) => {
    //res.json(entries);
//});

//app.post('/api/entries', async (req, res) => {
         //try {
           //const { fullname, title, category, purok } = req.body;
           //if (!fullname || !title || !category || !purok) {
             //return res.status(400).json({ error: 'Missing required request fields.' });
           //}
 
           //const count = await Entry.countDocuments();
           //const newRef = `MLY-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
           //const newRef = `MLY-2026-${String(232 + count).padStart(4, '0')}`;
 
           //const newEntry = new Entry({
             //ref: newRef,
             //fullname,
             //title,
             //category,
             //purok,
             //date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'Asia/Manila' }),
             //status: 'pending'
           //});
 
           //await newEntry.save();
           //res.status(201).json({ message: 'Entry saved successfully!', entry: newEntry });
         //} catch (e) {
           //res.status(500).json({ error: 'Failed to save entry' });
         //}
       //});

       app.post('/api/entries', authLimiter, async (req, res) => {
         try {
           const { fullname, title, category, purok } = req.body;
           if (!fullname || !title || !category || !purok) {
             return res.status(400).json({ error: 'Missing required request fields.' });
           }
 
           const now = new Date();
           const year = now.toLocaleDateString('en-US', { year: 'numeric', timeZone: 'Asia/Manila' });
           const md = now.toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', timeZone: 'Asia/Manila' }).replace('/', '');
           const newRef = `MLY-${year}-${md}-${Math.random().toString(36).slice(2, 8)}`;
 
           const newEntry = new Entry({
             ref: newRef,
             fullname,
             title,
             category,
             purok,
             date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'Asia/Manila' }),
             status: 'pending'
           });
 
           await newEntry.save();
           res.status(201).json({ message: 'Entry saved successfully!', entry: newEntry });
         } catch (e) {
           res.status(500).json({ error: 'Failed to save entry' });
         }
       });

//app.post('/api/entries', (req, res) => {
    //const { title, category, purok } = req.body;

    //if (!title || !category || !purok) {
        //return res.status(400).json({ error: 'Missing required request fields.' });
    //}

    //const newEntry = {
        //ref: `MLY-2026-${String(refCounter++).padStart(4, '0')}`,
        //title: title,
        //category: category,
        //purok: purok,
        //date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
        //status: 'pending'
    //};

    //entries.unshift(newEntry); 
    //saveEntries();
    //res.status(201).json({ message: 'Entry saved successfully!', entry: newEntry });
//});

app.patch('/api/entries/:ref', authenticateAdmin, authLimiter, async (req, res) => {
  try {
    const { ref } = req.params;
    const { status, note } = req.body;

    const update = {};
    if (status) update.status = status;
    if (note !== undefined) update.note = note;

    const entry = await Entry.findOneAndUpdate(
    { ref },
    { $set: update },
    { new: true }
  );
    if (!entry) {
      return res.status(404).json({ error: 'Record reference not found' });
    }

    res.json({ message: 'Record updated successfully!', entry });
  } catch (e) {
    console.error('PATCH error:', e.message);
    res.status(500).json({ error: 'Failed to update entry' });
  }
});

// --- Server Startup ---
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

