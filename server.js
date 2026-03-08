#!/usr/bin/env node
'use strict';

const http   = require('node:http');
const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = 'edugrade_super_secret_key_2024';
const DB_PATH    = path.join(__dirname, 'edugrade.db');

// ═══════════════════════════════════════════════
// DATABASE SETUP
// ═══════════════════════════════════════════════
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS teachers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS assignments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id  INTEGER NOT NULL UNIQUE,
    title       TEXT NOT NULL,
    subject     TEXT DEFAULT '',
    total_marks INTEGER DEFAULT 100,
    difficulty  TEXT DEFAULT 'Intermediate',
    description TEXT DEFAULT '',
    deadline    TEXT DEFAULT '',
    strictness  TEXT DEFAULT 'standard',
    api_key     TEXT DEFAULT '',
    rubric      TEXT DEFAULT '[]',
    updated_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(teacher_id) REFERENCES teachers(id)
  );

  CREATE TABLE IF NOT EXISTS students (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER NOT NULL,
    roll       TEXT NOT NULL,
    name       TEXT NOT NULL,
    password   TEXT,
    registered INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(teacher_id, roll),
    FOREIGN KEY(teacher_id) REFERENCES teachers(id)
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id    INTEGER NOT NULL UNIQUE,
    assignment_id INTEGER NOT NULL,
    answer        TEXT NOT NULL,
    submitted_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(student_id) REFERENCES students(id)
  );

  CREATE TABLE IF NOT EXISTS results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id    INTEGER NOT NULL UNIQUE,
    scores           TEXT DEFAULT '[]',
    total_score      INTEGER DEFAULT 0,
    total_max        INTEGER DEFAULT 100,
    percentage       REAL DEFAULT 0,
    grade            TEXT DEFAULT 'F',
    strengths        TEXT DEFAULT '',
    improvements     TEXT DEFAULT '',
    overall_feedback TEXT DEFAULT '',
    code_quality     TEXT DEFAULT '',
    published        INTEGER DEFAULT 0,
    graded_at        TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(submission_id) REFERENCES submissions(id)
  );
`);
console.log('✓ Database ready');

// ═══════════════════════════════════════════════
// CRYPTO — no bcrypt needed, uses Node built-ins
// ═══════════════════════════════════════════════
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(plain, salt, 100000, 64, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}
function checkPassword(plain, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.pbkdf2Sync(plain, salt, 100000, 64, 'sha256').toString('hex') === hash;
}
function b64url(d) {
  return (Buffer.isBuffer(d) ? d : Buffer.from(d)).toString('base64url');
}
function makeToken(payload) {
  const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const b = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+604800 }));
  const s = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest());
  return `${h}.${b}.${s}`;
}
function readToken(token) {
  try {
    const [h, b, s] = token.split('.');
    const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest());
    if (expected !== s) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    return p.exp > Math.floor(Date.now()/1000) ? p : null;
  } catch { return null; }
}

// ═══════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
function respond(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  res.end(JSON.stringify(data));
}
function getAuth(req) {
  const h = req.headers['authorization'] || '';
  return h.startsWith('Bearer ') ? readToken(h.slice(7)) : null;
}
function requireTeacher(req) { const u = getAuth(req); return (u && u.role === 'teacher') ? u : null; }
function requireStudent(req) { const u = getAuth(req); return (u && u.role === 'student') ? u : null; }

// ═══════════════════════════════════════════════
// STATIC FILE SERVING
// ═══════════════════════════════════════════════
const MIME = { '.html':'text/html', '.css':'text/css', '.js':'application/javascript' };
function serveStatic(req, res) {
  const pub = path.join(__dirname, 'public');
  const fp  = path.join(pub, req.url === '/' ? 'index.html' : req.url);
  if (!fp.startsWith(pub)) return respond(res, 403, { error: 'Forbidden' });
  fs.readFile(fp, (err, data) => {
    if (err) {
      fs.readFile(path.join(pub, 'index.html'), (e2, d2) => {
        if (e2) return respond(res, 404, { error: 'Not found' });
        res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(d2);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
    res.end(data);
  });
}

// ═══════════════════════════════════════════════
// ROUTE HANDLERS
// ═══════════════════════════════════════════════

async function teacherRegister(req, res) {
  const { name, email, password } = await readBody(req);
  if (!name || !email || !password) return respond(res, 400, { error: 'Name, email and password required.' });
  if (password.length < 4) return respond(res, 400, { error: 'Password must be at least 4 characters.' });
  if (db.prepare('SELECT id FROM teachers WHERE email=?').get(email.toLowerCase()))
    return respond(res, 400, { error: 'Email already registered.' });
  const r = db.prepare('INSERT INTO teachers(name,email,password) VALUES(?,?,?)')
    .run(name.trim(), email.toLowerCase().trim(), hashPassword(password));
  const token = makeToken({ id: r.lastInsertRowid, role: 'teacher', name: name.trim(), email: email.toLowerCase() });
  respond(res, 201, { token, name: name.trim(), email: email.toLowerCase() });
}

async function teacherLogin(req, res) {
  const { email, password } = await readBody(req);
  if (!email || !password) return respond(res, 400, { error: 'Email and password required.' });
  const t = db.prepare('SELECT * FROM teachers WHERE email=?').get(email.toLowerCase().trim());
  if (!t || !checkPassword(password, t.password)) return respond(res, 401, { error: 'Invalid email or password.' });
  const token = makeToken({ id: t.id, role: 'teacher', name: t.name, email: t.email });
  respond(res, 200, { token, name: t.name, email: t.email });
}

async function saveAssignment(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const d = await readBody(req);
  if (!d.title) return respond(res, 400, { error: 'Title required.' });
  const ex = db.prepare('SELECT id FROM assignments WHERE teacher_id=?').get(u.id);
  if (ex) {
    db.prepare(`UPDATE assignments SET title=?,subject=?,total_marks=?,difficulty=?,description=?,deadline=?,strictness=?,api_key=?,rubric=?,updated_at=datetime('now') WHERE teacher_id=?`)
      .run(d.title, d.subject||'', d.total_marks||100, d.difficulty||'Intermediate', d.description||'', d.deadline||'', d.strictness||'standard', d.api_key||'', JSON.stringify(d.rubric||[]), u.id);
  } else {
    db.prepare('INSERT INTO assignments(teacher_id,title,subject,total_marks,difficulty,description,deadline,strictness,api_key,rubric) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .run(u.id, d.title, d.subject||'', d.total_marks||100, d.difficulty||'Intermediate', d.description||'', d.deadline||'', d.strictness||'standard', d.api_key||'', JSON.stringify(d.rubric||[]));
  }
  respond(res, 200, { message: 'Assignment saved.' });
}

function getAssignment(req, res) {
  const u = getAuth(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  let a;
  if (u.role === 'teacher') {
    a = db.prepare('SELECT * FROM assignments WHERE teacher_id=?').get(u.id);
  } else {
    const st = db.prepare('SELECT teacher_id FROM students WHERE id=?').get(u.id);
    if (!st) return respond(res, 404, { error: 'Student not found.' });
    a = db.prepare('SELECT * FROM assignments WHERE teacher_id=?').get(st.teacher_id);
  }
  if (!a) return respond(res, 404, { error: 'No assignment yet.' });
  const safe = { ...a };
  if (u.role !== 'teacher') delete safe.api_key;
  try { safe.rubric = JSON.parse(safe.rubric || '[]'); } catch { safe.rubric = []; }
  respond(res, 200, { assignment: safe });
}

function getStudents(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const students = db.prepare('SELECT id,roll,name,registered,created_at FROM students WHERE teacher_id=? ORDER BY roll').all(u.id);
  const enriched = students.map(s => {
    const sub    = db.prepare('SELECT id FROM submissions WHERE student_id=?').get(s.id);
    const result = sub ? db.prepare('SELECT published,percentage,grade FROM results WHERE submission_id=?').get(sub.id) : null;
    return { ...s, submitted: !!sub, graded: !!result, published: result?.published === 1, percentage: result?.percentage || null };
  });
  respond(res, 200, { students: enriched });
}

async function addStudent(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const { roll, name } = await readBody(req);
  if (!roll || !name) return respond(res, 400, { error: 'Roll and name required.' });
  try {
    db.prepare('INSERT INTO students(teacher_id,roll,name) VALUES(?,?,?)').run(u.id, roll.trim().toUpperCase(), name.trim());
    respond(res, 201, { message: 'Student added.' });
  } catch(e) {
    respond(res, 400, { error: e.message.includes('UNIQUE') ? 'Roll number already exists.' : e.message });
  }
}

async function bulkAdd(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const { entries } = await readBody(req);
  if (!Array.isArray(entries)) return respond(res, 400, { error: 'entries array required.' });
  const stmt = db.prepare('INSERT OR IGNORE INTO students(teacher_id,roll,name) VALUES(?,?,?)');
  let added = 0, skipped = 0;
  for (const e of entries) {
    if (e.roll && e.name) { const r = stmt.run(u.id, e.roll.trim().toUpperCase(), e.name.trim()); r.changes ? added++ : skipped++; }
  }
  respond(res, 200, { added, skipped, message: `${added} added, ${skipped} skipped.` });
}

function deleteStudent(req, res, roll) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const st = db.prepare('SELECT id FROM students WHERE teacher_id=? AND roll=?').get(u.id, roll);
  if (!st) return respond(res, 404, { error: 'Student not found.' });
  const sub = db.prepare('SELECT id FROM submissions WHERE student_id=?').get(st.id);
  if (sub) { db.prepare('DELETE FROM results WHERE submission_id=?').run(sub.id); db.prepare('DELETE FROM submissions WHERE id=?').run(sub.id); }
  db.prepare('DELETE FROM students WHERE id=?').run(st.id);
  respond(res, 200, { message: 'Student removed.' });
}

function resetStudentPwd(req, res, roll) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const st = db.prepare('SELECT id FROM students WHERE teacher_id=? AND roll=?').get(u.id, roll);
  if (!st) return respond(res, 404, { error: 'Not found.' });
  db.prepare('UPDATE students SET password=NULL, registered=0 WHERE id=?').run(st.id);
  respond(res, 200, { message: 'Reset done. Student must re-register.' });
}

async function studentRegister(req, res) {
  const { roll, password, password2 } = await readBody(req);
  if (!roll || !password) return respond(res, 400, { error: 'Roll and password required.' });
  if (password !== password2) return respond(res, 400, { error: 'Passwords do not match.' });
  if (password.length < 4) return respond(res, 400, { error: 'Password min 4 characters.' });
  const st = db.prepare('SELECT * FROM students WHERE roll=?').get(roll.trim().toUpperCase());
  if (!st) return respond(res, 404, { error: 'Roll number not in class list. Contact your teacher.' });
  if (st.registered) return respond(res, 400, { error: 'Already registered. Please use Student Login.' });
  db.prepare('UPDATE students SET password=?, registered=1 WHERE id=?').run(hashPassword(password), st.id);
  const teacher = db.prepare('SELECT name FROM teachers WHERE id=?').get(st.teacher_id);
  const token = makeToken({ id: st.id, role: 'student', name: st.name, roll: st.roll, teacher_id: st.teacher_id });
  respond(res, 200, { token, name: st.name, roll: st.roll, teacherName: teacher?.name || '' });
}

async function studentLogin(req, res) {
  const { roll, password } = await readBody(req);
  if (!roll || !password) return respond(res, 400, { error: 'Roll and password required.' });
  const st = db.prepare('SELECT * FROM students WHERE roll=?').get(roll.trim().toUpperCase());
  if (!st) return respond(res, 404, { error: 'Roll number not found. Contact your teacher.' });
  if (!st.registered || !st.password) return respond(res, 400, { error: 'Not registered yet. Please register first.' });
  if (!checkPassword(password, st.password)) return respond(res, 401, { error: 'Incorrect password.' });
  const teacher = db.prepare('SELECT name FROM teachers WHERE id=?').get(st.teacher_id);
  const token = makeToken({ id: st.id, role: 'student', name: st.name, roll: st.roll, teacher_id: st.teacher_id });
  respond(res, 200, { token, name: st.name, roll: st.roll, teacherName: teacher?.name || '' });
}

async function checkRoll(req, res) {
  const { roll } = await readBody(req);
  if (!roll) return respond(res, 400, { error: 'Roll required.' });
  const st = db.prepare('SELECT roll,name,registered FROM students WHERE roll=?').get(roll.trim().toUpperCase());
  if (!st) return respond(res, 404, { error: 'Roll number not found. Contact your teacher.' });
  respond(res, 200, { name: st.name, registered: !!st.registered });
}

async function submitWork(req, res) {
  const u = requireStudent(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const { answer } = await readBody(req);
  if (!answer?.trim()) return respond(res, 400, { error: 'Answer cannot be empty.' });
  const st = db.prepare('SELECT teacher_id FROM students WHERE id=?').get(u.id);
  if (!st) return respond(res, 404, { error: 'Student not found.' });
  const a = db.prepare('SELECT id FROM assignments WHERE teacher_id=?').get(st.teacher_id);
  if (!a) return respond(res, 404, { error: 'No assignment set up yet.' });
  if (db.prepare('SELECT id FROM submissions WHERE student_id=?').get(u.id))
    return respond(res, 400, { error: 'Already submitted.' });
  db.prepare('INSERT INTO submissions(student_id,assignment_id,answer) VALUES(?,?,?)').run(u.id, a.id, answer.trim());
  respond(res, 201, { message: 'Submitted successfully!' });
}

function getSubmissions(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const rows = db.prepare(`
    SELECT s.id AS sub_id, s.answer, s.submitted_at, s.student_id,
           st.roll, st.name,
           r.id AS result_id, r.published, r.percentage, r.grade
    FROM submissions s
    JOIN students st ON s.student_id=st.id
    JOIN assignments a ON s.assignment_id=a.id
    LEFT JOIN results r ON r.submission_id=s.id
    WHERE a.teacher_id=? ORDER BY s.submitted_at DESC
  `).all(u.id);
  respond(res, 200, { submissions: rows });
}

async function saveResult(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const d = await readBody(req);
  if (!d.submission_id) return respond(res, 400, { error: 'submission_id required.' });
  const ex = db.prepare('SELECT id FROM results WHERE submission_id=?').get(d.submission_id);
  if (ex) {
    db.prepare(`UPDATE results SET scores=?,total_score=?,total_max=?,percentage=?,grade=?,strengths=?,improvements=?,overall_feedback=?,code_quality=?,graded_at=datetime('now') WHERE submission_id=?`)
      .run(JSON.stringify(d.scores||[]), d.total_score, d.total_max, d.percentage, d.grade, d.strengths||'', d.improvements||'', d.overall_feedback||'', d.code_quality||'', d.submission_id);
  } else {
    db.prepare('INSERT INTO results(submission_id,scores,total_score,total_max,percentage,grade,strengths,improvements,overall_feedback,code_quality) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .run(d.submission_id, JSON.stringify(d.scores||[]), d.total_score, d.total_max, d.percentage, d.grade, d.strengths||'', d.improvements||'', d.overall_feedback||'', d.code_quality||'');
  }
  respond(res, 200, { message: 'Result saved.' });
}

async function updateResult(req, res, subId) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const d = await readBody(req);
  db.prepare('UPDATE results SET scores=?,total_score=?,total_max=?,percentage=?,grade=? WHERE submission_id=?')
    .run(JSON.stringify(d.scores||[]), d.total_score, d.total_max, d.percentage, d.grade, parseInt(subId));
  respond(res, 200, { message: 'Updated.' });
}

async function publishResult(req, res, subId) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const { published } = await readBody(req);
  db.prepare('UPDATE results SET published=? WHERE submission_id=?').run(published ? 1 : 0, parseInt(subId));
  respond(res, 200, { message: published ? 'Published.' : 'Unpublished.' });
}

async function publishAll(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  db.prepare(`UPDATE results SET published=1 WHERE submission_id IN (SELECT s.id FROM submissions s JOIN students st ON s.student_id=st.id WHERE st.teacher_id=?)`).run(u.id);
  respond(res, 200, { message: 'All published.' });
}

function getResults(req, res) {
  const u = requireTeacher(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const rows = db.prepare(`
    SELECT r.*, st.roll, st.name, s.id AS sub_id, s.answer
    FROM results r
    JOIN submissions s ON r.submission_id=s.id
    JOIN students st ON s.student_id=st.id
    JOIN assignments a ON s.assignment_id=a.id
    WHERE a.teacher_id=? ORDER BY r.percentage DESC
  `).all(u.id);
  respond(res, 200, { results: rows.map(r => ({ ...r, scores: JSON.parse(r.scores||'[]') })) });
}

function getMyResult(req, res) {
  const u = requireStudent(req);
  if (!u) return respond(res, 401, { error: 'Unauthorized' });
  const sub = db.prepare('SELECT * FROM submissions WHERE student_id=?').get(u.id);
  if (!sub) return respond(res, 200, { status: 'not_submitted' });
  const result = db.prepare('SELECT * FROM results WHERE submission_id=?').get(sub.id);
  if (!result) return respond(res, 200, { status: 'submitted_waiting' });
  if (!result.published) return respond(res, 200, { status: 'graded_waiting' });
  const assignment = db.prepare('SELECT title,subject,total_marks FROM assignments WHERE id=?').get(sub.assignment_id);
  respond(res, 200, { status: 'published', result: { ...result, scores: JSON.parse(result.scores||'[]') }, assignment });
}

// ═══════════════════════════════════════════════
// ROUTER
// ═══════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type,Authorization', 'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS' });
    return res.end();
  }
  const url = req.url.split('?')[0];
  const m   = req.method;
  try {
    if (m==='POST'&&url==='/api/teacher/register')   return await teacherRegister(req,res);
    if (m==='POST'&&url==='/api/teacher/login')      return await teacherLogin(req,res);
    if (m==='POST'&&url==='/api/assignment')         return await saveAssignment(req,res);
    if (m==='GET' &&url==='/api/assignment')         return getAssignment(req,res);
    if (m==='GET' &&url==='/api/students')           return getStudents(req,res);
    if (m==='POST'&&url==='/api/students')           return await addStudent(req,res);
    if (m==='POST'&&url==='/api/students/bulk')      return await bulkAdd(req,res);
    if (m==='POST'&&url==='/api/student/register')   return await studentRegister(req,res);
    if (m==='POST'&&url==='/api/student/login')      return await studentLogin(req,res);
    if (m==='POST'&&url==='/api/student/check-roll') return await checkRoll(req,res);
    if (m==='POST'&&url==='/api/submit')             return await submitWork(req,res);
    if (m==='GET' &&url==='/api/submissions')        return getSubmissions(req,res);
    if (m==='POST'&&url==='/api/results')            return await saveResult(req,res);
    if (m==='GET' &&url==='/api/results')            return getResults(req,res);
    if (m==='GET' &&url==='/api/my-result')          return getMyResult(req,res);
    if (m==='POST'&&url==='/api/publish-all')        return await publishAll(req,res);

    const mDel  = url.match(/^\/api\/students\/([^/]+)$/);
    const mRset = url.match(/^\/api\/students\/([^/]+)\/reset$/);
    const mPub  = url.match(/^\/api\/results\/(\d+)\/publish$/);
    const mUpd  = url.match(/^\/api\/results\/(\d+)$/);

    if (mDel  && m==='DELETE') return deleteStudent(req,res, decodeURIComponent(mDel[1]));
    if (mRset && m==='PUT')    return resetStudentPwd(req,res, decodeURIComponent(mRset[1]));
    if (mPub  && m==='PUT')    return await publishResult(req,res, mPub[1]);
    if (mUpd  && m==='PUT')    return await updateResult(req,res, mUpd[1]);

    serveStatic(req, res);
  } catch(err) {
    console.error('Error:', err.message);
    respond(res, 500, { error: 'Server error.' });
  }
});

server.listen(PORT, () => {
  console.log(`\n🎓  EduGrade AI running at  http://localhost:${PORT}\n`);
});