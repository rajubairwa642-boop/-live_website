// server.js — Roles: user, admin + Email Verification
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const nodemailer = require("nodemailer");

const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_demo";
const USERS_FILE = path.join(__dirname, "users.json");

// ---------- helpers: file db ----------
function readUsers() {
  try {
    const raw = fs.existsSync(USERS_FILE) ? fs.readFileSync(USERS_FILE, "utf-8") : "[]";
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
function writeUsers(list) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(list, null, 2));
}

// ---------- middleware ----------
app.use(cors());
app.use(express.json());

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
function adminOnly(req, res, next) {
  if (req.user?.role === "admin") return next();
  return res.status(403).json({ error: "Admin only" });
}

// ---------- Email Setup ----------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "ishvarekh@gmail.com",        // अपना Gmail डालो
    pass: "okfa lnyl rexz vhuy"         // App password (Google से बनाया हुआ)
  },
});

// ---------- routes ----------
app.get("/", (_, res) => res.send("✅ Backend with Auth + Roles + Email is running"));

/**
 * Register
 * body: { username, email, password }
 */
app.post("/auth/register", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: "username, email, password required" });
  }

  const users = readUsers();
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "Email already in use" });
  }

  const hash = await bcrypt.hash(password, 10);
  const role = users.length === 0 ? "admin" : "user";
  const verifyToken = uuid();
  const user = {
    id: uuid(),
    username,
    email,
    passwordHash: hash,
    role,
    createdAt: Date.now(),
    verified: false,            // नया field
    verifyToken                 // verify link के लिए token
  };
  users.push(user);
  writeUsers(users);

  // send verification email
  const verifyLink = `http://localhost:${PORT}/auth/verify/${verifyToken}`;
  try {
    await transporter.sendMail({
      from: '"My App" <ishvarekh@gmail.com>',
      to: email,
      subject: "Verify your email",
      text: `Hi ${username}, please verify your account: ${verifyLink}`,
      html: `<p>Hi <b>${username}</b>,</p><p>Please verify your account by clicking the link below:</p><a href="${verifyLink}">Verify Email</a>`,
    });
  } catch (e) {
    console.error("Email send failed", e);
  }

  res.json({ message: "Registered successfully. Please check your email to verify your account." });
});

/**
 * Email verification
 */
app.get("/auth/verify/:token", (req, res) => {
  const { token } = req.params;
  const users = readUsers();
  const user = users.find(u => u.verifyToken === token);
  if (!user) return res.status(400).send("Invalid verification link");

  user.verified = true;
  delete user.verifyToken; // token हटा दो
  writeUsers(users);

  res.send("✅ Email verified successfully! You can now login.");
});

/**
 * Login
 * body: { email, password }
 */
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email, password required" });

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  if (!user.verified) {
    return res.status(403).json({ error: "Please verify your email first" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ uid: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role }, token });
});

/** Current user */
app.get("/auth/me", auth, (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.user.uid);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role, verified: user.verified } });
});

// ---------- Admin APIs ----------
/** List all users (admin only) */
app.get("/admin/users", auth, adminOnly, (req, res) => {
  const users = readUsers().map(u => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    verified: u.verified,
    createdAt: u.createdAt
  }));
  res.json({ users });
});

/** Delete a user (admin only) */
app.delete("/admin/users/:id", auth, adminOnly, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });

  if (users[idx].id === req.user.uid) {
    return res.status(400).json({ error: "You cannot delete yourself" });
  }

  users.splice(idx, 1);
  writeUsers(users);
  res.json({ ok: true });
});

// ---------- start ----------
app.listen(PORT, () => console.log(`🔐 Auth API running at http://localhost:${PORT}`));
