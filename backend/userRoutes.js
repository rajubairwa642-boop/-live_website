const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const { createUser, findUserByEmail, findUserByUsername, getAllUsers } = require("./userModel");
const nodemailer = require("nodemailer");

const router = express.Router();

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (findUserByEmail(email)) {
    return res.status(400).json({ msg: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = createUser({
    id: uuidv4(),
    username,
    email,
    passwordHash: hashedPassword,
    verified: false
  });

  // ✅ Mail Setup
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "ishvarekh@gmail.com",        // तुम्हारा Gmail
      pass: "okfalnylrexzvhuy"            // App Password
    }
  });

  try {
    await transporter.sendMail({
      from: '"My App" <ishvarekh@gmail.com>',
      to: email,
      subject: "Welcome to My App 🎉",
      html: `<h2>Hello ${username}!</h2>
             <p>Your account has been created successfully ✅</p>
             <p>Please verify your email to activate login 🚀</p>`
    });

    console.log("Mail sent to:", email);
  } catch (error) {
    console.error("Mail error:", error);
  }

  res.json({ msg: "User registered successfully, mail sent!", user: newUser });
});

// ================= LOGIN (Email or Username) =================
router.post("/login", async (req, res) => {
  const { emailOrUsername, password } = req.body;

  // पहले email से खोजो
  let user = findUserByEmail(emailOrUsername);

  // अगर email से नहीं मिला, तो username से खोजो
  if (!user) {
    user = findUserByUsername(emailOrUsername);
  }

  if (!user) {
    return res.status(400).json({ msg: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.status(400).json({ msg: "Invalid credentials" });
  }

  // JWT Token बनाना
  const token = jwt.sign({ id: user.id }, "secretkey", { expiresIn: "1h" });
  res.json({ msg: "Login successful", token, user });
});

// ================= GET ALL USERS (Testing) =================
router.get("/users", (req, res) => {
  res.json(getAllUsers());
});

module.exports = router;
