// refactored index.js
require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");

// Environment variables
const {
  MONGODB_HOST,
  MONGODB_USER,
  MONGODB_PASSWORD,
  MONGODB_DATABASE,
  MONGODB_SESSION_SECRET,
  NODE_SESSION_SECRET,
  PORT = 3000
} = process.env;

// Constants
const SALT_ROUNDS = 12;
const EXPIRY = 1 * 60 * 60 * 1000; // 1 hour

// Initialize Express
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

// MongoDB session store
const mongoUrl = `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/sessions`;
app.use(
  session({
    secret: NODE_SESSION_SECRET,
    store: MongoStore.create({ mongoUrl, crypto: { secret: MONGODB_SESSION_SECRET } }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: EXPIRY, httpOnly: true }
  })
);

// Database connection
const { database } = include("databaseConnection");
const users = database.db(MONGODB_DATABASE).collection("users");

// Validation schemas
const signupSchema = Joi.object({
  username: Joi.string().alphanum().max(20).required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required()
});
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required()
});

// Middleware to protect routes
function requireAuth(req, res, next) {
  if (!req.session.authenticated) return res.redirect("/");
  next();
}

// Routes
// Home
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    return res.send(`
      <h1>Hello, ${req.session.username}</h1>
      <a href="/members">Members</a> | <a href="/logout">Logout</a>
    `);
  }
  res.send(`
    <h1>Welcome</h1>
    <a href="/signup">Sign Up</a><br>
    <a href="/login">Log In</a>
  `);
});

// Sign-up
app.route("/signup")
  .get((req, res) => {
    res.send(`
      <h1>Sign Up</h1>
      <form method="post">
        <input name="username" placeholder="Username" required><br>
        <input name="email" type="email" placeholder="Email" required><br>
        <input name="password" type="password" placeholder="Password" required><br>
        <button>Sign Up</button>
      </form>
    `);
  })
  .post(async (req, res) => {
    const { error, value } = signupSchema.validate(req.body);
    if (error) {
      return res.send(`<p style="color:red">${error.details[0].message}</p><a href="/signup">Retry</a>`);
    }
    const hashed = await bcrypt.hash(value.password, SALT_ROUNDS);
    await users.insertOne({ username: value.username, email: value.email, password: hashed });
    req.session.authenticated = true;
    req.session.username = value.username;
    res.redirect("/members");
  });

// Log-in
app.route("/login")
  .get((req, res) => {
    res.send(`
      <h1>Log In</h1>
      <form method="post">
        <input name="email" type="email" placeholder="Email" required><br>
        <input name="password" type="password" placeholder="Password" required><br>
        <button>Log In</button>
      </form>
    `);
  })
  .post(async (req, res) => {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.send(`<p style="color:red">${error.details[0].message}</p><a href="/login">Retry</a>`);
    }
    const found = await users.findOne({ email: value.email });
    if (!found || !(await bcrypt.compare(value.password, found.password))) {
      return res.send(`<p>Invalid email or password</p><a href="/login">Retry</a>`);
    }
    req.session.authenticated = true;
    req.session.username = found.username;
    res.redirect("/members");
  });

// Members area
app.get("/members", requireAuth, (req, res) => {
  const pics = ["img1.jpg", "img2.jpg", "img3.jpg"];
  const pick = pics[Math.floor(Math.random() * pics.length)];
  res.send(`
    <h1>Hello, ${req.session.username}</h1>
    <img src="/${pick}" style="width:250px"><br>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// NoSQL injection demo
app.get("/nosql-injection", async (req, res) => {
  const schema = Joi.string().max(20).required();
  const { error, value } = schema.validate(req.query.user);
  if (error) return res.send("<h1 style='color:red'>NoSQL injection detected</h1>");
  const docs = await users.find({ username: value }).toArray();
  res.send(`<pre>${JSON.stringify(docs, null, 2)}</pre>`);
});

// Static catch-all for 404
app.use((req, res) => res.status(404).send("404 Not Found"));

// Start server
app.listen(port, () => console.log(`Server on port ${port}`));
