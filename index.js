require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

const {
  MONGODB_HOST,
  MONGODB_USER,
  MONGODB_PASSWORD,
  MONGODB_DATABASE,
  MONGODB_SESSION_SECRET,
  NODE_SESSION_SECRET
} = process.env;

var { database } = include("databaseConnection");
const userCollection = database.db(MONGODB_DATABASE).collection("users");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

const mongoUrl = `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/sessions`;
const mongoStore = MongoStore.create({
  mongoUrl,
  crypto: { secret: MONGODB_SESSION_SECRET }
});

app.use(session({
  secret: NODE_SESSION_SECRET,
  store: mongoStore,
  saveUninitialized: false,
  resave: false,
  cookie: { maxAge: expireTime, httpOnly: true }
}));

// Home page
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
      <h1>Welcome</h1>
      <a href="/signup">Sign Up</a><br>
      <a href="/login">Log In</a>
    `);
  } else {
    res.send(`
      <h1>Hello, ${req.session.username}</h1>
      <a href="/members">Members Area</a><br>
      <a href="/logout">Log Out</a>
    `);
  }
});

// Sign-up
app.get("/signup", (req, res) => {
  res.send(`
    <h1>Sign Up</h1>
    <form action="/signup" method="post">
      <input name="username" type="text" placeholder="username"><br>
      <input name="email" type="email" placeholder="email"><br>
      <input name="password" type="password" placeholder="password"><br>
      <button>Submit</button>
    </form>
  `);
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email:    Joi.string().email().required(),
    password: Joi.string().max(20).required()
  });
  const { error } = schema.validate({ username, email, password });
  if (error) {
    return res.send(`
      <h1>Sign Up Error</h1>
      <p>${error.details[0].message}</p>
      <a href="/signup">Try again</a>
    `);
  }

  const hashed = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ username, email, password: hashed });
  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

// Log-in
app.get("/login", (req, res) => {
  res.send(`
    <h1>Log In</h1>
    <form action="/login" method="post">
      <input name="email" type="email" placeholder="email"><br>
      <input name="password" type="password" placeholder="password"><br>
      <button>Submit</button>
    </form>
  `);
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const schema = Joi.string().email().required();
  const { error } = schema.validate(email);
  if (error) {
    return res.send(`
      <h1>Log In Error</h1>
      <p>Invalid email format.</p>
      <a href="/login">Try again</a>
    `);
  }

  const users = await userCollection
    .find({ email })
    .project({ username: 1, password: 1 })
    .toArray();

  if (users.length !== 1) {
    return res.send(`
      <h1>Invalid email or password</h1>
      <a href="/login">Try again</a>
    `);
  }

  const user = users[0];
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.send(`
      <h1>Invalid email or password</h1>
      <a href="/login">Try again</a>
    `);
  }

  req.session.authenticated = true;
  req.session.username = user.username;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

// Members area
app.get("/members", (req, res) => {
  if (!req.session.authenticated) return res.redirect("/");
  const images = ["3.0CSL.jpg", "e92.jpg", "f80.jpg"];
  const pick = images[Math.floor(Math.random() * images.length)];
  res.send(`
    <h1>Hello, ${req.session.username}</h1>
    <img src="/${pick}" style="width:1000px;"><br>
    <a href="/logout">Log Out</a>
  `);
});

// Log-out
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404 catch-all
app.get("*", (req, res) => {
  res.status(404).send("404 Not Found");
});

app.listen(port, () => {
  console.log(`Node application listening on port ${port}`);
});
