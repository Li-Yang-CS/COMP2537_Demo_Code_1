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
  PORT = 3000,
} = process.env;

// App constants
const app = express();
const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

// Session store
const mongoUrl = `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/sessions`;
app.use(
  session({
    secret: NODE_SESSION_SECRET,
    store: MongoStore.create({
      mongoUrl,
      crypto: { secret: MONGODB_SESSION_SECRET },
    }),
    saveUninitialized: false,
    resave: false,
    cookie: {
      maxAge: expireTime,
      httpOnly: true,
    },
  })
);

// Database
const { database } = include(
  "databaseConnection"
);
const userCollection = database
  .db(MONGODB_DATABASE)
  .collection("users");

// Joi Schemas
const signupSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .max(20)
    .required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.authenticated)
    return res.redirect("/");
  next();
}

// Routes
// Home
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    return res.send(`
      <h1>Hello, ${req.session.username}</h1>
      <a href="/members">Members Area</a><br>
      <a href="/logout">Log Out</a>
    `);
  }
  res.send(`
    <h1>Welcome</h1>
    <a href="/signup">Sign Up</a><br>
    <a href="/login">Log In</a>
  `);
});

// Sign-up
app
  .route("/signup")
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
    const { error, value } =
      signupSchema.validate(req.body);
    if (error) {
      return res.send(
        `<p style="color:red">${error.details[0].message}</p><a href="/signup">Retry</a>`
      );
    }
    const hashed = await bcrypt.hash(
      value.password,
      saltRounds
    );
    await userCollection.insertOne({
      username: value.username,
      email: value.email,
      password: hashed,
    });
    req.session.authenticated = true;
    req.session.username = value.username;
    res.redirect("/members");
  });

// Log-in
app
  .route("/login")
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
    const { error, value } = loginSchema.validate(
      req.body
    );
    if (error) {
      return res.send(
        `<p style="color:red">${error.details[0].message}</p><a href="/login">Retry</a>`
      );
    }
    const found = await userCollection.findOne({
      email: value.email,
    });
    if (
      !found ||
      !(await bcrypt.compare(
        value.password,
        found.password
      ))
    ) {
      return res.send(
        `<p>Invalid email or password</p><a href="/login">Retry</a>`
      );
    }
    req.session.authenticated = true;
    req.session.username = found.username;
    res.redirect("/members");
  });

// NoSQL Injection
app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;
  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult =
    schema.validate(username);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  res.send(`<h1>Hello ${username}</h1>`);
});

// Members area
app.get("/members", requireAuth, (req, res) => {
  const pics = [
    "3.0CSL.jpg",
    "e92.jpg",
    "f80.jpg",
  ];
  const pick =
    pics[Math.floor(Math.random() * pics.length)];
  res.send(`
    <h1>Hello, ${req.session.username}</h1>
    <img src="/${pick}" style="width:1000px"><br>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404 catch-all
app.use((req, res) =>
  res.status(404).send("404 Not Found")
);

// Start server
app.listen(PORT, () =>
  console.log(`Server listening on port ${PORT}`)
);
