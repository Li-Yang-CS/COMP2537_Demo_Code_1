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

app.set("view engine", "ejs");

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

// From Example
function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", {
      error: "Not Authorized - You must be an admin to access this page.",
    });
    return;
  } else {
    next();
  }
}

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

// Routes
// Home EJS
app.get("/", (req, res) => {
  res.render("index");
});

// Sign-up
app
  .route("/signup")
  .get((req, res) => {
    res.render("signup", {
      errorMessage: null,
    });
  })
  .post(async (req, res) => {
    const { error, value } =
      signupSchema.validate(req.body);
    if (error) {
      return res.render("signup", {
        errorMessage: error.details[0].message,
      });
    }
    const hashed = await bcrypt.hash(
      value.password,
      saltRounds
    );
    await userCollection.insertOne({
      username: value.username,
      email: value.email,
      password: hashed,
      user_type: "user",
    });
    req.session.authenticated = true;
    req.session.username = value.username;
    res.redirect("/members");
  });

// Log-in
app
  .route("/login")
  .get((req, res) => {
    res.render("login", {
      errorMessage: null,
    });
  })
  .post(async (req, res) => {
    const { error, value } = loginSchema.validate(
      req.body
    );
    if (error) {
      return res.render("login", {
        errorMessage: error.details[0].message,
      });
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
      return res.render("login", {
        errorMessage: "Invalid email or password",
      });
    }
    req.session.authenticated = true;
    req.session.username = found.username;
    req.session.user_type = found.user_type;
    res.redirect("/members");
  });

// Members area EJS
app.get("/members", requireAuth, (req, res) => {
  const images = [
    "3.0CSL.jpg",
    "e92.jpg",
    "f80.jpg",
  ];

  res.render("members", {
    username: req.session.username,
    images: images,
  });
});

// Admin area EJS
app.get(
  "/admin",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const result = await userCollection
      .find()
      .project({
        username: 1,
        user_type: 1,
        _id: 1,
      })
      .toArray();

    res.render("admin", { users: result });
  }
);

// Add new routes for promote/demote functionality
app.get(
  "/promote/:id",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const userId = req.params.id;

    try {
      // Update the user's type to admin
      await userCollection.updateOne(
        {
          _id: new require("mongodb").ObjectId(
            userId
          ),
        },
        { $set: { user_type: "admin" } }
      );
      res.redirect("/admin");
    } catch (error) {
      console.error(
        "Error promoting user:",
        error
      );
      res.status(500).render("errorMessage", {
        error:
          "Failed to promote user. Please try again.",
      });
    }
  }
);

app.get(
  "/demote/:id",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const userId = req.params.id;

    try {
      // Update the user's type to regular user
      await userCollection.updateOne(
        {
          _id: new require("mongodb").ObjectId(
            userId
          ),
        },
        { $set: { user_type: "user" } }
      );
      res.redirect("/admin");
    } catch (error) {
      console.error(
        "Error demoting user:",
        error
      );
      res.status(500).render("errorMessage", {
        error:
          "Failed to demote user. Please try again.",
      });
    }
  }
);

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404 catch-all EJS
app.get("*", (req, res) => {
  res.status(404).render("404");
});

// Start server
app.listen(PORT, () =>
  console.log(`Server listening on port ${PORT}`)
);
