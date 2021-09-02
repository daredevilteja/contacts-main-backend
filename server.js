require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { mongo } = require("mongoose");
const app = express();
// const knex = require("knex")({
//   client: "mysql",
//   connection: {
//     host: "127.0.0.1",
//     user: "your_database_user",
//     password: "your_database_password",
//     database: "myapp_test",
//   },
// });

app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:4200",
  })
);

const db = mongoose.createConnection("mongodb://localhost:27017/ContactsApp", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  userId: { type: Number },
  email: { type: String, required: true },
  password: { type: String, required: true },
  token: { type: String },
});

const contactSchema = new mongoose.Schema({
  name: String,
  creationTime: Date,
  phoneNumber: mongoose.Schema.Types.Array,
  email: mongoose.Schema.Types.Array,
  userId: mongoose.Schema.Types.ObjectId,
});

const userModel = db.model("user", userSchema);
const contactModel = db.model("contact", contactSchema);

const isNullOrUndefined = (val) => val === null || val === undefined;

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader.split(" ")[1];
  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_SECRET_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await userModel.findOne({ email });
  if (isNullOrUndefined(existingUser)) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new userModel({ email, password: hashedPassword });
    const user = { name: email };
    newUser.token = jwt.sign(user, process.env.ACCESS_SECRET_TOKEN, {
      expiresIn: "2h",
    });
    newUser.userId = await userModel.count();
    await newUser.save();
    res.status(201).send("Signed Up");
  } else {
    res.sendStatus(409);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await userModel.findOne({ email });

  if (isNullOrUndefined(existingUser)) {
    res.sendStatus(401);
  } else {
    try {
      if (await bcrypt.compare(password, existingUser.password)) {
        const user = { name: existingUser.email };
        existingUser.token = jwt.sign(user, process.env.ACCESS_SECRET_TOKEN, {
          expiresIn: "2h",
        });
        res.json({ id: existingUser.userId });
      } else {
        res.send("not allowed");
      }
    } catch {
      res.sendStatus(500);
    }
  }
});

app.get("/home", authenticateToken, async (req, res) => {
  const contacts = await contactModel.find();
  res.send(contacts);
});

app.listen(9999);
