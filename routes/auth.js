const express = require("express");
const env = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const { MongoClient, Collection } = require("mongodb");
const router = express.Router();
env.config();

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URL = process.env.MONGO_URL;
const USERNAME = process.env.GMAILUSERNAME;
const PASSWORD = process.env.PASSWORD;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REFRESH_TOKEN = process.env.REFRESH_TOKEN

// connection to gmail using nodemailer
const OAuth2 = google.auth.OAuth2;

const oauth2Client = new OAuth2(
  CLIENT_ID, // ClientID
  CLIENT_SECRET, // Client Secret
  "https://developers.google.com/oauthplayground" // Redirect URL
);

oauth2Client.setCredentials({
  refresh_token: REFRESH_TOKEN
});
const accessToken = oauth2Client.getAccessToken()

const mailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: USERNAME,
    // pass: PASSWORD,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    refreshToken: REFRESH_TOKEN, 
    accessToken:accessToken,
    tls: {
      rejectUnauthorized: false
    }
  },
});

// making a connection with mongodb database.
const client = new MongoClient(MONGO_URL);

// Database Name
const dbName = "guvi";

async function main() {
  // Use connect method to connect to the server
  await client.connect();
  console.log("Connected successfully to server");
  const db = client.db(dbName);
  const collection = db.collection("authUser");
  return db;
}

const db = main();

// endpoint for sign up functionality
router.post("/signup", async (request, response) => {
  const { name, email, password } = request.body;
  if (!name || !email || !password) {
    return response.send({ message: "Please fill in all the fields" });
  }
  (await db)
    .collection("authUser")
    .findOne({ email: email })
    .then((dbUser) => {
      if (dbUser) {
        return response
          .status(422)
          .send({ message: "Try with different email" });
      }
      bcrypt.hash(password, 10).then(async (hashedPassword) => {
        const user = {
          name: name,
          email: email,
          password: hashedPassword,
          active: false,
          resetString: null,
          resetToken: null,
          expireToken: null,
        };
        (await db)
          .collection("authUser")
          .insertOne(user)
          .then(() => {
            response
              .send({ message: "User created" })
              .catch((err) => console.log(err));
          });
      });
    });
});

// endpoint for login functionality.
router.post("/login", async (request, response) => {
  console.log(request.body);
  const { email, password } = request.body;
  if (!email || !password) {
    return response.send({ message: "Please fill out the email and password" });
  }
  (await db)
    .collection("authUser")
    .findOne({ email: email })
    .then((user) => {
      if (!user) {
        return response.send({ message: "Invalid Credentials" });
      }
      bcrypt.compare(password, user.password).then((match) => {
        if (match) {
          const jwtToken = jwt.sign({ _id: user._id }, JWT_SECRET);
          const { _id, email, name } = user;
          response.send({ jwtToken, name: name, email: email });
        } else {
          return response.send({ message: "Invalid Credentials" });
        }
      });
    })
    .catch((err) => console.log(err));
});

// endpoint for forget password functionality
router.post("/forgot-password", async (request, response) => {
  const { email } = request.body;
  crypto.randomBytes(32, async (error, buffer) => {
    if (error) {
      console.log(error);
    }
    const token = buffer.toString("hex");
    (await db)
      .collection("authUser")
      .findOne({ email: email })
      .then(async (user) => {
        if (!user) {
          return response.send({ message: "Invalid username" });
        }
        (await db)
          .collection("authUser")
          .updateOne(
            { email: email },
            { $set: { resetToken: token, expireToken: Date.now() + 3600000 } }
          )
          .then((result) => {
            let mailDetails = {
              to: user.email,
              from: "no-replay@insta.com",
              subject: "password reset",
              html: `
                <p>You requested for password reset</p>
                <h5>click in this <a href="http://localhost:3000/reset-password-form/${token}">link</a> to reset password</h5>
                `,
            };
            mailTransporter.sendMail(mailDetails, function (error, data) {
              if (error) {
                console.log(error);
              } else {
                console.log("Email sent successfully");
              }
            });
            response.send({ message: "Email Sent" });
          });
      });
  });
});

router.post("/new-password", async (request, response) => {
  const { password, token } = request.body;
  (await db)
    .collection("authUser")
    .findOne({ resetToken: token, expireToken: { $gt: Date.now() } })
    .then((user) => {
      if (!user) {
        response.send({ message: "Session expired please try again" });
      }
      bcrypt.hash(password, 12).then(async (hashedpassword) => {
        (await db)
          .collection("authUser")
          .updateOne(
            { resetToken: token, expireToken: { $gt: Date.now() } },
            {
              $set: {
                password: hashedpassword,
                resetToken: null,
                expireToken: null,
              },
            }
          )
          .then(() => {
            response.json({ message: "password updated success" });
          });
      });
    })
    .catch((err) => {
      console.log(err);
    });
});

exports.userRouter = router;
