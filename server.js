const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const hasher = require("pbkdf2-password-hash");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Client } = require("pg");

const app = express();
const PORT = process.env.PORT || 8080;

const connectionString =
  "postgres://odvdbrrr:p10yRAxTJfqOkZU23llxcKYjeoraYJCE@rogue.db.elephantsql.com/odvdbrrr";
const client = new Client(connectionString);
client.connect();

const corsOptions = {
  origin: ["http://localhost:3000"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.get("/", (req, res) => {
  res.json({ response: "running" });
});
app.post("/login", handleLogin);
app.delete("/login", handleUserLogout);
app.post("/register", handleRegistration);
app.post("/verify-session", verifySession);

app.listen(PORT, () => {
  console.log(`Example app listening on port ${PORT}`);
});
module.exports = app;

async function handleLogin(server) {
  const { email, password } = await server.body;
  const users = (await client.queryObject(`SELECT * FROM users;`)).rows;
  let user;
  users.forEach((currentUser) => {
    if (currentUser.email === email) {
      user = currentUser;
    }
  });
  const userExists = user !== undefined;
  const passwordIsValid = userExists
    ? await bcrypt.compare(password, user.hashed_password)
    : false;
  if (!(userExists && passwordIsValid))
    return server.json({ error: "Email or password is incorrect" }, 400);
  // EDGE CASE: user left site and deleted their cookies
  await client.queryObject("DELETE FROM sessions WHERE user_id = $1;", user.id);
  const sessionUUID = v4.generate();
  await client.queryObject(
    "INSERT INTO sessions (uuid, user_id, created_at) VALUES ($1, $2, NOW());",
    sessionUUID,
    user.id
  );
  //Cookies must be set from frontend because of netlify
  return server.json({ response: sessionUUID });
}

async function handleUserLogout(server, res) {
  const sessionId = server.queryParams;
  const user = await getCurrentUser(sessionId);
  if (user.length > 0) {
    const query = `DELETE FROM sessions WHERE user_id = $1`;
    await client.query(query, [user[0].id]);
    return res.json({ response: "Successfully logged out" });
  }
  return res.status(400).json({ error: "User not logged in" });
}

async function handleRegistration(server) {
  const { email, password } = await server.body;

  const salt = await bcrypt.genSalt(8);
  const hashed_password = await bcrypt.hash(password, salt);
  try {
    await client.queryObject(
      "INSERT INTO users (email, hashed_password, salt) VALUES ($1,$2)",
      email,
      hashed_password,
      salt
    );
  } catch (e) {
    return server.json({ error: "could not add user to database" }, 500);
  }
  server.json({ response: "User added successfully" }, 200);
}

async function getCurrentUser(sessionId) {
  const query =
    "SELECT * FROM users JOIN sessions ON users.id = sessions.user_id WHERE sessions.created_at < NOW() + INTERVAL '7 DAYS' AND sessions.uuid = $1";
  const user = await client.query(query, [sessionId]);
  return user.rows;
}

async function verifySession(server) {
  const { sessionID } = server.queryParams;
  const sessions = (await client.queryObject("SELECT * FROM sessions")).rows;

  let isValid = false;
  sessions.forEach((session) => {
    if (session.uuid === sessionID) isValid = true;
  });

  return server.json({ response: isValid });
}
