const { Client } = require("pg");
const client = new Client(
  "postgres://odvdbrrr:p10yRAxTJfqOkZU23llxcKYjeoraYJCE@rogue.db.elephantsql.com/odvdbrrr"
);

async function populateDb() {
  await client.connect();

  await client.query(`CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  hashed_password TEXT NOT NULL,
  salt TEXT NOT NULL
  )`);

  await client.query(`CREATE TABLE sessions (
  uuid TEXT PRIMARY KEY,
  user_id INTEGER,
  created_at DATE NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  await client.end();
}

populateDb();
