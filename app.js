const express = require("express");
const jsonwebtoken = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const app = express();
const port = 3000;
const salt = 10;

app.use(express.json());

const JWT_KEY = "";

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jsonwebtoken.verify(token, JWT_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

app.use(async (req, res, next) => {
  global.db = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "bvt_demo",
    multipleStatements: true,
  });

  global.db.query(`SET time_zone = '-8:00'`);
  await next();
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, salt);

    const result = await global.db.query(
      "INSERT INTO user (email, password) VALUES (?, ?)",
      [email, hashedPassword],
    );

    res
      .status(201)
      .send({ message: "User created successfully", userId: result.insertId });
  } catch (err) {
    res
      .status(500)
      .send({ message: "Failed to create user", error: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Both email and password are required");
  }

  try {
    const [[user]] = await global.db.query(
      "SELECT id, email, password FROM user WHERE email = ?",
      [email],
    );

    if (!user) {
      return res.status(401).send("No user found with this email.");
    }

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res
          .status(500)
          .send({ message: "Error while checking password" });
      }

      if (!isMatch) {
        return res.status(401).send("Password is incorrect");
      }

      const token = jsonwebtoken.sign(
        { id: user.id, email: user.email },
        JWT_KEY,
      );

      res.json({
        jwt: token,
      });
    });
  } catch (err) {
    res.status(500).send({ message: "Login Error", error: err.message });
  }
});

app.get("/", async (req, res) => {
  const [data] = await global.db.query(`SELECT * FROM car`);

  res.send({
    data,
  });
});

app.get("/car", authenticateJWT, async (req, res) => {
  const userId = req.user.id;

  try {
    const [data] = await global.db.query(
      `SELECT * FROM car WHERE user_id = ?`,
      [userId],
    );

    if (data.length === 0) {
      return res.status(404).send("No cars found for this user");
    }

    res.send({
      data,
    });
  } catch (err) {
    res
      .status(500)
      .send({ message: "Failed to fetch cars", error: err.message });
  }
});

app.get("/school/:id", async (req, res) => {
  const [data] = await global.db.query(`SELECT * FROM school WHERE id = ?`, [
    req.params.id,
  ]);

  res.send({
    data,
  });
});

app.post("/", authenticateJWT, async (req, res) => {
  const { makeId, color } = req.body;
  const userId = req.user.id;

  if (!makeId || !color) {
    return res.status(400).send("Make ID and color are required");
  }

  try {
    await global.db.query(
      `INSERT INTO car (make_id, color, user_id) VALUES (?, ?, ?)`,
      [makeId, color, userId],
    );

    res.send("Car added successfully");
  } catch (err) {
    res.status(500).send({ message: "Failed to add car", err: err.message });
  }
});

app.delete("/:id", async (req, res) => {
  await global.db.query(`DELETE FROM car WHERE id = ?`, [req.params.id]);
  res.send("I am deleting data!");
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
