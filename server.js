// server.js
import express from "express";
import Stripe from "stripe";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs-extra";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ───────── Stripe ─────────
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ───────── ES Module __dirname fix ─────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ───────── Auth config ─────────
const USERS_FILE = path.join(__dirname, "users.json");
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";

// Helpers
const readUsers = async () => {
  try {
    const exists = await fs.pathExists(USERS_FILE);
    if (!exists) {
      await fs.writeJson(USERS_FILE, []);
    }
    return fs.readJson(USERS_FILE);
  } catch (err) {
    console.error("READ USERS ERROR:", err);
    return []; // fallback empty array
  }
};


const writeUsers = async (users) => {
  try {
    await fs.writeJson(USERS_FILE, users, { spaces: 2 });
  } catch (err) {
    console.error("WRITE USERS ERROR:", err);
    throw err;
  }
};

// ───────── AUTH ROUTES ─────────

// REGISTER
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const users = await readUsers();
    const exists = users.find(u => u.email === email);
    if (exists) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now(),
      email,
      password: hashedPassword,
    };

    users.push(newUser);
    await writeUsers(users);

    const token = jwt.sign(
      { id: newUser.id, email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, email });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const users = await readUsers();
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, email });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// ───────── STRIPE ROUTE ─────────
app.post("/create-checkout-session", async (req, res) => {
  try {
    const { title, price } = req.body;

    if (!title || !price || price <= 0) {
      return res.status(400).json({ error: "Invalid book data" });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            unit_amount: Math.round(price * 100),
            product_data: { name: title },
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: "http://localhost:3000/success",
      cancel_url: "http://localhost:3000/cancel",
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("STRIPE ERROR:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ───────── START SERVER ─────────
app.listen(4242, () => console.log("Backend running on port 4242"));
