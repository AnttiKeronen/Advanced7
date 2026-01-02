import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import path from "path";
import { validateToken } from "./authMiddleware";

dotenv.config();

const app = express();
const PORT = 3000;
const SECRET = process.env.SECRET as string;

if (!SECRET) throw new Error("SECRET not defined in .env");

app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

interface User {
  email: string;
  password: string;
}

const users: User[] = [];

// Registration route
app.post("/api/user/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  if (users.find(u => u.email === email)) return res.status(403).json({ message: "Email already in use" });

  const hashedPassword = await bcrypt.hash(password, 6);
  const newUser: User = { email, password: hashedPassword };
  users.push(newUser);

  res.json(newUser);
});

// Login route
app.post("/api/user/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ email: user.email }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// Private route
app.get("/api/private", validateToken, (_req, res) => {
  res.status(200).json({ message: "This is protected secure route!" });
});

// Serve index.html
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
