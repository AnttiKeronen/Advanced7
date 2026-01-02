import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import { validateToken } from "./authMiddleware";

const app = express();
const PORT = 3000;
const SECRET = process.env.SECRET as string;
if (!SECRET) throw new Error("SECRET not defined");
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));
interface User {
  email: string;
  password: string;
}
const users: User[] = [];
app.post("/api/user/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });
  if (users.find(u => u.email === email)) return res.status(403).json({ message: "Email already used" });
  const hashedPassword = await bcrypt.hash(password, 6);
  const newUser: User = { email, password: hashedPassword };
  users.push(newUser);
  res.json(newUser);
});

app.get("/api/user/list", (_req, res) => res.json(users));
app.post("/api/user/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(401).json({ message: "Invalid credentials" });
  const token = jwt.sign({ email: user.email }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});
app.get("/api/private", validateToken, (_req, res) => {
  res.status(200).json({ message: "This is protected secure route!" });
});
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
