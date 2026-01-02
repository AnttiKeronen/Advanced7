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
if (!SECRET) {
  throw new Error("Ei o definattu");
}
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));
interface User {
  email: string;
  password: string;
}
const users: User[] = [];
app.post("/api/user/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "vaatii moelmmat" });
  }
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(403).json({ message: "Email o käytös jo" });
  }
  const hashedPassword = await bcrypt.hash(password, 6);
  const newUser: User = {
    email,
    password: hashedPassword
  };
  users.push(newUser);
  res.json(newUser);
});
app.get("/api/user/list", (_req, res) => {
  res.json(users);
});
app.post("/api/user/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ message: "väärin" });
  }
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: "väärin" });
  }
  const token = jwt.sign({ email: user.email }, SECRET, {
    expiresIn: "1h"
  });
  res.json({ token });
});
app.get("/api/private", validateToken, (_req, res) => {
  res.status(200).json({ message: "You shall not pass" });
});
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
