import express from "express";
import http from "http";
import { Server } from "socket.io";
import dotenv from "dotenv";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ----------------- Supabase Setup -----------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ----------------- JWT Setup -----------------
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";

// ----------------- Admin Login -----------------
app.post("/auth/admin-login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: userData, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !userData) return res.status(400).json({ msg: "User not found" });
    if (userData.role !== "admin") return res.status(403).json({ msg: "Not an admin" });

    const isMatch = await bcrypt.compare(password, userData.password_hash);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = jwt.sign({ id: userData.id, role: userData.role }, JWT_SECRET, { expiresIn: "2h" });

    return res.json({
      token,
      admin: { id: userData.id, name: userData.name, email: userData.email },
    });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// ----------------- Socket.IO -----------------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const onlineUsers = new Map();

io.on("connection", (socket) => {
  console.log("✅ Socket connected:", socket.id);

  // ----------------- Join Room -----------------
  socket.on("join-room", ({ roomId, user }) => {
    socket.join(roomId);
    socket.data.user = user;
    onlineUsers.set(user.email, socket.id);
    io.to(roomId).emit("user_online", user.email);
    console.log(`✅ ${user.name} joined room ${roomId}`);
  });

  // ----------------- Typing -----------------
  socket.on("typing", ({ roomId, isTyping, senderName }) => {
    socket.to(roomId).emit("typing", { isTyping, senderName });
  });

  // ----------------- Send Message -----------------
  socket.on("send_message", async (msg) => {
    try {
      const { roomId, sender_id, sender_email, content, created_at } = msg;

      // Save message in Supabase
      const { error } = await supabase.from("messages").insert([{
        room_id: roomId,
        sender_id,
        sender_email,
        content,
        created_at
      }]);
      if (error) return console.error("Supabase insert error:", error);

      // Broadcast message only to members in room
      io.to(roomId).emit("receive_message", msg);
    } catch (err) {
      console.error("Message send error:", err);
    }
  });

  // ----------------- New Room -----------------
  socket.on("new_room_created", ({ id, name, is_group, members }) => {
    io.emit("room_added", { id, name, is_group, members });
  });

  // ----------------- Video Call -----------------
  socket.on("offer", ({ roomId, sdp }) => socket.to(roomId).emit("offer", { from: socket.id, sdp }));
  socket.on("answer", ({ roomId, sdp }) => socket.to(roomId).emit("answer", { from: socket.id, sdp }));
  socket.on("ice-candidate", ({ roomId, candidate }) => socket.to(roomId).emit("ice-candidate", { from: socket.id, candidate }));

  // ----------------- Disconnect -----------------
  socket.on("disconnect", async () => {
    const user = socket.data.user;
    if (user) {
      onlineUsers.delete(user.email);
      const lastSeen = new Date().toISOString();
      io.emit("user_offline", user.email, lastSeen);
      await supabase.from("users").update({ last_seen: lastSeen }).eq("email", user.email);
      console.log(`❌ ${user.name} disconnected`);
    }
  });
});

// ----------------- Admin CRUD -----------------
app.post("/admin/create-user", async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ msg: "Missing fields" });

    const password = Math.random().toString(36).slice(-8);
    const hashed = await bcrypt.hash(password, 10);

    const { data: authData, error: supaError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (supaError) return res.status(400).json({ msg: supaError.message });

    const { error: dbError } = await supabase
      .from("users")
      .insert([{ name, email, role: "member", password_hash: hashed }]);
    if (dbError) return res.status(400).json({ msg: dbError.message });

    // Send email via EmailJS
    await fetch("https://api.emailjs.com/api/v1.0/email/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service_id: process.env.EMAILJS_SERVICE_ID,
        template_id: process.env.EMAILJS_TEMPLATE_ID,
        public_key: process.env.EMAILJS_PUBLIC_KEY,
        private_key: process.env.EMAILJS_PRIVATE_KEY,
        template_params: {
          to_name: name,
          to_email: email,
          password,
          message: `Welcome ${name}! Your login email is ${email} and password is ${password}.`
        }
      }),
    });

    return res.json({ msg: "✅ User created successfully", name, email, password });
  } catch (err) {
    console.error("Create user error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

app.get("/admin/users", async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("id, name, email, role, created_at");
    if (error) return res.status(400).json({ error: error.message });
    return res.json(data);
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ msg: "Missing fields" });

    const { error } = await supabase.from("users").update({ name, email }).eq("id", id);
    if (error) return res.status(400).json({ msg: error.message });

    return res.json({ msg: "User updated" });
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

app.delete("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from("users").delete().eq("id", id);
    if (error) return res.status(400).json({ msg: error.message });
    return res.json({ msg: "User deleted" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// ----------------- Test Route -----------------
app.get("/", (req, res) => res.send("✅ Backend server running!"));

// ----------------- Start Server -----------------
const PORT = process.env.PORT || 5013;
server.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
