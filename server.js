// Required Modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const http = require("http");
const { Server } = require("socket.io");
require('dotenv').config();

// Initialize Express App
const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.json());

// Setup Cloudinary
const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API,
  api_secret: process.env.CLOUDINARY_SECRET
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema & Model
const userSchema = new mongoose.Schema({
  fullName: String,
  dob: {
    day: String,
    month: String,
    year: String
  },
  gender: String,
  mobileNumber: String,
  email: { type: String, unique: true },
  pin: String,
  emergencyContacts: [
    {
      fullName: String,
      relation: String,
      contactNumber: String,
    }
  ]
});

// Pre-save hook for password hashing
userSchema.pre('save', async function (next) {
  if (!this.isModified('pin')) return next();
  const salt = await bcrypt.genSalt(10);
  this.pin = await bcrypt.hash(this.pin, salt);
  next();
});

// Password comparison method
userSchema.methods.comparePin = async function (inputPin) {
  return await bcrypt.compare(inputPin, this.pin);
};

const User = mongoose.model('User', userSchema);

// Create HTTP Server and Socket.io Instance
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Real-time chat message handling
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  // Handle incoming chat messages
  socket.on("chat message", (data) => {
    const { name, message } = data;
    console.log("Message received from:", name, "Message:", message);

    // Emit message to all clients, including the sender
    io.emit("chat message", { name, message });
  });

  // Handle disconnection
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});


// Signup Route
app.post('/signup', async (req, res) => {
  try {
    const { fullName, dob, gender, mobileNumber, email, pin } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const newUser = new User({ fullName, dob, gender, mobileNumber, email, pin });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '9h' });

    res.status(201).json({ message: 'User created successfully', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  try {
    const { email, mobileNumber, pin, otp } = req.body;

    if (email) {
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: 'User not found' });

      const isValidPin = await user.comparePin(pin);
      if (!isValidPin) return res.status(401).json({ message: 'Invalid credentials' });

      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '9h' });
      return res.status(200).json({ message: 'Login successful', token });
    }

    if (mobileNumber) {
      const user = await User.findOne({ mobileNumber });
      if (!user) return res.status(404).json({ message: 'User not found' });

      const isValidOtp = otp === '123456'; // Simulated OTP verification
      if (!isValidOtp) return res.status(401).json({ message: 'Invalid OTP' });

      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '9h' });
      return res.status(200).json({ message: 'Login successful', token });
    }

    return res.status(400).json({ message: 'Invalid login method' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// JWT Token Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error("JWT verification failed:", error);
    return res.status(403).json({ message: 'Failed to authenticate token' });
  }
};


// User Profile Route
app.get('/api/user/account', verifyToken, async (req, res) => {
  try {
      const userId = req.userId; // Extracted from the JWT token by verifyToken middleware
      const user = await User.findById(userId) // Fetch user data except for the pin/password
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
  } catch (error) {
      res.status(500).json({ message: 'Internal server error' });
  }
});

// Update Password Route (Node.js example)
app.put('/api/user/update-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.userId; // Assuming you have a middleware to extract the user's ID from the token

  try {
      const user = await User.findById(userId);
      console.log("userfound")
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Compare current password
      const isMatch = await bcrypt.compare(currentPassword, user.pin);
      if (!isMatch) {
          return res.status(400).json({ message: 'Incorrect current password' });
      }

      // Hash the new password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
      await user.save();

      res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
  }
});

// Nominee Management
app.post('/nominee', verifyToken, async (req, res) => {
  try {
    const { fullName, relation, contactNumber } = req.body;
    const userId = req.userId;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const newContact = { fullName, relation, contactNumber };
    user.emergencyContacts.push(newContact);

    await user.save();

    res.status(201).json({ message: 'Emergency contact added successfully', emergencyContacts: user.emergencyContacts });
  } catch (error) {
    console.error('Error adding nominee:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Crisis Schema & Model
const crisisSchema = new mongoose.Schema({
  desc: String,
  fullName: String,
  time: String,
  date: String,
  cords: [Number]
});
const Crisis = mongoose.model('Crisis', crisisSchema);

// Crisis Reporting Route
app.post("/crisis", async (req, res) => {
  try {
    const { desc, fullName, time, date, cords } = req.body;
    if (!cords || cords.length !== 2) {
      return res.status(400).json({ message: "Coordinates must be an array of two numbers [longitude, latitude]" });
    }
    const newCrisis = new Crisis({ desc, fullName, time, date, cords });
    await newCrisis.save();
    res.status(201).json({ message: "Crisis saved successfully", crisis: newCrisis });
  } catch (error) {
    console.error("Error saving crisis:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Fetch All Crises
app.get("/crises", async (req, res) => {
  try {
    const crises = await Crisis.find({});
    res.status(200).json(crises);
  } catch (error) {
    console.error("Error fetching crises:", error);
    res.status(500).json({ message: "Error fetching crises" });
  }
});

// Start Server with HTTP and WebSocket (Socket.io) support
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
