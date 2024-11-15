// Required Modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const bodyParser = require('body-parser');
const http = require("http");
const { Server } = require("socket.io");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const genAI = new GoogleGenerativeAI("AIzaSyAl-k30fenpNfcnkl1mmCeYRJzvALGH0Gk");
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
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
const personalInfoSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  middleName: { type: String },
  lastName: { type: String, required: true },
  age: { type: Number, required: true },
  bloodGroup: { type: String, required: true },
  flatNo: { type: String, required: true },
  area: { type: String, required: true },
  landmark: { type: String },
  pincode: { type: String, required: true },
  city: { type: String, required: true },
  email: { type: String, required: true },
  insuranceNumber: { type: String },
  height: { type: Number },
  heightUnit: { type: String, enum: ['cm', 'feet'] },
  weight: { type: Number },
  weightUnit: { type: String, enum: ['kg', 'lb'] },
  allergies: { type: String },
  medication: { type: String },
  createdAt: { type: Date, default: Date.now }
});


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
  ],
  hostedEvents: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }],
  
  // Add personalInfo as a subdocument
  personalInfo: personalInfoSchema
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
    origin: "*",
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

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET);

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

      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
      return res.status(200).json({ message: 'Login successful', token });
    }

    if (mobileNumber) {
      const user = await User.findOne({ mobileNumber });
      if (!user) return res.status(404).json({ message: 'User not found' });

      const isValidPin = await user.comparePin(pin);
      if (!isValidPin) return res.status(401).json({ message: 'Invalid credentials' });

      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
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

app.get('/gethist', verifyToken, async (req, res) => {
  const { _id } = req.query;

  console.log(_id);
  try {
    const historyData = await Crisis.find({ _id });
    if (!historyData.length) {
      return res.status(404).json({ message: "No documents found" });
    }
    res.json(historyData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
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

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  location: { type: String, required: true },
  skillsRequired: { type: String },
  volunteers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User ' }],
  host: { type: mongoose.Schema.Types.ObjectId, ref: 'User ', required: true } // Add host field
});

const Event = mongoose.model('Event', eventSchema);

app.get("/events", async (req, res) => {
  try {
    const events = await Event.find({});
    res.status(200).json(events);
  } catch (error) {
    console.error("Error fetching events:", error);
    res.status(500).json({ message: "Error fetching events" });
  }
});

// Create a new event
app.post('/create', verifyToken, async (req, res) => {
  const { title, description, date, location, skillsRequired } = req.body;
  const userId = req.userId; // Get userId from the request object

  try {
    const newEvent = new Event({
      title,
      description,
      date,
      location,
      skillsRequired,
      volunteers: [],
      host: userId // Set the host to the current user's ID
    });

    await newEvent.save();

    // Update the user to include this event in their hostedEvents
    await User.findByIdAndUpdate(userId, { $push: { hostedEvents: newEvent._id } });

    res.status(201).json({ message: 'Event created successfully', event: newEvent });
  } catch (error) {
    console.error('Error creating event:', error);
    res.status(500).json({ message: 'Error creating event', error });
  }
});

// Volunteer for an event
app.post('/:eventId/volunteer', async (req, res) => {
  const { eventId } = req.params;
  const userId = req.userId; // Get userId from the request object
  console.log(userId);

  try {
    const event = await Event.findById(eventId);
    if (!event) return res.status(404).json({ message: 'Event not found' });

    if (!event.volunteers.includes(userId)) {
      event.volunteers.push(userId);
      await event.save();
    }

    res.json({ message: 'User  added as volunteer', event });
  } catch (error) {
    console.error('Error volunteering for event:', error);
    res.status(500).json({ message: 'Error volunteering for event', error });
  }
});

// Route to get hosted events for the authenticated user
app.get('/hosted-events', verifyToken, async (req, res) => {
  try {
    // Find the user by ID and populate hosted events
    const user = await User.findById(req.userId).populate('hostedEvents');
    if (!user) {
      return res.status(404).json({ message: 'User  not found' });
    }
    res.status(200).json(user.hostedEvents); // Return the hosted events
  } catch (error) {
    console.error("Error fetching hosted events:", error);
    res.status(500).json({ message: "Error fetching hosted events" });
  }
});

app.post('/userevents' ,async (req, res) => {
  const userId = req.body.userId; // No need to check if userId is present here

  try {
      // Fetch events where the user is a volunteer
      const userEvents = await Event.find({ volunteers: userId });

      if (userEvents.length === 0) {
          return res.status(404).json({ message: "No events found for this user." });
      }

      return res.status(200).json(userEvents);
  } catch (error) {
      console.error('Error fetching events:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Route to delete an event
app.delete('/events/:eventId', verifyToken, async (req, res) => {
  const { eventId } = req.params;

  try {
    // Find the event and delete it
    const event = await Event.findByIdAndDelete(eventId);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(200).json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error("Error deleting event:", error);
    res.status(500).json({ message: "Error deleting event" });
  }
});

// Add/Update Personal Information Route
app.post('/personal-info', verifyToken, async (req, res) => {
  try {
      const userId = req.userId;
      const personalInfoData = req.body;

      // Find the user and update their personal information
      const updatedUser = await User.findByIdAndUpdate(
          userId, 
          { personalInfo: personalInfoData }, 
          { new: true, upsert: true }
      );

      res.status(200).json({
          message: 'Personal Information updated successfully',
          personalInfo: updatedUser.personalInfo
      });
  } catch (error) {
      console.error('Error updating personal info:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});

// Get Personal Information Route
app.get('/personal-info', verifyToken, async (req, res) => {
  try {
      const userId = req.userId;
      const user = await User.findById(userId);

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      res.status(200).json({
          personalInfo: user.personalInfo || null
      });
  } catch (error) {
      console.error('Error fetching personal info:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/news', async (req, res) => {
  try {
    const response = await axios.get('https://newsapi.org/v2/everything', {
      params: {
        q: '"India" AND ("disaster management" OR "natural disaster" OR "emergency response" OR "disaster relief" OR "crisis management")',
        language: 'en',
        sortBy: 'publishedAt',
        apiKey: '1ee17a07805e4ab8b52f359a44e4e026',
      },
    });
    res.json(response.data);
  } catch (error) {
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

app.delete('/personal-info/delete',verifyToken, async (req, res) => {
  const userId = req.userId; // assuming user authentication middleware provides the user ID
  try {
      await User.updateOne({ _id: userId }, { $unset: { personalInfo: "" } });
      res.status(200).send({ message: "Personal info deleted successfully" });
  } catch (error) {
      res.status(500).send({ message: "Error deleting personal info", error });
  }
});

app.post('/personal-info/update', verifyToken, async (req, res) => {
  try {
      const userId = req.userId;
      const personalInfoData = req.body;

      // Update personal info
      const updatedUser = await User.findByIdAndUpdate(
          userId, 
          { personalInfo: personalInfoData }, 
          { new: true, upsert: true }
      );

      res.status(200).json({
          message: 'Personal Information updated successfully',
          personalInfo: updatedUser.personalInfo
      });
  } catch (error) {
      console.error('Error updating personal info:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});

app.post("/chatbot", async (req, res) => {
  try {
    const userMessage = req.body.message;

    // Define the system message: guide the model to stay within safety and security context
    const systemMessage = `
      You are a safety and security assistant. Provide only general advice related to safety, security, and self-help in a crisis. 
      Limit your response to 5-6 sentences and focus on how the user can help themselves until help arrives.Also provide information relevent in INDIA and not any other countries.
    `;

    // Combine the system message and the user's message
    const prompt = `${systemMessage}\nUser: ${userMessage}\nAssistant:`;

    // Generate content using the Gemini model
    const result = await model.generateContent(prompt);

    // Handle response
    res.json({ reply: result.response.text() });
  } catch (error) {
    console.error("Error during chatbot request:", error);
    res.status(500).send("Error communicating with chatbot");
  }
});


// Start Server with HTTP and WebSocket (Socket.io) support
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
