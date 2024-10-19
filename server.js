//this is the backend server
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();
const app = express();
app.use(cors());
const PORT = process.env.PORT || 5000;

// Cloudinary Configuration
const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API,
  api_secret: process.env.CLOUDINARY_SECRET
});

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));
  
  // Define User Schema
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
  });
  
  // Pre-save hook for password hashing
  userSchema.pre('save', async function (next) {
    try {
      if (!this.isModified('pin')) return next(); // Use 'pin' for password hashing
      const salt = await bcrypt.genSalt(10);
      this.pin = await bcrypt.hash(this.pin, salt); // Hash the pin
      next();
    } catch (error) {
      next(error);
    }
  });
  
  // Method to compare the pin
  userSchema.methods.comparePin = async function (inputPin) {
    return await bcrypt.compare(inputPin, this.pin); // Compare hashed pin
  };
  
  const User = mongoose.model('User', userSchema);
  
  // Signup Route
  app.post('/signup', async (req, res) => {
    try {
      const { fullName, dob, gender, mobileNumber, email, pin } = req.body;
  
      // Check if the user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already in use' });
      }
  
      // Create new user instance
      const newUser = new User({ fullName, dob, gender, mobileNumber, email, pin });
      await newUser.save();
  
      // Generate JWT token
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
      console.log(email, mobileNumber, pin, otp )
  
      // Handle login via email and pin
      if (email) {
        const user = await User.findOne({ email });
        console.log("user found");
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }
  
        const isValidPin = await user.comparePin(pin); // Compare the pin using the comparePin method
        if (!isValidPin) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }
  
        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '9h' });
        return res.status(200).json({ message: 'Login successful', token });
      }
  
      // Handle login via mobile number and OTP
      if (mobileNumber) {
        const user = await User.findOne({ mobileNumber });
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }
  
        // Simulate OTP verification. Replace with actual OTP verification logic.
        const isValidOtp = otp === '123456'; // Assuming a mock OTP of 123456
        if (!isValidOtp) {
          return res.status(401).json({ message: 'Invalid OTP' });
        }
  
        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '9h' });
        return res.status(200).json({ message: 'Login successful', token });
      }
  
      // If neither email nor mobileNumber is provided
      return res.status(400).json({ message: 'Invalid login method' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // Middleware to verify JWT token
  const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    try {
      const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
      req.userId = decoded.userId;
      next();
    } catch (error) {
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


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
