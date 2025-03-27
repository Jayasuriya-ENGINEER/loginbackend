require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json()); // Parse JSON data from request body

// MongoDB Atlas connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("Error connecting to MongoDB Atlas:", err));

// Defining the user schema
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    aadhaar_number: { type: String, required: true, unique: true },
    mcp_card_number: { type: String, required: true },
    mobile_number: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

// Creating the user model
const User = mongoose.model("User", userSchema);

// Sign-Up route
app.post("/signup", async (req, res) => {
  const {
    name,
    aadhaar_number,
    mcp_card_number,
    mobile_number,
    email,
    password,
    confirm_password,
  } = req.body;

  // Validate password match
  if (password !== confirm_password) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  try {
    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      aadhaar_number,
      mcp_card_number,
      mobile_number,
      email,
      password: hashedPassword, // Store hashed password
    });

    await newUser.save();
    res.status(201).json({ message: "User signed up successfully" });
  } catch (err) {
    console.error("Error during sign-up:", err);
    res.status(500).json({ message: "Error signing up. Please try again." });
  }
});

// Login route with JWT authentication
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid credentials" });

    // Generate a JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Error logging in. Please try again." });
  }
});

// Protected route example (Requires JWT)
app.get("/profile", async (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "Access denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password"); // Exclude password field
    res.status(200).json(user);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Start the server
const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
  console.log(`Backend server is running on http://localhost:${PORT}`);
});
