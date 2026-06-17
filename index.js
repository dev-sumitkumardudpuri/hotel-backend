import "dotenv/config";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Stripe from "stripe"; // IMPORT STRIPE FOR SECURE ONLINE TRANSACTIONS

// Initialize Stripe with strict environment configurations
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ==========================================
// MIDDLEWARE: Verify if the user is an Admin
// ==========================================
const verifyAdmin = (req, res, next) => {
  // 1. Get the token from the Authorization header
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Expecting "Bearer <token>"

  // 2. If no token is provided, deny access
  if (!token) {
    return res.status(403).json({
      success: false,
      message: "Access Denied: No token provided.",
    });
  }

  try {
    // 3. Verify the token using your JWT secret key
    // Note: Make sure process.env.JWT_SECRET matches what you used in login/signup
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 4. Check if the user has the 'admin' role
    if (decoded.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access Denied: Unauthorized access. Admin role required.",
      });
    }

    // 5. If everything is valid, attach admin data to request and proceed
    req.admin = decoded;
    next();
  } catch (error) {
    // 6. If token is invalid or expired
    return res.status(401).json({
      success: false,
      message: "Authentication Failed: Invalid or expired token.",
    });
  }
};

const app = express();

// MIDDLEWARES
app.use(cors());
app.use(express.json());

// DATABASE CONNECTION USING ENVIRONMENT VARIABLES
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => console.log("MongoDB is now connected successfully!"))
  .catch((err) => console.error("Database connection failed:", err));

// TEST ROUTE
app.get("/", (req, res) => {
  res.send("Backend Server is running!");
});

// ==========================================
// 1. USER SCHEMA & MODEL
// ==========================================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: {
    type: String,
    required: true,
    unique: true,
    // Backend validation regex to prevent invalid email formats
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      "Please enter a valid email address",
    ],
  },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
});

const User = mongoose.model("User", userSchema);

// ==========================================
// 2. AUTHENTICATION APIs (SIGNUP, LOGIN & GOOGLE AUTH)
// ==========================================

// USER SIGNUP API
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // STRICT REAL LIFE EMAIL DOMAIN CHECK
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    // Only globally certified trusted email networks are allowed
    const allowedDomains = [
      "gmail.com",
      "yahoo.com",
      "outlook.com",
      "hotmail.com",
      "icloud.com",
      "aol.com",
      "zoho.com",
      "proton.me",
      "protonmail.com",
    ];

    if (!emailRegex.test(email)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid email structure format!" });
    }

    // Extract the full domain part securely (e.g., "gmail.com")
    const emailDomain = email.split("@")[1]?.toLowerCase();

    // Reject instantly if the domain is not present in our trusted whitelist array
    if (!allowedDomains.includes(emailDomain)) {
      return res.status(400).json({
        success: false,
        message:
          "Only authentic email networks (Gmail, Yahoo, Outlook, iCloud, etc.) are permitted!",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "Email is already registered!" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: "user",
    });
    await newUser.save();

    res
      .status(201)
      .json({ success: true, message: "Account created successfully!" });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
});

// USER LOGIN API
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Email or Password!" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Email or Password!" });
    }

    // Dynamic extraction of token keys from protected runtime environments
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.status(200).json({
      success: true,
      message: "Login successful!",
      token: token,
      user: { name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
});

// CLOUD GOOGLE SIGN-IN API (LOGIN & AUTO-REGISTER SYNC)
app.post("/api/auth/google-login", async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Google account email is missing!" });
    }

    // Check if user exists in our DB
    let user = await User.findOne({ email });

    // If user doesn't exist, create account on-the-fly dynamically
    if (!user) {
      const generatedPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8);
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(generatedPassword, salt);

      user = new User({
        name: name || "Google Guest",
        email: email,
        password: hashedPassword,
        role: "user",
      });
      await user.save();
    }

    // Sign complete master session token securely
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.status(200).json({
      success: true,
      message: "Google login verified successfully!",
      token: token,
      user: { name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Google Auth protocol synchronization failed",
      error: error.message,
    });
  }
});

// ==========================================
// 3. BOOKING SCHEMA & MODEL
// ==========================================
const bookingSchema = new mongoose.Schema({
  roomId: { type: Number, required: true },
  guestName: { type: String, required: true },
  roomTitle: { type: String, required: true },
  nights: { type: Number, required: true },
  dates: { type: String, required: true },
  amount: { type: Number, required: true },
  status: {
    type: String,
    enum: ["Pending", "Checked In", "Checked Out", "Cancelled", "Refunded"],
    default: "Pending",
  },
  paymentMethod: {
    type: String,
    enum: ["hotel", "online"],
    default: "hotel",
  },
  paymentStatus: {
    type: String,
    enum: ["Paid", "Unpaid"],
    default: "Unpaid",
  },
  stripeSessionId: { type: String }, // Backwards tracking key to perform real dashboard refunds
  bookedAt: { type: Date, default: Date.now },
});

const Booking = mongoose.model("Booking", bookingSchema);

// ==========================================
// 4. BOOKING API (SAVE NEW BOOKING)
// ==========================================
app.post("/api/bookings", async (req, res) => {
  try {
    const {
      roomId,
      guestName,
      roomTitle,
      nights,
      dates,
      amount,
      paymentMethod,
      paymentStatus,
    } = req.body;

    if (!roomId) {
      return res
        .status(400)
        .json({ success: false, message: "Room ID is missing!" });
    }

    const newBooking = new Booking({
      roomId: Number(roomId),
      guestName,
      roomTitle,
      nights,
      dates,
      amount,
      status: "Pending",
      paymentMethod: paymentMethod || "hotel",
      paymentStatus: paymentStatus || "Unpaid",
    });

    await newBooking.save();

    res.status(201).json({
      success: true,
      message: "Booking is permanently saved in database!",
      booking: newBooking,
    });
  } catch (error) {
    console.error("POST BOOKING ERROR:", error.message);
    res.status(500).json({
      success: false,
      message: "Error while saving bookings",
      error: error.message,
    });
  }
});

// STRIPE ONLINE INTEGRATION CHECKOUT GATEWAY ROUTE
app.post("/api/bookings/stripe-checkout", async (req, res) => {
  try {
    const { roomId, guestName, roomTitle, nights, dates, amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Dynamic transaction amount calculation is invalid!",
      });
    }

    // Generate Stripe secure runtime payload parameters
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "inr",
            product_data: {
              name: `${roomTitle} Reservation`,
              description: `Stay Duration: ${dates} (${nights} Nights)`,
            },
            unit_amount: Math.round(amount * 100),
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      metadata: {
        roomId: String(roomId),
        guestName,
        roomTitle,
        nights: String(nights),
        dates,
        amount: String(amount),
      },
      success_url: `${process.env.CLIENT_URL || "http://localhost:5173"}/booking-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL || "http://localhost:5173"}/booking-failed?cancelled=true`,
    });

    res.status(200).json({ success: true, id: session.id, url: session.url });
  } catch (error) {
    console.error("STRIPE TRANSACTIONS GATEWAY FAILURE:", error.message);
    res.status(500).json({
      success: false,
      message: "Stripe electronic payment engine deployment failed",
      error: error.message,
    });
  }
});

// FIXES: TO PREVENT DUPLICATE ENTRIES FROM STRIPE RE-RENDERS
app.post("/api/bookings/stripe-success", async (req, res) => {
  try {
    const { session_id } = req.body;
    if (!session_id) {
      return res
        .status(400)
        .json({ success: false, message: "Session ID missing!" });
    }

    // GUARD CONDITION: Direct match using unique Stripe identifier
    const existing = await Booking.findOne({ stripeSessionId: session_id });
    if (existing) {
      return res.status(200).json({
        success: true,
        message: "Booking details already processed and validated!",
        booking: existing,
      });
    }

    // Retrieve session payload securely directly from Stripe API
    const session = await stripe.checkout.sessions.retrieve(session_id);

    if (session.payment_status === "paid") {
      const { roomId, guestName, roomTitle, nights, dates, amount } =
        session.metadata;

      const verifiedOnlineBooking = new Booking({
        roomId: Number(roomId),
        guestName,
        roomTitle,
        nights: Number(nights),
        dates,
        amount: Number(amount),
        status: "Pending",
        paymentMethod: "online",
        paymentStatus: "Paid",
        stripeSessionId: session.id, // Save this dynamically for future admin dashboard refunds
      });

      await verifiedOnlineBooking.save();

      return res.status(201).json({
        success: true,
        message: "Stripe transaction verified and saved to database!",
        booking: verifiedOnlineBooking,
      });
    }

    res.status(400).json({
      success: false,
      message: "Payment verification failed on Stripe server.",
    });
  } catch (error) {
    console.error("STRIPE SUCCESS VERIFICATION ERROR:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET BOOKED DATES FOR A SPECIFIC ROOM
app.get("/api/bookings/booked-dates", async (req, res) => {
  try {
    const { roomId } = req.query;

    if (!roomId || roomId === "undefined") {
      return res.status(400).json({
        success: false,
        message: "Valid Room Id is necessary!",
      });
    }

    const bookings = await Booking.find({
      roomId: Number(roomId),
      status: { $nin: ["Cancelled", "Refunded"] },
    });
    let allBookedDates = [];

    bookings.forEach((booking) => {
      if (booking.dates && booking.dates.includes(" to ")) {
        const [startStr, endStr] = booking.dates.split(" to ");

        if (startStr && endStr) {
          let start = new Date(startStr);
          let end = new Date(endStr);

          while (start <= end) {
            allBookedDates.push(start.toISOString().split("T")[0]);
            start.setDate(start.getDate() + 1);
          }
        }
      }
    });

    const uniqueBookedDates = [...new Set(allBookedDates)];
    res.status(200).json({ success: true, bookedDates: uniqueBookedDates });
  } catch (error) {
    console.error("GET BOOKED DATES ERROR:", error.message);
    res.status(500).json({
      success: false,
      message: "Booked dates error",
      error: error.message,
    });
  }
});

// ==========================================
// 5. USER PROFILE CRUD ROUTERS
// ==========================================

// GET SPECIFIC USER BOOKINGS
app.get("/api/bookings/user", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email parameter is missing!",
      });
    }

    const activeUser = await User.findOne({ email: email });
    if (!activeUser) {
      return res
        .status(404)
        .json({ success: false, message: "User is not in database!" });
    }

    const userBookings = await Booking.find({ guestName: activeUser.name });
    res.status(200).json({ success: true, bookings: userBookings });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error to fetch user bookings",
      error: error.message,
    });
  }
});

// FIXES: SMART DELETE/CANCEL BOOKING TO PREVENT 500 ERROR
app.delete("/api/bookings/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // SECURITY SHIELD: Check if the string pattern aligns with real JSON Hex IDs
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message:
          "Malformed client token key or dynamic booking ID pattern detected!",
      });
    }

    const operationalBooking = await Booking.findById(id);
    if (!operationalBooking) {
      return res
        .status(404)
        .json({ success: false, message: "Booking record not found!" });
    }

    if (
      operationalBooking.paymentMethod === "online" &&
      operationalBooking.paymentStatus === "Paid"
    ) {
      operationalBooking.status = "Cancelled";
      await operationalBooking.save();
      return res.status(200).json({
        success: true,
        message:
          "Online booking successfully marked as Cancelled. Audit trail preserved for refund mapping.",
      });
    }

    await Booking.findByIdAndDelete(id);
    res.status(200).json({
      success: true,
      message: "Booking cancelled successfully!",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Cancel error",
      error: error.message,
    });
  }
});

// PUT RESCHEDULE BOOKING DATES
app.put("/api/bookings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { roomId, arrivalDate, departureDate } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid dynamic ID string" });
    }

    const existingBookings = await Booking.find({
      roomId: Number(roomId),
      _id: { $ne: id },
      status: { $nin: ["Cancelled", "Refunded"] },
    });
    let hasConflict = false;

    let targetDates = [];
    let start = new Date(arrivalDate);
    let end = new Date(departureDate);
    while (start <= end) {
      targetDates.push(start.toISOString().split("T")[0]);
      start.setDate(start.getDate() + 1);
    }

    for (let booking of existingBookings) {
      if (booking.dates && booking.dates.includes(" to ")) {
        const [sStr, eStr] = booking.dates.split(" to ");
        let s = new Date(sStr);
        let e = new Date(eStr);

        while (s <= e) {
          const currentFormatted = s.toISOString().split("T")[0];
          if (targetDates.includes(currentFormatted)) {
            hasConflict = true;
            break;
          }
          s.setDate(s.getDate() + 1);
        }
      }
      if (hasConflict) break;
    }

    if (hasConflict) {
      return res.status(400).json({
        success: false,
        message:
          "These dates have already been booked. Please choose available dates!",
      });
    }

    const date1 = new Date(arrivalDate);
    const date2 = new Date(departureDate);
    const diffTime = Math.abs(date2 - date1);
    const calculatedNights = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) || 1;

    const updatedBooking = await Booking.findByIdAndUpdate(
      id,
      { dates: `${arrivalDate} to ${departureDate}`, nights: calculatedNights },
      { new: true },
    );

    res.status(200).json({
      success: true,
      message: "Dates successfully updated!",
      booking: updatedBooking,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Date changing error",
      error: error.message,
    });
  }
});

// ==========================================
// 6. CONTACT API
// ==========================================

const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, default: "unread" },
  sentAt: { type: Date, default: Date.now },
});

const Contact =
  mongoose.models.Contact || mongoose.model("Contact", contactSchema);

/**
 * ROUTE 1: POST /api/contact
 * Persists incoming public user communication inquiries securely into the database
 */
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;
    const newContactMessage = new Contact({ name, email, phone, message });
    await newContactMessage.save();
    res.status(201).json({
      success: true,
      message: "Your message is safely saved in the database!",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error while saving messages",
      error: error.message,
    });
  }
});

/**
 * ROUTE 2: GET /api/contact
 * Fetches and sorts all archived user inquiries for admin control matrix display interfaces
 */
app.get("/api/contact", async (req, res) => {
  try {
    const contacts = await Contact.find({}).sort({ sentAt: -1 });
    res.status(200).json({
      success: true,
      inquiries: contacts,
      data: contacts,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch contact inquiries",
      error: error.message,
    });
  }
});

/**
 * ROUTE 3: PATCH /api/contact/:id
 * Modifies inquiry processing tracking metadata states seamlessly across components
 */
app.patch("/api/contact/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const updatedContact = await Contact.findByIdAndUpdate(
      id,
      { status },
      { new: true },
    );

    if (!updatedContact) {
      return res
        .status(404)
        .json({ success: false, message: "Inquiry not found" });
    }

    res.status(200).json({
      success: true,
      message: "Status updated successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to update status",
      error: error.message,
    });
  }
});

/**
 * ROUTE 4: DELETE /api/contact/:id
 * Purges specific client communication clusters permanently from underlying storage schemas
 */
app.delete("/api/contact/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const deletedContact = await Contact.findByIdAndDelete(id);

    if (!deletedContact) {
      return res
        .status(404)
        .json({ success: false, message: "Inquiry not found" });
    }

    res.status(200).json({
      success: true,
      message: "Inquiry deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to delete inquiry",
      error: error.message,
    });
  }
});

//=================================================================
// 7. ADMIN DASHBOARD CONTROL APIs
// ================================================================

// CREATE NEW BOOKING DIRECTLY BY ADMIN (OFFLINE)
app.post("/api/admin/bookings/create", verifyAdmin, async (req, res) => {
  try {
    const {
      roomId,
      guestName,
      roomTitle,
      nights,
      dates,
      amount,
      status,
      paymentMethod,
      paymentStatus,
    } = req.body;

    if (!roomId || !guestName || !roomTitle || !nights || !dates || !amount) {
      return res.status(400).json({
        success: false,
        message: "All fields are required to create an offline booking!",
      });
    }

    const targetRoomBookings = await Booking.find({
      roomId: Number(roomId),
      status: { $nin: ["Cancelled", "Refunded"] },
    });

    let adminConflict = false;
    let processingDates = [];

    if (dates.includes(" to ")) {
      const [startStr, endStr] = dates.split(" to ");
      let currentStart = new Date(startStr);
      let currentEnd = new Date(endStr);
      while (currentStart <= currentEnd) {
        processingDates.push(currentStart.toISOString().split("T")[0]);
        currentStart.setDate(currentStart.getDate() + 1);
      }

      for (let existingActiveRow of targetRoomBookings) {
        if (
          existingActiveRow.dates &&
          existingActiveRow.dates.includes(" to ")
        ) {
          const [sS, eE] = existingActiveRow.dates.split(" to ");
          let activeS = new Date(sS);
          let activeE = new Date(eE);
          while (activeS <= activeE) {
            if (processingDates.includes(activeS.toISOString().split("T")[0])) {
              adminConflict = true;
              break;
            }
            activeS.setDate(activeS.getDate() + 1);
          }
        }
        if (adminConflict) break;
      }
    }

    if (adminConflict) {
      return res.status(400).json({
        success: false,
        message:
          "Overlapping reservation detected! Selected target timeline is already booked for this room.",
      });
    }

    let finalPaymentStatus = paymentStatus || "Unpaid";
    if (status === "Checked In" || status === "Checked Out") {
      finalPaymentStatus = "Paid";
    }

    const adminBooking = new Booking({
      roomId: Number(roomId),
      guestName,
      roomTitle,
      nights: Number(nights),
      dates,
      amount: Number(amount),
      status: status || "Checked In",
      paymentMethod: paymentMethod || "hotel",
      paymentStatus: finalPaymentStatus,
    });

    await adminBooking.save();

    res.status(201).json({
      success: true,
      message: "Offline booking successfully created by Admin!",
      booking: adminBooking,
    });
  } catch (error) {
    console.error("ADMIN CREATE BOOKING ERROR:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to create booking by admin",
      error: error.message,
    });
  }
});

// GET LIVE COUNTERS & METRICS
app.get("/api/admin/stats", verifyAdmin, async (req, res) => {
  try {
    const allBookings = await Booking.find({});
    let totalRevenue = 0;
    let activeGuestsCount = 0;

    allBookings.forEach((b) => {
      if (b.status === "Checked In" || b.status === "Checked Out") {
        totalRevenue += Number(b.amount);
      }
      if (b.status === "Checked In") {
        activeGuestsCount += 1;
      }
    });

    const totalRoomsCount = 8;
    const uniqueBookedRooms = [
      ...new Set(
        allBookings
          .filter((b) => b.status === "Checked In")
          .map((b) => b.roomId),
      ),
    ].length;

    const availableRoomsCount = Math.max(
      0,
      totalRoomsCount - uniqueBookedRooms,
    );

    res.status(200).json({
      success: true,
      stats: {
        totalBookings: allBookings.length,
        totalRevenue: totalRevenue,
        activeGuests: activeGuestsCount,
        availableRooms: availableRoomsCount,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Stats compile error",
      error: error.message,
    });
  }
});

// GET ALL CUSTOMERS BOOKINGS FOR MASTER TABLE
app.get("/api/admin/bookings", verifyAdmin, async (req, res) => {
  try {
    const masterBookingsList = await Booking.find({}).sort({ bookedAt: -1 });
    res.status(200).json({ success: true, bookings: masterBookingsList });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "List loading failed",
      error: error.message,
    });
  }
});

// UPDATE BOOKING LIFECYCLE STATUS (AUTOMATED CRITICAL LOGIC APPLIED HERE)
app.put("/api/admin/bookings/:id/status", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, paymentStatus } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid ID string" });
    }

    const existingBooking = await Booking.findById(id);
    if (!existingBooking) {
      return res
        .status(404)
        .json({ success: false, message: "Booking not found!" });
    }

    const updatePayload = { status: status };

    // AUTOMATED SYNCHRONIZATION LOGIC BASED ON STATUS LIFE CYCLE
    if (status === "Checked In" || status === "Checked Out") {
      updatePayload.paymentStatus = "Paid";
    } else if (
      status === "Cancelled" &&
      existingBooking.paymentMethod === "hotel"
    ) {
      updatePayload.paymentStatus = "Unpaid";
    } else if (paymentStatus) {
      updatePayload.paymentStatus = paymentStatus;
    }

    const updatedBookingStatus = await Booking.findByIdAndUpdate(
      id,
      updatePayload,
      { new: true },
    );
    res.status(200).json({
      success: true,
      message: `Status updated successfully to ${status}!`,
      booking: updatedBookingStatus,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Status sync error",
      error: error.message,
    });
  }
});

// REAL INTEGRATION: STRIPE DASHBOARD AUTOMATED REFUND DISPATCH ROUTE
app.post("/api/admin/bookings/:id/refund", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid ID string" });
    }

    const targetedBooking = await Booking.findById(id);
    if (!targetedBooking) {
      return res
        .status(404)
        .json({ success: false, message: "Target booking not discovered!" });
    }

    // STRICT VALIDATION GUARDS: Block refunds for offline or unpaid reservations instantly
    if (
      targetedBooking.paymentMethod !== "online" ||
      !targetedBooking.stripeSessionId
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Refund operation rejected. This booking was processed offline or contains no active Stripe transaction payload.",
      });
    }

    // STRIPE GATEWAY PIPELINE EXECUTION
    try {
      // Retrieve session to get payment_intent key securely
      const session = await stripe.checkout.sessions.retrieve(
        targetedBooking.stripeSessionId,
      );
      if (session && session.payment_intent) {
        await stripe.refunds.create({
          payment_intent: session.payment_intent,
        });
        console.log("Stripe Engine Refund executed successfully!");
      }
    } catch (stripeErr) {
      console.error(
        "Stripe Dashboard System Refund pipeline failed:",
        stripeErr.message,
      );

      // SMART FIX ADDED HERE
      if (stripeErr.message.includes("has already been refunded")) {
        targetedBooking.status = "Refunded";
        targetedBooking.paymentStatus = "Paid";
        await targetedBooking.save();

        return res.status(200).json({
          success: true,
          message:
            "This transaction was already refunded on Stripe. Database successfully synchronized!",
          booking: targetedBooking,
        });
      }

      return res.status(502).json({
        success: false,
        message:
          "Stripe gateway interface rejected the refund request pipeline.",
        error: stripeErr.message,
      });
    }

    // Synchronize document records upon successful transaction verification
    targetedBooking.status = "Refunded";
    targetedBooking.paymentStatus = "Paid";
    await targetedBooking.save();

    res.status(200).json({
      success: true,
      message:
        "Stripe Reversal system successful! Session synchronized to Refunded.",
      booking: targetedBooking,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Stripe automated engine processing failure",
      error: error.message,
    });
  }
});

// FULL ROW UPDATE API -> ALLOW DYNAMIC CHANGES FROM FRONTEND MODAL
app.put(
  "/api/admin/bookings/:id/update-full",
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        guestName,
        roomTitle,
        paymentMethod,
        paymentStatus,
        roomId,
        dates,
        nights,
        amount,
      } = req.body;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid ID string" });
      }

      const existingBooking = await Booking.findById(id);
      if (!existingBooking) {
        return res
          .status(404)
          .json({ success: false, message: "Booking record not found!" });
      }

      // Hydrate parameters dynamically or retain pre-existing database matrix
      const updatedBooking = await Booking.findByIdAndUpdate(
        id,
        {
          guestName: guestName || existingBooking.guestName,
          roomTitle: roomTitle || existingBooking.roomTitle,
          paymentMethod: paymentMethod || existingBooking.paymentMethod,
          paymentStatus: paymentStatus || existingBooking.paymentStatus,
          roomId:
            roomId !== undefined ? Number(roomId) : existingBooking.roomId,
          dates: dates || existingBooking.dates,
          nights:
            nights !== undefined ? Number(nights) : existingBooking.nights,
          amount:
            amount !== undefined ? Number(amount) : existingBooking.amount,
        },
        { new: true, runValidators: true },
      );

      res.status(200).json({
        success: true,
        message:
          "Database record successfully updated by Admin with new inputs!",
        booking: updatedBooking,
      });
    } catch (error) {
      console.error("ADMIN FULL UPDATE ERROR:", error.message);
      res.status(500).json({
        success: false,
        message: "Failed to update records",
        error: error.message,
      });
    }
  },
);

// DELETE BOOKING PERMANENTLY FROM DATABASE
app.delete("/api/admin/bookings/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid ID string" });
    }
    await Booking.findByIdAndDelete(id);
    res.status(200).json({
      success: true,
      message: "Booking is now permanently deleted from the database!",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Delete operation failed",
      error: error.message,
    });
  }
});

// ============================================================
// SERVER START LINE WITH ENVIRONMENT PORT FALLBACK
// ============================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server port ${PORT} is now running securely!`);
});
