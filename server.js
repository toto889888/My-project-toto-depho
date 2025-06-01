require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public'));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/travel-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  phone: String,
  password: String,
  country: String,
  receiveNews: Boolean,
  resetToken: String,
  resetTokenExpiry: Date,
});
const User = mongoose.model('User', userSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Registration Endpoint
app.post('/api/register', async (req, res) => {
  console.log('Received registration data:', req.body);
  const { firstName, lastName, email, phone, password, confirmPassword, country, receiveNews, terms } = req.body;

  if (!firstName || !lastName || !email || !phone || !password || !confirmPassword || !country) {
    return res.status(400).json({ 
      message: 'กรุณากรอกข้อมูลให้ครบทุกช่องที่จำเป็น',
      missing_fields: {
        firstName: !firstName,
        lastName: !lastName,
        email: !email,
        phone: !phone,
        password: !password,
        confirmPassword: !confirmPassword,
        country: !country
      }
    });
  }

  if (!terms) {
    return res.status(400).json({ message: 'กรุณายอมรับเงื่อนไขการใช้งาน' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'รหัสผ่านไม่ตรงกัน' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      if (existingUser.email === email) return res.status(400).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });
      if (existingUser.phone === phone) return res.status(400).json({ message: 'เบอร์โทรนี้ถูกใช้งานแล้ว' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.toLowerCase().trim(),
      phone: phone.trim(),
      password: hashedPassword,
      country: country,
      receiveNews: receiveNews === true || receiveNews === 'true',
    });
    await user.save();

    console.log('User created successfully:', { id: user._id, email: user.email, firstName: user.firstName });
    res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ!', success: true });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(400).json({ message: `${field === 'email' ? 'อีเมล' : 'เบอร์โทร'}นี้ถูกใช้งานแล้ว` });
    }
    res.status(500).json({ message: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์' });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { emailOrPhone, password, rememberMe } = req.body;

  if (!emailOrPhone || !password) {
    return res.status(400).json({ message: 'Please provide email/phone and password' });
  }

  try {
    const user = await User.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    res.status(200).json({ message: 'Login successful', user: { firstName: user.firstName, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Forgot Password Endpoint
app.post('/api/request-reset', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'ไม่พบอีเมลนี้ในระบบ' });

    const token = jwt.sign({ email }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
    user.resetToken = token;
    user.resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour expiry
    await user.save();

    const resetLink = `http://localhost:3000/update_password.html?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'รีเซ็ตรหัสผ่าน',
      html: `<p>คลิกลิงก์นี้เพื่อรีเซ็ตรหัสผ่าน: <a href="${resetLink}">${resetLink}</a></p><p>ลิงก์นี้จะหมดอายุใน 1 ชั่วโมง</p>`
    });

    res.status(200).json({ message: 'ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลของคุณแล้ว' });
  } catch (error) {
    console.error('Error sending reset email:', error);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการส่งอีเมล' });
  }
});

// Reset Password Endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'กรุณาระบุ token และรหัสผ่านใหม่' });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({ message: 'รหัสผ่านไม่ตรงตามเงื่อนไข' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decoded.email, resetToken: token, resetTokenExpiry: { $gt: new Date() } });
    if (!user) {
      return res.status(400).json({ message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.status(200).json({ message: 'รีเซ็ตรหัสผ่านสำเร็จ' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการรีเซ็ตรหัสผ่าน' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));