require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const twilio = require('twilio');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------- DB ----------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB OK'))
  .catch(e => console.error(e));

// ---------- Models ----------
const UserSchema = new mongoose.Schema({
  name: String, email: String, mobile: String, password: String,
  isNewUser: { type: Boolean, default: true },
  purchases: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Purchase' }]
});
const User = mongoose.model('User', UserSchema);

const PurchaseSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: [{ bookId: Number, qty: Number, price: Number, title: String }],
  total: Number, paymentId: String, address: String,
  date: { type: Date, default: Date.now }
});
const Purchase = mongoose.model('Purchase', PurchaseSchema);

// ---------- File upload ----------
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, file.fieldname + '.pdf')
});
const upload = multer({ storage });

// ---------- Twilio ----------
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);

// ---------- Nodemailer ----------
const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ---------- Razorpay ----------
const rzp = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ---------- Auth Middleware ----------
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) { res.status(401).json({ error: 'Bad token' }); }
};

/* ---------- ROUTES ---------- */

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, mobile, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ name, email, mobile, password: hashed });
  await user.save();
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, isNewUser: true });
});

// Login
app.post('/api/login', async (req, res) => {
  const { id, password } = req.body;
  const user = await User.findOne({ $or: [{ email: id }, { mobile: id }] });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, isNewUser: user.isNewUser });
});

/* ---- OTP ---- */
let otpStore = {};   // replace with Redis for production
app.post('/api/send-otp', async (req, res) => {
  const { mobile } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[mobile] = { otp, expires: Date.now() + 5 * 60 * 1000 };
  await twilioClient.messages.create({
    body: `ShyamBooks OTP: ${otp}`,
    from: process.env.TWILIO_PHONE,
    to: mobile
  });
  res.json({ msg: 'sent' });
});

app.post('/api/verify-otp', async (req, res) => {
  const { mobile, otp } = req.body;
  const rec = otpStore[mobile];
  if (!rec || rec.expires < Date.now() || rec.otp !== otp)
    return res.status(400).json({ error: 'Invalid OTP' });
  delete otpStore[mobile];
  let user = await User.findOne({ mobile });
  if (!user) { user = new User({ mobile, isNewUser: true }); await user.save(); }
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, isNewUser: user.isNewUser });
});

/* ---- Razorpay ---- */
app.post('/api/create-order', auth, async (req, res) => {
  const { amount } = req.body;
  const order = await rzp.orders.create({
    amount: amount * 100,
    currency: 'INR',
    receipt: `receipt_${Date.now()}`
  });
  res.json({ id: order.id });
});

app.post('/api/verify-payment', auth, async (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature, items, total, address } = req.body;
  const sign = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`).digest('hex');
  if (sign !== razorpay_signature) return res.status(400).json({ error: 'Bad sign' });

  const purchase = new Purchase({ user: req.userId, items, total, paymentId: razorpay_payment_id, address });
  await purchase.save();
  await User.updateOne({ _id: req.userId }, { isNewUser: false });
  res.json({ ok: true });
});

/* ---- Email PDFs + Bill ---- */
app.post('/api/send-pdf-email', auth, async (req, res) => {
  const { items, address } = req.body;
  const user = await User.findById(req.userId);
  const attachments = items.map(it => ({
    filename: `${it.title}.pdf`,
    path: path.join(__dirname, 'uploads', `${it.bookId}.pdf`)
  }));
  // simple bill HTML → PDF (using inline style)
  const billHTML = `
    <h2>ShyamBooks – Invoice</h2>
    <p>Date: ${new Date().toLocaleString()}</p>
    <p>Address: ${address}</p>
    <table border="1" style="width:100%;border-collapse:collapse">
      <tr><th>Title</th><th>Qty</th><th>Price</th></tr>
      ${items.map(i => `<tr><td>${i.title}</td><td>${i.qty}</td><td>₹${i.qty * i.price}</td></tr>`).join('')}
    </table>
    <p><strong>Total: ₹${items.reduce((s, i) => s + i.qty * i.price, 0)}</strong></p>
  `;
  attachments.push({ filename: 'Bill.pdf', content: billHTML, contentType: 'text/html' });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email || `${user.mobile}@example.com`,
    subject: 'ShyamBooks – Your Purchase',
    html: 'Thank you! PDFs + Bill attached.',
    attachments
  });
  res.json({ sent: true });
});

/* ---- Admin upload (optional) ---- */
app.post('/api/upload-pdf', upload.single('pdf'), (req, res) => {
  res.json({ msg: `Uploaded ${req.file.originalname}` });
});

app.listen(3000, () => console.log('Backend → http://localhost:3000'));