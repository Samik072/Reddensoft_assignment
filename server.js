require('dotenv').config();
const express       = require('express');
const mongoose      = require('mongoose');
const bcrypt        = require('bcryptjs');
const session       = require('express-session');
const MongoStore    = require('connect-mongo');
const nodemailer    = require('nodemailer');
const bodyParser    = require('body-parser');
const { body, validationResult } = require('express-validator');
const User          = require('./models/User');

const app = express();
mongoose.connect(process.env.MONGO_URI);

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI })
}));

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});



// ----- SIGNUP -----
app.get('/signup', (req, res) => res.render('signup', { errors: [] }));
app.post('/signup', [
  body('name').trim().notEmpty(),
  body('email').isEmail().normalizeEmail(),
  body('phone').matches(/^\d{10}$/),
  body('password')
    .isLength({ min: 8 })
    .matches(/[a-z]/).withMessage('lowercase')
    .matches(/[A-Z]/).withMessage('uppercase')
    .matches(/\d/).withMessage('number')
    .matches(/[^A-Za-z0-9]/).withMessage('symbol'),
  body('agree').equals('on')
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) {
    return res.render('signup', { errors: errs.array() });
  }
  const { name, email, phone, password } = req.body;
  const exists = await User.findOne({ email });
  if (exists) {
    return res.render('signup', { errors: [{ msg: 'Email already in use' }] });
  }
  const hash = await bcrypt.hash(password, 12);
  const token = Math.random().toString(36).substr(2);
  const user = new User({ name, email, phone, password: hash, verifyToken: token });
  await user.save();

  // send verification email
  const url = `${process.env.BASE_URL}/verify/${token}`;
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to: email,
    subject: 'Please verify your email',
    html: `<p>Hi ${name},</p>
           <p>Click <a href="${url}">here</a> to verify your account.</p>`
  });

  res.render('verify');
});

// ----- EMAIL VERIFICATION -----
app.get('/verify/:token', async (req, res) => {
  const user = await User.findOne({ verifyToken: req.params.token });
  if (!user) {
    return res.send('Invalid token');
  }
  user.verified = true;
  user.verifyToken = undefined;
  await user.save();
  res.send('Email verified! You can now <a href="/login">login</a>.');
});

// ----- LOGIN -----
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render('login', { error: 'Invalid credentials.' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.render('login', { error: 'Invalid credentials.' });
  if (!user.verified) {
    return res.send('Please verify your email before logging in.');
  }
  // set session and redirect
  req.session.userId = user._id;
  res.redirect('/dashboard');
});

// ----- DASHBOARD -----
app.get('/dashboard', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const user = await User.findById(req.session.userId);
  res.render('dashboard', { name: user.name });
});

// ----- LOGOUT -----
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ----- START -----
app.listen(process.env.PORT, () => {
  console.log(`Listening on http://localhost:${process.env.PORT}`);
});
