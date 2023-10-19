require('dotenv').config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const User = require('./models/userModel');
const BlogPost = require('./models/blogPostModel');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const async = require('async');
const asyncHandler = require('express-async-handler');
const cors = require('cors');
const { body } = require('express-validator');
// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.log(err));

// Middleware
app.use(cors());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Passport

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(async(username, password, done) => {
try{
    const user = await User.findOne({ username: username });
    if(!user) return done(null, false, { message: 'Incorrect username' });
    const validPassword = await bcrypt.compare(password, user.password);
    if(!validPassword) return done(null, false, { message: 'Incorrect password' });
    done(null, user);
} catch(err) {
    done(err);
}
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
}
);

passport.deserializeUser(async(id, done) => {
    try{
        const user = await User.findById(id);
        done(null, user);
    } catch(err) {
        done(err);
    }
}
);

const validateRegister = [
    body('username').isLength({ min: 5 }).trim().escape(),
    body('password').isLength({ min: 8 }),
    // Add more validations as needed
];

// Routes

app.get('/api', (req, res) => {
    res.json({ message: 'API root' });
});

app.post('/api/register', validateRegister, asyncHandler(async(req, res) => {
    try{
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
        username: req.body.username, //changelater
        password: hashedPassword //changelater
    });
    const savedUser = await user.save();
    res.json(savedUser);
} catch(err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
}}
));

app.post('/api/login', passport.authenticate('local', { failureRedirect: '/api/login-failure', successRedirect: '/api/login-success' }));

app.get('/api/login-success', (req, res) => {
    res.json({ message: 'Login successful', user: req.user });
}
);

app.get('/api/login-failure', (req, res) => {
    res.json({ message: 'Login failed' });
}
);

app.get('/api/logout', (req, res) => {
req.logout();
res.redirect('/api');
})

// Add this route to app.js
app.get('/api/usernames', async (req, res) => {
    try {
      const users = await User.find({}, 'username');
      const usernames = users.map((user) => user.username);
      res.json({ usernames });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  });
  

app.listen(3000, () => console.log('3000'));

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Application-specific logging, rethrowing the error, or other logic here
});
