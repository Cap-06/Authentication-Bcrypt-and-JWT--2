const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const BlacklistedToken = require('../models/BlacklistedToken');
const auth = require('../middlewares/auth');

const router = express.Router();

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = new User({ username, password });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Error registering user', error });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });

    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRATION,
    });

    user.refreshToken = refreshToken;
    await user.save();

    res.json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});


router.post('/logout', auth, async (req, res) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  try {
  
    const blacklistedToken = new BlacklistedToken({
      token,
      expirationDate: new Date(jwt.decode(token).exp * 1000),
    });
    await blacklistedToken.save();

   
    const user = await User.findById(req.user.id);
    user.refreshToken = null;
    await user.save();

    res.status(200).json({ message: 'User logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});


router.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});

module.exports = router;
