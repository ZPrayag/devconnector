const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('./../../models/User');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');

//@route GET api/auth
//@desc Test route
//@access Public

router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).send('Server error');
  }
});

//@route POST api/auth
//@desc Authenticate user and get token
//@access Public

router.post(
  '/',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    console.log(req.body);

    const { email, password } = req.body;

    try {
      //See if users exist
      let user = await User.findOne({ email });
      if (!user) {
        // console.log(user);
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid credentials' }] });
      }
      //Return JWT
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 3600000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );

      //   res.send('Users registered');
    } catch (error) {
      console.log(error.message);
      return res.status(500).send('Server error');
    }
  }
);

module.exports = router;
