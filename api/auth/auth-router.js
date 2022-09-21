const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcryptjs = require('bcryptjs');
const userMod = require('../users/users-model')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, (req, res, next) => {
  const { password } = req.body;
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }
    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const hash = bcryptjs.hashSync(password, 12);
  userMod.add({...req.body, password: hash})
    .then(result => {
      res.status(201).json(result);
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }
    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }
    The token must expire in one day, and must provide the following information
    in its payload:
    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const {user} = req;
  if(!bcryptjs.compareSync(req.body.password, user.password)){
    return next({status: 401, message: "Invalid credentials"})
  }
  try {
    const token = generateToken(user)
    res.json({token, message: `${user.username} is back!`})
  } catch(err) {
    next(err)
  }

});

const generateToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  return jwt.sign(payload, JWT_SECRET, {expiresIn: '1d'})
}

module.exports = router;
