var express = require('express');
const { userValidation, validate } = require('../middleware/validation');
var router = express.Router();
var authController = require("../controller/auth.controller");

router.post('/register', userValidation(), validate, authController.registerUser);

router.post('/sendCode', authController.sendCode);

router.post('/sendSmsCode', authController.sendSmsCode);

module.exports = router;