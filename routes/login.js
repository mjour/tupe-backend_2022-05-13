var express = require('express');
var router = express.Router();
var authController = require("../controller/auth.controller");

router.post('/login', authController.loginUser);

module.exports = router;