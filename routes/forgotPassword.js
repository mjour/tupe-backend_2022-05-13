const express = require('express');
const router = express.Router();
var authController = require("../controller/auth.controller");

// Unused API
router.post('/forgotPassword', authController.forgotPassword);

router.post('/forPassWithPhone', authController.forPassWithPhone);

// Unused API
router.post("/reset-password",authController.resetPassword);

router.post("/resPassWithPhone",authController.resPassWithPhone);

module.exports = router;