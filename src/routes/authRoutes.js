const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const path = require('path');
router.get('/sign_in', (req, res) => {
    res.send("ok");
});

router.get('/sign_up', (req, res) => {
    res.send("ok");
});

router.get('/forgot_password', (req, res) => {
    res.sendFile(path.join(__dirname, '..','..', 'public', 'forgot_password.html'));
});

router.get('/resert', (req, res)=>{
    res.send("ok");
});

router.post('/sign_in',authController.loginLimiter, authController.signIn);
router.post('/sign_up', authController.signUp);
router.post('/forgot_password', authController.forgotPassword);
router.post('/reset_password', authController.resetPassword);

module.exports = router;
