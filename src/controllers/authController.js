const { query } = require('express');
const pool = require('../../public/database/db');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const saltRounds = 10;

const transporter = nodemailer.createTransport({
    service:'gmail',
    auth:{
        user: process.env.mail_user,
        pass: process.env.mail_password
    }
});

exports.signUp = async (req, res) => {
    const { username, email, password } = req.body;

    const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/; 
    if (!emailRegex.test(email)) {
        return res.status(400).send("Geçersiz e-posta adresi. Sadece @gmail.com adresleri desteklenir.");
    }

    
    const passwordRegex = /^(?=.*[A-Z]).{8,}$/; 
    if (!passwordRegex.test(password)) {
        return res.status(400).send("Şifre en az 8 karakter uzunluğunda ve en az bir büyük harf içermelidir.");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const result = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *',
            [username, email, hashedPassword]
        );
        res.send("Kayıt başarılı");
    } catch (err) {
        res.status(500).send("Sunucu hatası");
    }
};

exports.signIn = async (req, res) => {
    const { email, password } = req.body;


    try {
        const client = await pool.connect();
        const result = await client.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                res.send("Giriş yapıldı");
            } else {
                res.send("Hatalı şifre");
            }
        } else {
            res.send("Kullanıcı bulunamadı");
        }

        client.release();
    } catch (err) {
        res.status(500).send("Sunucu hatası");
    }
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const secret = process.env.JWT_SECRET; 
            const token = jwt.sign({ email: user.email }, secret, { expiresIn: '1h' });

            await pool.query(
                'INSERT INTO password_reset_tokens (token, email) VALUES ($1, $2)',
                [token, email]
            );

            const resetLink = `http://localhost:3000/reset_password?token=${token}`;

           /* const mailOptions = {
                from: process.env.mail_user,
                to: email,
                subject: 'Şifrenizi sıfırlayın',
                text: 'Şifrenizi sıfırlamak için buraya tıklayın: ${resetLink}' 
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('E-posta gönderim hatası:', error);
                    return res.status(500).send('E-posta gönderim hatası');
                }
                res.send('Mail gönderildi: ' + info.response);
            });*/
            res.send(resetLink);

        } else {
            res.send("Mail mevcut değil");
        }
    } catch (err) {
        console.error(err); 
        res.status(500).send("Sunucu hatası");
    }
};

exports.resetPassword = async (req, res) => {
    const newPassword  = req.body.newPassword;
    const token = req.query.token;
   
    try {
        
        const secret = process.env.JWT_SECRET;
        const decoded = jwt.verify(token, secret);

        const tokenResult = await pool.query(
            'SELECT * FROM password_reset_tokens WHERE token = $1 AND used = FALSE',
            [token]
        );

        if (tokenResult.rows.length === 0) {
            return res.status(400).send("Geçersiz veya kullanılmış token.");
        }


        const passwordRegex = /^(?=.*[A-Z]).{8,}$/; 
        if (!passwordRegex.test(newPassword)) {

            return res.status(400).send("Şifre en az 8 karakter uzunluğunda ve en az bir büyük harf içermelidir.");
        }

        const email = decoded.email;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        const result = await pool.query('UPDATE users SET password = $1 WHERE email = $2',
             [hashedPassword, email]);

        if (result.rowCount > 0) {
            await pool.query(
                'UPDATE password_reset_tokens SET used = TRUE WHERE token = $1',
                [token]
            );
            res.send("Şifre başarıyla güncellendi.");
        } else {
            res.status(404).send("Kullanıcı bulunamadı.");
        }
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            res.status(400).send("Token süresi dolmuş.");
        } else {
            res.status(500).send("Sunucu hatası");
        }
    }
};

exports.loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 3, 
    message: "Too many login attempts from this IP, please try again later."
});



