const express = require('express');
const path = require('path');
const app = express();
const authRoutes = require('./src/routes/authRoutes'); // Route dosyasını içe aktarın

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

// Route'ları kullanın
app.use('/', authRoutes);

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
