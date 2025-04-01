const express = require('express');
const fetch = require('node-fetch');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUDIENCE = `https://${AUTH0_DOMAIN}/api/v2/`;

// 🔹 Авторизація (отримання access_token через password grant type)
app.post('/api/login', async (req, res) => {
    console.log("🔹 /api/login викликано");
    const { email, password } = req.body;
    console.log("🔹 Отримано email:", email);

    try {
        const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                grant_type: "password",
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                username: email,
                password: password,
                audience: AUDIENCE,
                scope: "openid profile email",
                default_directory: process.env.AUTH0_CONNECTION
            })
        });

        console.log("🔹 Response status:", response.status);
        const data = await response.json();
        console.log("🔹 Auth0 Response:", data);

        if (data.error) throw new Error(data.error_description);

        res.json(data);
    } catch (error) {
        console.error("🔹 Auth0 Error:", error.message);
        res.status(400).json({ error: error.message });
    }
});

// 🔹 Отримання інформації про користувача
app.get('/api/userinfo', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];
    console.log("🔹 Token received:", token);

    try {
        const userResponse = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        console.log("🔹 UserInfo Response Status:", userResponse.status);
        if (!userResponse.ok) throw new Error('Invalid token');

        const user = await userResponse.json();
        res.json(user);
    } catch (error) {
        console.error("🔹 Access denied:", error.message);
        res.status(403).json({ error: 'Access denied', details: error.message });
    }
});
console.log("🔹 AUTH0_DOMAIN:", process.env.AUTH0_DOMAIN);
console.log("🔹 CLIENT_ID:", process.env.CLIENT_ID);
console.log("🔹 CLIENT_SECRET:", process.env.CLIENT_SECRET);
console.log("🔹 AUDIENCE:", process.env.AUDIENCE);
console.log("🔹 CONNECTION:", process.env.AUTH0_CONNECTION);


app.listen(3000, () => console.log('✅ Server running on port 3000'));
