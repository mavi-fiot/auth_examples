const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Налаштовуємо клієнт для отримання публічного ключа
const client = jwksClient({
    jwksUri: 'https://kpi.eu.auth0.com/.well-known/jwks.json'
});

// Функція для отримання ключа за `kid`
function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            return callback(err, null);
        }
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

// Middleware для перевірки JWT
function checkJwt(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token is missing' });
    }

    jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token', error: err.message });
        }

        req.user = decoded;
        next();
    });
}

// Захищений маршрут
app.get('/protected', checkJwt, (req, res) => {
    res.json({ message: 'Success! You accessed a protected route.', user: req.user });
});
