const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const app = express();

// Middleware to set security headers
app.use(helmet());

// Middleware to parse JSON requests
app.use(express.json());

// Rate limiter middleware to limit repeated requests
const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 60, // limit each IP to 60 requests per windowMs
    message: "Too many requests, please try again later."
});
app.use(limiter);

// Public key for JWT verification
const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY || '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';

// Middleware to verify JWT
function verifyJwtMiddleware(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
    if (!token) {
        return res.status(401).json({ message: 'No token provided.' });
    }

    jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Failed to authenticate token.' });
        }
        req.user = decoded; // Save decoded user info in request object
        next();
    });
}

// Example route that requires authentication
app.get('/protected', verifyJwtMiddleware, (req, res) => {
    res.status(200).json({ message: 'This is a protected route.', user: req.user });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
