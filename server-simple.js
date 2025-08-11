/**
 * Simple Authentication Backend for C8C Studio
 */

const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Import auth routes
const authRoutes = require('./auth-routes');

const app = express();
const PORT = process.env.PORT || 8080;

// CORS configuration
app.use(cors({
    origin: ['https://studio.c8c.ai', 'https://audition.c8c.ai', 'http://localhost:3000'],
    credentials: true
}));

app.use(express.json());

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'c8c-studio-auth-backend',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Authentication routes
app.post('/auth/login', authRoutes.login);
app.post('/auth/verify-token', authRoutes.verifyToken);
app.post('/auth/forgot-password', authRoutes.forgotPassword);
app.post('/auth/reset-password', authRoutes.resetPassword);
app.post('/auth/verify-reset-token', authRoutes.verifyResetToken);

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl,
        method: req.method
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

app.listen(PORT, () => {
    console.log(`C8C Studio Auth Backend running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;