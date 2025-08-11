/**
 * Enhanced Backend for Project 1958 Audition Review
 * Now with admin authentication and real audio examples
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import route handlers
const authRoutes = require('./auth-routes');
const adminRoutes = require('./admin-routes');

const app = express();
const PORT = process.env.PORT || 8080;

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? [
            'https://audition.c8c.ai',
            'https://studio.c8c.ai',
            'http://localhost:3000'
          ]
        : '*',
    credentials: true
}));

app.use(express.json());

// Admin credentials (in production, use proper auth system)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Quality1958!';

// Simple access token for audio playback
const SIMPLE_ACCESS_TOKEN = 'training2025secure';

// Real training data from Excel analysis
const TRAINING_DATA = {
    project: '1958',
    title: 'Expressive Español - Cinematic Casting',
    stats: {
        total_reviewed: 66,
        approved: 8,
        rejected: 51,
        pending: 8,
        recommend_retake: 2,
        rejection_rate: 77.3  // More accurate: 51 rejected out of 66
    },
    approved_examples: [
        {
            id: 'APPR001',
            feedback: 'excellent diction and timing',
            quality: 'excellent',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/c559262f-36da-4240-b099-1eaf52416470.mp3'
        },
        {
            id: 'APPR002',
            feedback: 'pretty good acting, emotions are clearly separated by her intonation',
            quality: 'good',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/a3a5f8eb-b2d5-4d6f-800a-1f0fd3bf7e2f.mp3'
        },
        {
            id: 'APPR003',
            feedback: 'good performance over all, each of the emotions were well differentiated',
            quality: 'good',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/8759cff1-1725-4c0c-b9fc-21d36f965cc3.wav'
        },
        {
            id: 'APPR004',
            feedback: 'Pretty good acting, her high pitch makes her sound cheeful even when trying to express sadness',
            quality: 'good_with_notes',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/34c55fde-ceea-46f3-87e9-22e8b2356b30.wav'
        },
        {
            id: 'APPR005',
            feedback: 'He could slow down and work on his diction to achieve even better results',
            quality: 'approved_needs_improvement',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/436e72b2-99b8-468c-b643-15fa87d6469a.mp3'
        }
    ],
    problematic_approved: [
        {
            id: 'PROB001',
            feedback: 'He sounded pretty flat in all the lines, no emotions at all',
            note: 'APPROVED despite poor feedback - shows inconsistency',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/312ca790-c471-450b-9a92-7a2d68d14f07.mp3'
        },
        {
            id: 'PROB002',
            feedback: 'The required emotions were not accomplished',
            note: 'APPROVED despite failing requirements',
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/f7e6a1f2-a096-4b72-9c14-1b4ccd0453f1.mp3'
        }
    ],
    rejected_examples: [
        {
            id: 'REJ001',
            feedback: 'lacks expression, hesitates, stutter, not good overall',
            issues: ['No expression', 'Hesitation', 'Stuttering'],
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/e848a187-b244-4952-a267-1f3809d98ee3.mp3'
        },
        {
            id: 'REJ002',
            feedback: 'background noises, hesitates when reading, very flat delivery, not laughing etc',
            issues: ['Background noise', 'Flat delivery', 'No emotion'],
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/a4752e23-46e8-4e32-8cdf-1fb9956ed67b.mp3'
        },
        {
            id: 'REJ003',
            feedback: 'sound garbled at the start, noise artifact, stops in the middle of the read and retries several times',
            issues: ['Technical issues', 'Multiple retakes', 'Noise artifacts'],
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/4dcd7bfb-3b66-4bba-be4b-3228d21c64a5.wav'
        },
        {
            id: 'REJ004',
            feedback: 'sound too muffled and volume too low, inaudible at times',
            issues: ['Poor audio quality', 'Low volume', 'Muffled'],
            audioUrl: 'https://dcpd01workflowstorage.blob.core.windows.net/data-collections/f5aea568-5fc7-47f5-86de-b78ccbdc64c2/39c46f4c-954b-438b-8076-7e3d0c952ec3/5cfe37d0-9e5d-4329-b5a7-37e4ee1f3c65.wav'
        }
    ],
    common_issues: [
        'Lack of emotional expression (most common)',
        'Just reading, not acting',
        'Not following emotional directions',
        'Technical audio problems',
        'Hesitations and retakes',
        'Flat, monotone delivery'
    ],
    improvement_tips: [
        'Study the approved examples with "excellent" ratings',
        'Notice how emotions are clearly differentiated',
        'Maintain consistent audio quality',
        'Complete full takes without stopping',
        'Act, don\'t just read',
        'Follow emotional directions precisely'
    ],
    client_notes: [
        'Even some approved auditions had poor feedback',
        'Consistency is a major issue',
        'Clear emotional differentiation is key',
        'Technical quality must be maintained'
    ]
};

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'audition-review-backend',
        version: '2.0.0'
    });
});

// Authentication routes
app.post('/auth/login', authRoutes.login);
app.post('/auth/verify-token', authRoutes.verifyToken);
app.post('/auth/forgot-password', authRoutes.forgotPassword);
app.post('/auth/reset-password', authRoutes.resetPassword);
app.post('/auth/verify-reset-token', authRoutes.verifyResetToken);

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        // In production, generate a proper JWT token
        const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
        res.json({ 
            success: true, 
            token,
            message: 'Login successful'
        });
    } else {
        res.status(401).json({ 
            success: false, 
            message: 'Invalid credentials' 
        });
    }
});

// Middleware to check admin token
const checkAdminAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // In production, verify JWT properly
    const token = authHeader.split(' ')[1];
    try {
        const decoded = Buffer.from(token, 'base64').toString();
        if (decoded.startsWith(ADMIN_USERNAME + ':')) {
            next();
        } else {
            res.status(401).json({ error: 'Invalid token' });
        }
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Simple password check endpoint
app.post('/api/training/1958/access', (req, res) => {
    const { password } = req.body;
    
    if (password === 'Quality1958') {
        res.json({ 
            success: true, 
            token: SIMPLE_ACCESS_TOKEN,
            data: TRAINING_DATA
        });
    } else {
        res.status(401).json({ 
            success: false, 
            message: 'Invalid password' 
        });
    }
});

// Get training data (public endpoint)
app.get('/api/training/1958/overview', (req, res) => {
    // Return data without audio URLs for public access
    const publicData = {
        ...TRAINING_DATA,
        approved_examples: TRAINING_DATA.approved_examples.map(ex => ({
            id: ex.id,
            feedback: ex.feedback,
            quality: ex.quality
        })),
        problematic_approved: TRAINING_DATA.problematic_approved.map(ex => ({
            id: ex.id,
            feedback: ex.feedback,
            note: ex.note
        })),
        rejected_examples: TRAINING_DATA.rejected_examples.map(ex => ({
            id: ex.id,
            feedback: ex.feedback,
            issues: ex.issues
        }))
    };
    res.json(publicData);
});

// Get full data with audio URLs (requires admin auth)
app.get('/api/training/1958/full', checkAdminAuth, (req, res) => {
    res.json(TRAINING_DATA);
});

// Simple middleware to check token
const checkSimpleAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader === `Bearer ${SIMPLE_ACCESS_TOKEN}`) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// Get specific audio URL (simple auth)
app.get('/api/training/1958/audio/:exampleId', checkSimpleAuth, (req, res) => {
    const { exampleId } = req.params;
    
    // Find the audio URL from all categories
    let audioUrl = null;
    
    // Check approved examples
    const approved = TRAINING_DATA.approved_examples.find(ex => ex.id === exampleId);
    if (approved) audioUrl = approved.audioUrl;
    
    // Check problematic approved
    if (!audioUrl) {
        const problematic = TRAINING_DATA.problematic_approved.find(ex => ex.id === exampleId);
        if (problematic) audioUrl = problematic.audioUrl;
    }
    
    // Check rejected examples
    if (!audioUrl) {
        const rejected = TRAINING_DATA.rejected_examples.find(ex => ex.id === exampleId);
        if (rejected) audioUrl = rejected.audioUrl;
    }
    
    if (audioUrl) {
        // Log access
        console.log(`Audio access granted for ${exampleId} at ${new Date().toISOString()}`);
        
        // Return the URL directly - browser will handle CORS
        res.json({ 
            url: audioUrl,
            example_id: exampleId
        });
    } else {
        res.status(404).json({ error: 'Example not found' });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Enhanced audition review backend running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Admin username: ${ADMIN_USERNAME}`);
    console.log(`CORS enabled for production domains`);
});