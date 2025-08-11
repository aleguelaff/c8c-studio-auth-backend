/**
 * Authentication routes for Railway backend
 * Handles login and token verification using DynamoDB
 */

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, PutCommand, ScanCommand } = require('@aws-sdk/lib-dynamodb');

// Initialize DynamoDB client
const dynamoClient = new DynamoDBClient({
    region: process.env.AWS_REGION || 'us-west-2',
    credentials: process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY ? {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    } : undefined
});

const dynamodb = DynamoDBDocumentClient.from(dynamoClient);
const USER_PERMISSIONS_TABLE = 'c8c-auditions-user-permissions-prod';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

/**
 * Handle user login
 */
async function login(req, res) {
    try {
        const { email_or_username, username, email, password, recaptcha_token } = req.body;
        
        console.log('Login attempt:', { email_or_username, username, email });
        
        if (!password) {
            return res.status(400).json({
                success: false,
                error: 'Password is required'
            });
        }
        
        // Determine the user identifier (prioritize email_or_username format from frontend)
        const userIdentifier = email_or_username || username || email;
        
        if (!userIdentifier) {
            return res.status(400).json({
                success: false,
                error: 'Email or username is required'
            });
        }
        
        // Look up user in DynamoDB - try different approaches to find the user
        let userData = null;
        
        // Try exact match with user_id
        try {
            const result = await dynamodb.send(new GetCommand({
                TableName: USER_PERMISSIONS_TABLE,
                Key: { user_id: userIdentifier }
            }));
            userData = result.Item;
        } catch (error) {
            console.log('Direct lookup failed:', error.message);
        }
        
        // If not found by user_id, scan by email
        if (!userData) {
            try {
                const scanResult = await dynamodb.send(new ScanCommand({
                    TableName: USER_PERMISSIONS_TABLE,
                    FilterExpression: 'email = :email',
                    ExpressionAttributeValues: {
                        ':email': userIdentifier
                    },
                    Limit: 1
                }));
                
                if (scanResult.Items && scanResult.Items.length > 0) {
                    userData = scanResult.Items[0];
                }
            } catch (error) {
                console.log('Email scan failed:', error.message);
            }
        }
        
        if (!userData) {
            console.log('User not found:', userIdentifier);
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        console.log('Found user:', userData.user_id, 'Role:', userData.role);
        
        // Verify password
        const passwordHash = userData.password_hash;
        if (!passwordHash) {
            console.log('No password hash found for user');
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // Check password - handle both bcrypt and temp passwords
        let passwordValid = false;
        
        try {
            // Try bcrypt first
            passwordValid = await bcrypt.compare(password, passwordHash);
        } catch (error) {
            console.log('Bcrypt comparison failed:', error.message);
        }
        
        // If bcrypt failed, check temp password
        if (!passwordValid && userData.temp_password) {
            passwordValid = password === userData.temp_password;
            console.log('Temp password check:', passwordValid);
        }
        
        if (!passwordValid) {
            console.log('Password verification failed');
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // Check user status
        if (userData.status && userData.status !== 'active') {
            return res.status(401).json({
                success: false,
                error: 'Account is not active'
            });
        }
        
        // Generate JWT token
        const tokenPayload = {
            userId: userData.user_id,
            email: userData.email,
            role: userData.role,
            permissions: userData.permissions,
            department: userData.department
        };
        
        const accessToken = jwt.sign(tokenPayload, JWT_SECRET, {
            expiresIn: '8h',
            issuer: 'c8c-studio-backend',
            audience: 'c8c-studio-users'
        });
        
        // Prepare user object for response
        const userResponse = {
            user_id: userData.user_id,
            email: userData.email,
            username: userData.user_id, // Use user_id as username for compatibility
            role: userData.role,
            permissions: userData.permissions,
            department: userData.department,
            status: userData.status || 'active'
        };
        
        console.log('Login successful for:', userData.email, 'Role:', userData.role);
        
        // Return success response
        res.status(200).json({
            success: true,
            access_token: accessToken,
            user: userResponse,
            expires_in: 28800 // 8 hours in seconds
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
}

/**
 * Verify JWT token
 */
async function verifyToken(req, res) {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({
                success: false,
                error: 'Token is required'
            });
        }
        
        // Verify JWT
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Optionally verify user still exists in database
        try {
            const result = await dynamodb.send(new GetCommand({
                TableName: USER_PERMISSIONS_TABLE,
                Key: { user_id: decoded.userId }
            }));
            
            if (!result.Item) {
                return res.status(401).json({
                    success: false,
                    error: 'User not found'
                });
            }
            
            if (result.Item.status && result.Item.status !== 'active') {
                return res.status(401).json({
                    success: false,
                    error: 'Account is not active'
                });
            }
        } catch (dbError) {
            console.error('Database verification error:', dbError);
            // Continue with token validation even if DB check fails
        }
        
        res.status(200).json({
            success: true,
            valid: true,
            user: {
                userId: decoded.userId,
                email: decoded.email,
                role: decoded.role,
                permissions: decoded.permissions,
                department: decoded.department
            }
        });
        
    } catch (error) {
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                valid: false,
                error: 'Invalid or expired token'
            });
        }
        
        console.error('Token verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
}

/**
 * Handle password reset requests
 */
async function forgotPassword(req, res) {
    // Placeholder for password reset functionality
    res.status(200).json({
        success: true,
        message: 'Password reset functionality not implemented yet'
    });
}

/**
 * Handle password reset with token
 */
async function resetPassword(req, res) {
    // Placeholder for password reset functionality
    res.status(200).json({
        success: true,
        message: 'Password reset functionality not implemented yet'
    });
}

/**
 * Verify reset token
 */
async function verifyResetToken(req, res) {
    // Placeholder for password reset functionality
    res.status(200).json({
        success: true,
        valid: false,
        message: 'Password reset functionality not implemented yet'
    });
}

module.exports = {
    login,
    verifyToken,
    forgotPassword,
    resetPassword,
    verifyResetToken
};