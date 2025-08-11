/**
 * Admin routes for Railway backend
 * Handles user management and admin operations
 */

const bcrypt = require('bcrypt');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, PutCommand, ScanCommand, DeleteCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');
const { v4: uuidv4 } = require('uuid');

// Initialize DynamoDB client
const dynamoClient = new DynamoDBClient({
    region: process.env.AWS_REGION || 'us-west-2',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

const dynamodb = DynamoDBDocumentClient.from(dynamoClient);
const USER_PERMISSIONS_TABLE = 'c8c-auditions-user-permissions-prod';
const AUDITIONS_TABLE = 'c8c-auditions-auditions-prod';

/**
 * Get all users
 */
async function getUsers(req, res) {
    try {
        const result = await dynamodb.send(new ScanCommand({
            TableName: USER_PERMISSIONS_TABLE
        }));
        
        // Filter out sensitive information
        const users = result.Items.map(user => ({
            user_id: user.user_id,
            email: user.email,
            role: user.role,
            department: user.department,
            status: user.status || 'active',
            permissions: user.permissions,
            created_at: user.created_at,
            updated_at: user.updated_at
        }));
        
        res.json({
            success: true,
            users
        });
        
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch users'
        });
    }
}

/**
 * Create new user
 */
async function createUser(req, res) {
    try {
        const { email, username, role, department, permissions, temp_password } = req.body;
        
        if (!email || !role) {
            return res.status(400).json({
                success: false,
                error: 'Email and role are required'
            });
        }
        
        // Generate temp password if not provided
        const password = temp_password || Math.random().toString(36).slice(-8) + '123!';
        const passwordHash = await bcrypt.hash(password, 10);
        
        const userId = username || email;
        const userData = {
            user_id: userId,
            email,
            role,
            department: department || 'General',
            permissions: permissions || [],
            password_hash: passwordHash,
            temp_password: password,
            status: 'active',
            created_at: Date.now(),
            updated_at: Date.now()
        };
        
        await dynamodb.send(new PutCommand({
            TableName: USER_PERMISSIONS_TABLE,
            Item: userData,
            ConditionExpression: 'attribute_not_exists(user_id)'
        }));
        
        // Return user data without sensitive information
        const responseData = { ...userData };
        delete responseData.password_hash;
        
        res.status(201).json({
            success: true,
            user: responseData
        });
        
    } catch (error) {
        if (error.name === 'ConditionalCheckFailedException') {
            return res.status(409).json({
                success: false,
                error: 'User already exists'
            });
        }
        
        console.error('Error creating user:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create user'
        });
    }
}

/**
 * Update user
 */
async function updateUser(req, res) {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Remove sensitive fields that shouldn't be updated directly
        delete updates.user_id;
        delete updates.password_hash;
        delete updates.created_at;
        
        updates.updated_at = Date.now();
        
        // Build update expression
        const updateExpression = [];
        const expressionAttributeValues = {};
        
        Object.keys(updates).forEach(key => {
            updateExpression.push(`${key} = :${key}`);
            expressionAttributeValues[`:${key}`] = updates[key];
        });
        
        await dynamodb.send(new UpdateCommand({
            TableName: USER_PERMISSIONS_TABLE,
            Key: { user_id: id },
            UpdateExpression: `SET ${updateExpression.join(', ')}`,
            ExpressionAttributeValues: expressionAttributeValues,
            ReturnValues: 'ALL_NEW'
        }));
        
        res.json({
            success: true,
            message: 'User updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update user'
        });
    }
}

/**
 * Delete user
 */
async function deleteUser(req, res) {
    try {
        const { id } = req.params;
        
        await dynamodb.send(new DeleteCommand({
            TableName: USER_PERMISSIONS_TABLE,
            Key: { user_id: id }
        }));
        
        res.json({
            success: true,
            message: 'User deleted successfully'
        });
        
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete user'
        });
    }
}

/**
 * Get auditions
 */
async function getAuditions(req, res) {
    try {
        const result = await dynamodb.send(new ScanCommand({
            TableName: AUDITIONS_TABLE,
            Limit: 50 // Limit for performance
        }));
        
        res.json({
            success: true,
            auditions: result.Items || []
        });
        
    } catch (error) {
        console.error('Error fetching auditions:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch auditions'
        });
    }
}

/**
 * Approve audition
 */
async function approveAudition(req, res) {
    try {
        const { id } = req.params;
        
        await dynamodb.send(new UpdateCommand({
            TableName: AUDITIONS_TABLE,
            Key: { audition_id: id },
            UpdateExpression: 'SET #status = :status, updated_at = :updated_at',
            ExpressionAttributeNames: {
                '#status': 'status'
            },
            ExpressionAttributeValues: {
                ':status': 'approved',
                ':updated_at': new Date().toISOString()
            }
        }));
        
        res.json({
            success: true,
            message: 'Audition approved successfully'
        });
        
    } catch (error) {
        console.error('Error approving audition:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to approve audition'
        });
    }
}

/**
 * Reject audition
 */
async function rejectAudition(req, res) {
    try {
        const { id } = req.params;
        
        await dynamodb.send(new UpdateCommand({
            TableName: AUDITIONS_TABLE,
            Key: { audition_id: id },
            UpdateExpression: 'SET #status = :status, updated_at = :updated_at',
            ExpressionAttributeNames: {
                '#status': 'status'
            },
            ExpressionAttributeValues: {
                ':status': 'rejected',
                ':updated_at': new Date().toISOString()
            }
        }));
        
        res.json({
            success: true,
            message: 'Audition rejected successfully'
        });
        
    } catch (error) {
        console.error('Error rejecting audition:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reject audition'
        });
    }
}

/**
 * Delete audition
 */
async function deleteAudition(req, res) {
    try {
        const { id } = req.params;
        
        await dynamodb.send(new DeleteCommand({
            TableName: AUDITIONS_TABLE,
            Key: { audition_id: id }
        }));
        
        res.json({
            success: true,
            message: 'Audition deleted successfully'
        });
        
    } catch (error) {
        console.error('Error deleting audition:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete audition'
        });
    }
}

module.exports = {
    getUsers,
    createUser,
    updateUser,
    deleteUser,
    getAuditions,
    approveAudition,
    rejectAudition,
    deleteAudition
};