# C8C Studio Authentication Backend

Railway backend service for C8C Studio portal authentication.

## Features

- DynamoDB user authentication
- JWT token management  
- bcrypt password hashing
- Temporary password support
- User management endpoints

## API Endpoints

### Authentication
- `POST /auth/login` - User login with DynamoDB lookup
- `POST /auth/verify-token` - Token validation
- `POST /auth/forgot-password` - Password reset request
- `POST /auth/reset-password` - Reset password with token

### Health
- `GET /health` - Service health check

## Environment Variables

Required:
- `JWT_SECRET` - Secret key for JWT token signing
- `AWS_ACCESS_KEY_ID` - AWS access key for DynamoDB
- `AWS_SECRET_ACCESS_KEY` - AWS secret key for DynamoDB  
- `AWS_REGION` - AWS region (default: us-west-2)

Optional:
- `NODE_ENV` - Environment (production/development)
- `PORT` - Port number (default: 8080)

## Deployment

This service is deployed to Railway and connects to:
- DynamoDB table: `c8c-auditions-user-permissions-prod`
- Frontend: `studio.c8c.ai`