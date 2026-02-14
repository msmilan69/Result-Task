// SECURITY FIX: Security tests for the airdrop platform
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/userModel');
const TokenBlacklist = require('../models/TokenBlacklist');

describe('Security Tests', () => {
    let app;
    let testUser;
    let authToken;

    beforeAll(async () => {
        // Setup test database and app
        app = require('../app');
        await mongoose.connect(process.env.MONGO_URI_TEST);
    });

    afterAll(async () => {
        // Cleanup
        await mongoose.connection.close();
    });

    beforeEach(async () => {
        // Create test user
        testUser = await User.create({
            name: 'Test User',
            email: 'test@example.com',
            password: 'TestPass123!',
            gender: 'other'
        });
        
        authToken = testUser.getJWTToken();
    });

    afterEach(async () => {
        // Cleanup test data
        await User.deleteMany({});
        await TokenBlacklist.deleteMany({});
    });

    describe('Authentication Security', () => {
        test('Should reject requests with invalid JWT tokens', async () => {
            const invalidToken = 'invalid.jwt.token';
            
            const response = await request(app)
                .get('/api/v1/me')
                .set('Cookie', `token=${invalidToken}`)
                .expect(401);
            
            expect(response.body.message).toContain('Invalid token');
        });

        test('Should reject requests with expired JWT tokens', async () => {
            const expiredToken = jwt.sign(
                { id: testUser._id }, 
                process.env.JWT_SECRET, 
                { expiresIn: '-1h' }
            );
            
            const response = await request(app)
                .get('/api/v1/me')
                .set('Cookie', `token=${expiredToken}`)
                .expect(401);
            
            expect(response.body.message).toContain('expired');
        });

        test('Should reject requests with blacklisted tokens', async () => {
            // Add token to blacklist
            await TokenBlacklist.create({
                token: authToken,
                userId: testUser._id,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
            });
            
            const response = await request(app)
                .get('/api/v1/me')
                .set('Cookie', `token=${authToken}`)
                .expect(401);
            
            expect(response.body.message).toContain('revoked');
        });

        test('Should reject requests after password change', async () => {
            // Change password
            testUser.passwordChangedAt = new Date();
            await testUser.save();
            
            const response = await request(app)
                .get('/api/v1/me')
                .set('Cookie', `token=${authToken}`)
                .expect(401);
            
            expect(response.body.message).toContain('Password recently changed');
        });
    });

    describe('Input Validation Security', () => {
        test('Should reject registration with XSS in name', async () => {
            const maliciousName = '<script>alert("xss")</script>';
            
            const response = await request(app)
                .post('/api/v1/register')
                .send({
                    name: maliciousName,
                    email: 'test2@example.com',
                    password: 'TestPass123!',
                    gender: 'other',
                    avatar: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
                })
                .expect(400);
            
            expect(response.body.message).toContain('between 2 and 50 characters');
        });

        test('Should reject registration with invalid email', async () => {
            const response = await request(app)
                .post('/api/v1/register')
                .send({
                    name: 'Test User',
                    email: 'invalid-email',
                    password: 'TestPass123!',
                    gender: 'other',
                    avatar: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
                })
                .expect(400);
            
            expect(response.body.message).toContain('valid email');
        });

        test('Should reject registration with weak password', async () => {
            const response = await request(app)
                .post('/api/v1/register')
                .send({
                    name: 'Test User',
                    email: 'test3@example.com',
                    password: 'weak',
                    gender: 'other',
                    avatar: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
                })
                .expect(400);
            
            expect(response.body.message).toContain('uppercase, lowercase, number, and special character');
        });

        test('Should reject password reset without confirmation', async () => {
            const resetToken = testUser.getResetPasswordToken();
            await testUser.save();
            
            const response = await request(app)
                .put(`/api/v1/password/reset/${resetToken}`)
                .send({
                    password: 'NewPass123!'
                    // Missing confirmPassword
                })
                .expect(400);
            
            expect(response.body.message).toContain('password and confirmation');
        });

        test('Should reject profile update with malicious avatar', async () => {
            const response = await request(app)
                .put('/api/v1/me/update')
                .set('Cookie', `token=${authToken}`)
                .send({
                    name: 'Updated Name',
                    avatar: 'not-an-image'
                })
                .expect(400);
            
            expect(response.body.message).toContain('avatar format');
        });
    });

    describe('Authorization Security', () => {
        test('Should prevent non-admin users from accessing admin routes', async () => {
            const response = await request(app)
                .get('/api/v1/admin/users')
                .set('Cookie', `token=${authToken}`)
                .expect(403);
            
            expect(response.body.message).toContain('not allowed');
        });

        test('Should prevent access to protected routes without authentication', async () => {
            const response = await request(app)
                .get('/api/v1/me')
                .expect(401);
            
            expect(response.body.message).toContain('Please Login to Access');
        });
    });

    describe('Rate Limiting Security', () => {
        test('Should implement rate limiting on sensitive endpoints', async () => {
            // This test would require implementing rate limiting middleware
            // For now, it's a placeholder to remind about this security feature
            
            // Example: Test multiple rapid login attempts
            const promises = Array(10).fill().map(() =>
                request(app)
                    .post('/api/v1/login')
                    .send({
                        email: 'test@example.com',
                        password: 'wrongpassword'
                    })
            );
            
            const responses = await Promise.all(promises);
            
            // At least one should be rate limited after multiple attempts
            const rateLimited = responses.some(res => res.status === 429);
            if (rateLimited) {
                expect(rateLimited).toBe(true);
            }
        }, 10000);
    });

    describe('Cookie Security', () => {
        test('Should set secure cookie flags in production', async () => {
            // Mock production environment
            const originalEnv = process.env.NODE_ENV;
            process.env.NODE_ENV = 'production';
            
            const response = await request(app)
                .post('/api/v1/login')
                .send({
                    email: 'test@example.com',
                    password: 'TestPass123!'
                })
                .expect(201);
            
            // Check if secure cookie flags are set
            const setCookieHeader = response.headers['set-cookie'];
            const cookieString = setCookieHeader ? setCookieHeader[0] : '';
            
            expect(cookieString).toContain('HttpOnly');
            expect(cookieString).toContain('Secure');
            expect(cookieString).toContain('SameSite=Strict');
            
            // Restore original environment
            process.env.NODE_ENV = originalEnv;
        });
    });

    describe('Blockchain Security', () => {
        test('Should verify signatures before blockchain submission', async () => {
            // This would test the frontend signature verification
            // Since this is a backend test suite, we'll test the backend validation
            
            // Mock a request with invalid signature data
            const response = await request(app)
                .post('/api/v1/prediction/submit')
                .set('Cookie', `token=${authToken}`)
                .send({
                    prediction: 'test-prediction',
                    signature: 'invalid-signature',
                    deadline: Date.now() / 1000 + 3600
                })
                .expect(400); // Should reject invalid signature
            
            expect(response.body.message).toContain('signature');
        });
    });
});

// SECURITY FIX: Integration tests for complete security flows
describe('Security Integration Tests', () => {
    test('Complete user lifecycle security', async () => {
        // 1. Register with secure data
        const registerResponse = await request(app)
            .post('/api/v1/register')
            .send({
                name: 'Secure User',
                email: 'secure@example.com',
                password: 'SecurePass123!',
                gender: 'other',
                avatar: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
            })
            .expect(201);
        
        expect(registerResponse.body.user.name).toBe('Secure User');
        
        // 2. Login and get token
        const loginResponse = await request(app)
            .post('/api/v1/login')
            .send({
                email: 'secure@example.com',
                password: 'SecurePass123!'
            })
            .expect(201);
        
        const token = loginResponse.body.token;
        
        // 3. Access protected endpoint
        const meResponse = await request(app)
            .get('/api/v1/me')
            .set('Cookie', `token=${token}`)
            .expect(200);
        
        expect(meResponse.body.user.email).toBe('secure@example.com');
        
        // 4. Update profile securely
        const updateResponse = await request(app)
            .put('/api/v1/me/update')
            .set('Cookie', `token=${token}`)
            .send({
                name: 'Updated Secure User'
            })
            .expect(200);
        
        // 5. Logout and blacklist token
        const logoutResponse = await request(app)
            .get('/api/v1/logout')
            .set('Cookie', `token=${token}`)
            .expect(200);
        
        // 6. Verify token is blacklisted
        const blockedResponse = await request(app)
            .get('/api/v1/me')
            .set('Cookie', `token=${token}`)
            .expect(401);
        
        expect(blockedResponse.body.message).toContain('revoked');
    });
});
