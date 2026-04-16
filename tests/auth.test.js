// Load env vars first for tests!
require("dotenv").config({ path: ".env.local" });

const request = require('supertest');
const app = require('../src/app');
const { connectDB } = require('../src/config/db');

describe('Auth API Integration Tests', () => {
    let cookie;

    beforeAll(async () => {
        await connectDB();
    });

    // Use a random username to avoid conflict on repeated runs
    const testUser = {
        username: `testuser${Date.now()}`,
        email: `test_${Date.now()}@example.com`,
        password: "password123!"
    };

    it('should register a new user', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send(testUser);
        
        if (res.statusCode !== 201) console.log(JSON.stringify(res.body, null, 2));
        
        expect(res.statusCode).toEqual(201);
        expect(res.body.user.email).toEqual(testUser.email);
        
        const setCookieHeader = res.headers['set-cookie'];
        expect(setCookieHeader).toBeDefined();
        cookie = setCookieHeader[0].split(';')[0]; // Extract "token=..."
    });

    it('should fail with missing fields (zod validation)', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send({ username: "imcomplete" });
        
        expect(res.statusCode).toEqual(400);
        expect(res.body.error.code).toEqual("VALIDATION_FAILED");
    });

    it('should fail registration with duplicate email', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send(testUser);
        
        expect(res.statusCode).toEqual(409);
        expect(res.body.error.code).toEqual("CONFLICT");
    });

    it('should login an existing user', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: testUser.email, password: testUser.password });
        
        expect(res.statusCode).toEqual(200);
        const setCookieHeader = res.headers['set-cookie'];
        expect(setCookieHeader).toBeDefined();
        cookie = setCookieHeader[0].split(';')[0];
    });

    it('should fail login with wrong password', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: testUser.email, password: "wrongpassword" });
        
        expect(res.statusCode).toEqual(401);
        expect(res.body.error.code).toEqual("INVALID_CREDENTIALS");
    });

    it('should get active sessions when authenticated', async () => {
        const res = await request(app)
            .get('/api/auth/sessions')
            .set('Cookie', cookie);
        
        expect(res.statusCode).toEqual(200);
        expect(res.body.sessions).toBeDefined();
        expect(res.body.sessions.length).toBeGreaterThan(0);
    });

    it('should get login history when authenticated', async () => {
        const res = await request(app)
            .get('/api/auth/login-history')
            .set('Cookie', cookie);
        
        expect(res.statusCode).toEqual(200);
        expect(res.body.history).toBeDefined();
        expect(res.body.history.length).toBeGreaterThan(0);
    });

    it('should logout user', async () => {
        const res = await request(app)
            .post('/api/auth/logout')
            .set('Cookie', cookie);
        
        expect(res.statusCode).toEqual(200);
    });

    it('should fail to get sessions after logout', async () => {
        const res = await request(app)
            .get('/api/auth/sessions')
            .set('Cookie', cookie);
        
        expect(res.statusCode).toEqual(401);
        expect(res.body.error.code).toEqual("TOKEN_REVOKED");
    });
});
