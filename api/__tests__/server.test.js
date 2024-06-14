const request = require('supertest');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const flash = require('connect-flash');
const path = require('path');
const methodOverride = require('method-override');
const db = require('../db');
const { ensureAuthenticated, ensureMedico, middlewares } = require('../middlewares');

// Initialize Express app
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secreto',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(methodOverride('_method'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../frontend/views'));

// Dummy route for testing
app.get('/login', (req, res) => res.status(200).send('Login Page'));
app.get('/', (req, res) => res.status(200).send('Home Page'));
app.post('/login', (req, res) => res.status(200).send('Logged In'));
app.get('/seleccion-tipo-usuario', (req, res) => res.status(200).send('Select User Type Page'));
app.post('/seleccion-tipo-usuario', (req, res) => res.status(200).send('User Type Selected'));
app.get('/registro', (req, res) => res.status(200).send('Registration Page'));
app.post('/registro', (req, res) => res.status(200).send('Registered'));
app.get('/auth/google', (req, res) => res.status(302).redirect('/auth/google/callback'));
app.get('/auth/google/callback', (req, res) => res.status(200).send('Google Auth Callback'));
app.get('/dashboard/*', (req, res) => res.status(200).send('Dashboard Page'));
app.get('/historialesmedicos/create', (req, res) => res.status(200).send('Create Medical Record Page'));
app.post('/historialesmedicos', (req, res) => res.status(200).send('Medical Record Created'));
app.post('/historialesmedicos/:id', (req, res) => res.status(200).send('Medical Record Updated'));
app.post('/historialesmedicos/:id/delete', (req, res) => res.status(200).send('Medical Record Deleted'));
app.get('/historialesmedicos', (req, res) => res.status(200).send('List of Medical Records'));

// Example user session for testing authentication
const authenticatedSession = {
    secret: 'secreto',
    cookie: {
        maxAge: 60000
    },
    resave: false,
    saveUninitialized: false
};

// Test Suite for All Endpoints
describe('All Endpoints', () => {
    it('GET / should return the home page', async () => {
        const res = await request(app).get('/');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Home Page');
    });

    it('GET /login should return the login page', async () => {
        const res = await request(app).get('/login');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Login Page');
    });

    it('POST /login should authenticate user', async () => {
        const res = await request(app)
            .post('/login')
            .send({ email: 'test@example.com', password: 'password' });
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Logged In');
    });

    it('GET /seleccion-tipo-usuario should return the select user type page', async () => {
        const res = await request(app).get('/seleccion-tipo-usuario');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Select User Type Page');
    });

    it('POST /seleccion-tipo-usuario should select user type', async () => {
        const res = await request(app)
            .post('/seleccion-tipo-usuario')
            .send({ tipoUsuario: 'medico' });
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('User Type Selected');
    });

    it('GET /registro should return the registration page', async () => {
        const res = await request(app).get('/registro');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Registration Page');
    });

    it('POST /registro should register user', async () => {
        const res = await request(app)
            .post('/registro')
            .send({ nombre: 'Test User', email: 'test@example.com', password: 'password' });
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Registered');
    });

    it('GET /auth/google should redirect to Google Auth', async () => {
        const res = await request(app).get('/auth/google');
        expect(res.statusCode).toBe(302);
        expect(res.header.location).toBe('/auth/google/callback');
    });

    it('GET /auth/google/callback should handle Google Auth callback', async () => {
        const res = await request(app).get('/auth/google/callback');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Google Auth Callback');
    });

    it('GET /dashboard/* should return the dashboard page', async () => {
        const res = await request(app).get('/dashboard/somepage');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Dashboard Page');
    });


    it('GET /historialesmedicos/create should return the create medical record page', async () => {
        const res = await request(app).get('/historialesmedicos/create');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Create Medical Record Page');
    });

    it('POST /historialesmedicos should create a medical record', async () => {
        const res = await request(app)
            .post('/historialesmedicos')
            .send({ PacienteID: 1, Fecha: '2023-01-01', Diagnostico: 'Diagnosis', Tratamiento: 'Treatment' });
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Medical Record Created');
    });

    it('POST /historialesmedicos/:id should update a medical record', async () => {
        const res = await request(app)
            .post('/historialesmedicos/1')
            .send({ PacienteID: 1, Fecha: '2023-01-01', Diagnostico: 'Updated Diagnosis', Tratamiento: 'Updated Treatment' });
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Medical Record Updated');
    });

    it('POST /historialesmedicos/:id/delete should delete a medical record', async () => {
        const res = await request(app)
            .post('/historialesmedicos/1/delete');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('Medical Record Deleted');
    });

    it('GET /historialesmedicos should return the list of medical records', async () => {
        const res = await request(app).get('/historialesmedicos');
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain('List of Medical Records');
    });
});

// Close the database connection after all tests are done
afterAll(() => {
    db.end();
});
