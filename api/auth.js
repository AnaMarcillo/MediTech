const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const db = require('./db');
const bcrypt = require('bcrypt');

// Configuración de estrategia local
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, (email, password, done) => {
    db.query('SELECT * FROM Usuarios WHERE Email = ?', [email], (error, results) => {
        if (error) {
            return done(error);
        }
        if (results.length === 0) {
            return done(null, false, { message: 'Usuario no encontrado' });
        }

        const user = results[0];
        bcrypt.compare(password, user.HashContraseña, (err, isMatch) => {
            if (err) {
                return done(err);
            }
            if (!isMatch) {
                return done(null, false, { message: 'Contraseña incorrecta' });
            }
            return done(null, user);
        });
    });
}));

// Configuración de estrategia de Google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;

    db.query('SELECT * FROM Usuarios WHERE Email = ?', [email], (error, results) => {
        if (error) {
            return done(error);
        }

        if (results.length === 0) {
            return done(null, false, { message: 'Usuario no registrado' });
        }
        done(null, results[0]);
    });
}));

passport.serializeUser((user, done) => {
    done(null, user.UserID);
});

passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM Usuarios WHERE UserID = ?', [id], (error, results) => {
        if (error) {
            return done(error);
        }
        if (results.length === 0) {
            return done(new Error('Usuario no encontrado'));
        }
        done(null, results[0]);
    });
});

module.exports = passport;
