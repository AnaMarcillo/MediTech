const bodyParser = require('body-parser');
const session = require('express-session');

const middlewares = {};

// Middleware para procesar datos del formulario
middlewares.bodyParser = bodyParser.urlencoded({ extended: true });

// Middleware de express-session
middlewares.session = session({
    secret: 'tu_secreto_aqui', // Cambia esto por una cadena de caracteres aleatoria y segura
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Cambia a true si usas HTTPS
});
// Middleware para asegurar que el usuario esté autenticado
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login'); // Redireccionar a la página de inicio de sesión si no está autenticado
}

// Middleware para asegurar que el usuario sea un médico
function ensureMedico(req, res, next) {
    if (req.user && req.user.TipoUsuario === 'medico') {
        return next();
    }
    res.status(403).send('Acceso no autorizado'); // Forbidden si el usuario no es un médico
}

module.exports = {
    ensureAuthenticated,
    ensureMedico,
    middlewares
};

