require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const flash = require('connect-flash');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const methodOverride = require('method-override'); // Asegúrate de requerir method-override

const app = express(); // Inicializar express aquí

// Configuración de base de datos
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'meditech'
});

db.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        process.exit(1);
    } else {
        console.log('Conexión exitosa a la base de datos');
    }
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secreto',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(methodOverride('_method')); // Usar method-override aquí

// Configuración de rutas estáticas
const frontendDir = 'C:\\Users\\Usuario\\Desktop\\Noveno Semestre\\Programación Web\\Meditech - copia\\frontend\\';
app.use(express.static(path.join(frontendDir, 'public')));
app.use('/dashboard', express.static(path.join(frontendDir, 'web', 'startbootstrap-sb-admin-gh-pages')));
app.use('/other-path', express.static(path.join(frontendDir, 'path_to_other_static_files')));

// Motor de plantillas
app.set('view engine', 'ejs');
app.set('views', path.join(frontendDir, 'views'));

// Serialización y deserialización de usuarios
passport.serializeUser((user, done) => {
    done(null, user.UserID);
});

passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM Usuarios WHERE UserID = ?', [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]);
    });
});

// Estrategia Local
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, (email, password, done) => {
    db.query('SELECT * FROM Usuarios WHERE Email = ?', [email], (err, results) => {
        if (err) return done(err);
        if (results.length === 0) {
            return done(null, false, { message: 'El usuario no está registrado' });
        }
        const user = results[0];
        bcrypt.compare(password, user.HashContraseña, (err, isMatch) => {
            if (err) return done(err);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Contraseña incorrecta' });
            }
        });
    });
}));

// Estrategia Google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    db.query('SELECT * FROM Usuarios WHERE Email = ?', [email], (err, results) => {
        if (err) return done(err);
        if (results.length === 0) {
            return done(null, false, { message: 'El usuario no está registrado' });
        } else {
            return done(null, results[0]);
        }
    });
}));

// Middleware de autenticación
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function ensureMedico(req, res, next) {
    if (req.user && req.user.TipoUsuario === 'medico') {
        return next();
    }
    res.status(403).send('Acceso denegado');
}

// Rutas
app.get('/', (req, res) => {
    res.sendFile(path.join(frontendDir, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(frontendDir, 'public', 'login.html'));
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/seleccion-tipo-usuario', (req, res) => {
    res.sendFile(path.join(frontendDir, 'public', 'seleccion-tipo-usuario.html'));
});

app.post('/seleccion-tipo-usuario', (req, res) => {
    const tipoUsuario = req.body.tipoUsuario;
    req.session.tipoUsuario = tipoUsuario;
    res.redirect('/registro');
});

app.get('/registro', (req, res) => {
    const tipoUsuario = req.session.tipoUsuario;
    res.render('auth/registro', { tipoUsuario });
});

app.post('/registro', (req, res) => {
    const { nombre, email, password } = req.body;
    const tipoUsuario = req.session.tipoUsuario;

    if (!tipoUsuario) {
        res.status(400).send('Tipo de usuario no especificado.');
        return;
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('Error al hashear la contraseña:', err);
            res.status(500).send('Error al procesar el registro');
            return;
        }
        db.query('INSERT INTO Usuarios (Nombre, Email, HashContraseña, TipoUsuario) VALUES (?, ?, ?, ?)', 
        [nombre, email, hash, tipoUsuario], (err, results) => {
            if (err) {
                console.error('Error al insertar en la base de datos:', err);
                res.status(500).send('Error al procesar el registro');
                return;
            }
            res.redirect('/login');
        });
    });
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/login'
}), (req, res) => {
    res.redirect('/dashboard');
});

// Proteger ruta del dashboard
app.get('/dashboard/*', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(frontendDir, 'web', 'startbootstrap-sb-admin-gh-pages', 'index.html'));
});

// Ruta cierre de sesión
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return next(err);
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Error al destruir la sesión:', err);
                return next(err);
            }
            res.redirect('/');
        });
    });
});

// GET para mostrar el formulario de creación
app.get('/historialesmedicos/create', ensureAuthenticated, ensureMedico, (req, res) => {
    db.query('SELECT * FROM usuarios WHERE TipoUsuario = "paciente"', (err, results) => {
        if (err) {
            console.error('Error al obtener pacientes:', err);
            res.status(500).send('Error al obtener pacientes');
            return;
        }
        res.render('historialesmedicos/create', { pacientes: results });
    });
});

/// POST para crear un historial médico
app.post('/historialesmedicos', ensureAuthenticated, ensureMedico, (req, res) => {
    const { PacienteID, Fecha, Diagnostico, Tratamiento } = req.body;

    // Validar que se haya seleccionado un paciente
    if (!PacienteID) {
        res.status(400).send('Selecciona un paciente');
        return;
    }

    // Verificar que el PacienteID existe y que corresponde a un paciente
    db.query('SELECT UserID FROM usuarios WHERE UserID = ? AND TipoUsuario = "paciente"', [PacienteID], (err, results) => {
        if (err) {
            console.error('Error al verificar PacienteID:', err);
            res.status(500).send('Error al crear historial médico');
            return;
        }

        if (results.length === 0) {
            res.status(400).send('El paciente seleccionado no existe');
            return;
        }

        // Insertar el historial médico en la base de datos
        const sql = 'INSERT INTO historialesmedicos (PacienteID, MedicoID, Fecha, Diagnostico, Tratamiento) VALUES (?, ?, ?, ?, ?)';
        db.query(sql, [PacienteID, req.user.UserID, Fecha, Diagnostico, Tratamiento], (err, result) => {
            if (err) {
                console.error('Error al crear historial médico:', err);
                res.status(500).send('Error al crear historial médico');
                return;
            }
            console.log('Historial médico creado correctamente');
            res.redirect('/dashboard');
        });
    });
});


// Actualizar historial médico
app.post('/historialesmedicos/:id', ensureAuthenticated, ensureMedico, (req, res) => {
    const { id } = req.params;
    const { PacienteID, Fecha, Diagnostico, Tratamiento } = req.body;
    db.query('UPDATE historialesmedicos SET PacienteID = ?, Fecha = ?, Diagnostico = ?, Tratamiento = ? WHERE HistorialID = ?',
        [PacienteID, Fecha, Diagnostico, Tratamiento, id], (err, results) => {
            if (err) {
                console.error('Error al actualizar el historial médico:', err);
                res.status(500).send('Error al actualizar el historial médico');
                return;
            }
            res.redirect('/historialesmedicos');
        });
});

// Eliminar historial médico
app.post('/historialesmedicos/:id/delete', ensureAuthenticated, ensureMedico, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM historialesmedicos WHERE HistorialID = ?', [id], (err, results) => {
        if (err) {
            console.error('Error al eliminar el historial médico:', err);
            res.status(500).send('Error al eliminar el historial médico');
            return;
        }
        res.redirect('/historialesmedicos');
    });
});

// GET para mostrar la lista de historiales médicos
app.get('/historialesmedicos', ensureAuthenticated, ensureMedico, (req, res) => {
    db.query('SELECT h.*, u.Nombre AS NombrePaciente FROM historialesmedicos h INNER JOIN usuarios u ON h.PacienteID = u.UserID', (err, results) => {
        if (err) {
            console.error('Error al obtener historiales médicos:', err);
            res.status(500).send('Error al obtener historiales médicos');
            return;
        }
        res.render('historialesmedicos/index', { historiales: results });
    });
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor iniciado en el puerto ${PORT}`);
});