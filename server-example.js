// Esempio di implementazione backend per Google OAuth
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const app = express();

// Configura il client Google OAuth
const client = new OAuth2Client('TUO-CLIENT-ID.apps.googleusercontent.com');

app.use(express.json());
app.use(express.static('public')); // Serve i file statici

// Endpoint per autenticazione Google
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;

        // Verifica il token Google
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: 'TUO-CLIENT-ID.apps.googleusercontent.com'
        });

        const payload = ticket.getPayload();
        const { sub: googleId, email, name, picture } = payload;

        // Controlla se l'email è del dominio scolastico
        if (!email.endsWith('@tuoistituto.edu.it')) {
            return res.status(403).json({ 
                error: 'Accesso consentito solo agli studenti dell\'istituto' 
            });
        }

        // Qui puoi salvare/aggiornare l'utente nel database
        const user = await saveOrUpdateUser({
            googleId,
            email,
            name,
            picture
        });

        // Genera JWT token per la sessione
        const authToken = jwt.sign(
            { userId: user.id, email: user.email },
            'TUO-SECRET-KEY',
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token: authToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                picture: user.picture
            }
        });

    } catch (error) {
        console.error('Auth error:', error);
        res.status(401).json({ error: 'Token non valido' });
    }
});

// Funzione per salvare/aggiornare utente (esempio con database)
async function saveOrUpdateUser(userData) {
    // Qui implementi la logica per salvare nel database
    // Esempio con MongoDB/Mongoose:
    /*
    const User = require('./models/User');
    let user = await User.findOne({ email: userData.email });
    
    if (!user) {
        user = new User(userData);
    } else {
        Object.assign(user, userData);
    }
    
    return await user.save();
    */
    
    // Per ora ritorna un oggetto mock
    return {
        id: '1',
        ...userData
    };
}

// Middleware per proteggere le route
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, 'TUO-SECRET-KEY', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Esempio di route protetta
app.get('/api/user/profile', authenticateToken, (req, res) => {
    res.json({ message: 'Profilo utente', user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server in ascolto sulla porta ${PORT}`);
});

module.exports = app;