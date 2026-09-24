const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const JWT_SECRET = 'chiave_segreta_gestionale_plc_2026';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware Autenticazione JWT
function autenticaToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Accesso non autorizzato. Token mancante.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token non valido o scaduto.' });
        req.user = user;
        next();
    });
}

// --- ROTTA LOGIN ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Inserisci username e password.' });
    }

    db.get(`SELECT * FROM utenti WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Errore interno del database.' });
        if (!user) return res.status(400).json({ error: 'Credenziali non valide.' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Credenziali non valide.' });

        const token = jwt.sign(
            { id: user.id, username: user.username, ruolo: user.ruolo },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ token, username: user.username, ruolo: user.ruolo });
    });
});

// --- ROTTE SHOP ED INVENTARIO ---
app.get('/api/prodotti', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM prodotti ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/shop/annunci', autenticaToken, (req, res) => {
    const { nome, categoria, prezzo, quantita, immagine, descrizione } = req.body;

    if (!nome || !prezzo) {
        return res.status(400).json({ error: 'Nome e prezzo sono campi obbligatori.' });
    }

    const codiceBarre = Math.floor(10000000 + Math.random() * 90000000).toString();

    // Inserisce il prodotto in magazzino
    db.run(
        `INSERT INTO prodotti (codice_barre, nome, quantita, categoria) VALUES (?, ?, ?, ?)`,
        [codiceBarre, nome, quantita || 1, categoria || 'Generico'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            const prodottoId = this.lastID;

            // Inserisce l'annuncio shop collegato
            db.run(
                `INSERT INTO annunci_shop (prodotto_id, categoria, prezzo, quantita, immagine, descrizione) VALUES (?, ?, ?, ?, ?, ?)`,
                [prodottoId, categoria, prezzo, quantita || 1, immagine || '', descrizione || ''],
                function(errShop) {
                    if (errShop) return res.status(500).json({ error: errShop.message });
                    io.emit('inventario_aggiornato');
                    res.json({ message: 'Annuncio pubblicato con successo nello shop!', id: prodottoId });
                }
            );
        }
    );
});

// --- CATEGORIE ---
app.get('/api/categorie', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM categorie ORDER BY nome ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server attivo su http://localhost:${PORT}`);
});