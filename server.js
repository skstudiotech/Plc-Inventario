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

// Middleware di autenticazione token JWT
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

// Socket.io connection
io.on('connection', (socket) => {
    console.log('Utente connesso via Socket.io');
});

// --- ROTTA DI LOGIN ---
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

        res.json({
            token,
            username: user.username,
            ruolo: user.ruolo
        });
    });
});

// --- ROTTE GESTIONE UTENTI (ADMIN) ---
app.get('/api/admin/utenti', autenticaToken, (req, res) => {
    if (req.user.ruolo !== 'Admin') return res.status(403).json({ error: 'Accesso negato.' });
    db.all(`SELECT id, username, ruolo FROM utenti`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/admin/crea-utente', autenticaToken, async (req, res) => {
    if (req.user.ruolo !== 'Admin') return res.status(403).json({ error: 'Accesso negato.' });
    const { newUsername, newPassword, ruolo } = req.body;
    
    if (!newUsername || !newPassword) return res.status(400).json({ error: 'Campi obbligatori mancanti.' });

    const passwordHash = await bcrypt.hash(newPassword, 10);
    db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, [newUsername, passwordHash, ruolo || 'Operatore'], function(err) {
        if (err) return res.status(400).json({ error: 'Username già in uso.' });
        res.json({ message: 'Utente creato con successo.' });
    });
});

app.put('/api/admin/cambia-ruolo', autenticaToken, (req, res) => {
    if (req.user.ruolo !== 'Admin') return res.status(403).json({ error: 'Accesso negato.' });
    const { id, nuovoRuolo } = req.body;
    db.run(`UPDATE utenti SET ruolo = ? WHERE id = ?`, [nuovoRuolo, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Ruolo aggiornato.' });
    });
});

app.delete('/api/admin/elimina-utente/:id', autenticaToken, (req, res) => {
    if (req.user.ruolo !== 'Admin') return res.status(403).json({ error: 'Accesso negato.' });
    db.run(`DELETE FROM utenti WHERE id = ? AND username != 'admin'`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Utente eliminato.' });
    });
});

app.post('/api/cambia-password', autenticaToken, async (req, res) => {
    const { nuovaPassword } = req.body;
    const passwordHash = await bcrypt.hash(nuovaPassword, 10);
    db.run(`UPDATE utenti SET password = ? WHERE id = ?`, [passwordHash, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Password aggiornata.' });
    });
});

// --- ROTTE CATEGORIE ---
app.get('/api/categorie', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM categorie ORDER BY nome ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categorie', autenticaToken, (req, res) => {
    const { nome, colore } = req.body;
    if (!nome) return res.status(400).json({ error: "Nome obbligatorio." });

    db.run(`INSERT INTO categorie (nome, colore) VALUES (?, ?)`, [nome.trim(), colore || '#3b82f6'], function(err) {
        if (err) return res.status(400).json({ error: "Categoria esistente." });
        io.emit('categorie_aggiornate');
        res.json({ id: this.lastID, nome: nome.trim(), colore });
    });
});

app.delete('/api/categorie/:id', autenticaToken, (req, res) => {
    db.run(`DELETE FROM categorie WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('categorie_aggiornate');
        res.json({ message: "Categoria eliminata." });
    });
});

// --- ROTTE PRODOTTI ---
app.get('/api/prodotti', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM prodotti ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/prodotti', autenticaToken, (req, res) => {
    let { codice_barre, nome, quantita, categoria } = req.body;
    if (!codice_barre) codice_barre = Math.floor(10000000 + Math.random() * 90000000).toString();

    db.run(
        `INSERT INTO prodotti (codice_barre, nome, quantita, categoria) VALUES (?, ?, ?, ?)`,
        [codice_barre, nome, quantita || 1, categoria || 'Generico'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            io.emit('inventario_aggiornato');
            res.json({ id: this.lastID, codice_generato: codice_barre, nome, quantita, categoria });
        }
    );
});

app.delete('/api/prodotti/:id', autenticaToken, (req, res) => {
    if (req.user.ruolo !== 'Admin') return res.status(403).json({ error: 'Solo Admin può eliminare.' });
    db.run(`DELETE FROM prodotti WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('inventario_aggiornato');
        res.json({ message: "Prodotto eliminato." });
    });
});

// Reindirizzamento di default
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server attivo su http://localhost:${PORT}`);
});