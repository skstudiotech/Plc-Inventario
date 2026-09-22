const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const JWT_SECRET = 'chiave_segreta_gestionale_plc_2026';

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

async function getDb() {
    return open({
        filename: './inventario.db',
        driver: sqlite3.Database
    });
}

function autenticaToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token mancante' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token non valido' });
        }
        req.user = user;
        next();
    });
}

io.on('connection', (socket) => {
    console.log('Client connesso:', socket.id);
    socket.on('disconnect', () => {
        console.log('Client disconnesso:', socket.id);
    });
});

// LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = await getDb();
        const user = await db.get('SELECT * FROM utenti WHERE username = ?', [username]);
        
        if (!user) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }

        let match = (password === user.password);
        if (!match && user.password && user.password.startsWith('$2')) {
            match = await bcrypt.compare(password, user.password);
        }

        if (!match) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }

        const ruoloUtente = user.ruolo || 'Operatore';
        const token = jwt.sign(
            { id: user.id, username: user.username, ruolo: ruoloUtente },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ message: 'Login effettuato', token, ruolo: ruoloUtente, username: user.username });
    } catch (err) {
        console.error('ERRORE LOGIN:', err);
        res.status(500).json({ error: 'Errore del server' });
    }
});

// ELIMINAZIONE PRODOTTO (SOLO ADMIN)
app.delete('/api/prodotti/:id', autenticaToken, async (req, res) => {
    try {
        const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
        if (ruolo !== 'admin') {
            return res.status(403).json({ error: 'Accesso negato: solo gli amministratori possono eliminare i prodotti' });
        }

        const { id } = req.params;
        const { password } = req.body;
        const db = await getDb();

        const user = await db.get('SELECT password FROM utenti WHERE username = ?', [req.user.username]);
        if (!user) {
            return res.status(404).json({ error: 'Utente non trovato' });
        }

        let match = (password === user.password);
        if (!match && user.password && user.password.startsWith('$2')) {
            match = await bcrypt.compare(password, user.password);
        }

        if (!match) {
            return res.status(401).json({ error: 'Password errata' });
        }

        await db.run('DELETE FROM prodotti WHERE id = ?', [id]);
        io.emit('inventario_aggiornato');
        res.json({ message: 'Prodotto eliminato' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Errore del server' });
    }
});

// API CATEGORIE
app.get('/api/categorie', autenticaToken, async (req, res) => {
    const db = await getDb();
    const rows = await db.all('SELECT * FROM categorie');
    res.json(rows);
});

app.post('/api/categorie', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin' && ruolo !== 'operatore') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const { nome, colore } = req.body;
    const db = await getDb();
    await db.run('INSERT INTO categorie (nome, colore) VALUES (?, ?)', [nome, colore]);
    io.emit('categorie_aggiornate');
    res.json({ message: 'Categoria creata' });
});

app.delete('/api/categorie/:id', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin' && ruolo !== 'operatore') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const db = await getDb();
    await db.run('DELETE FROM categorie WHERE id = ?', [req.params.id]);
    io.emit('categorie_aggiornate');
    res.json({ message: 'Categoria eliminata' });
});

// API PRODOTTI
app.get('/api/prodotti', autenticaToken, async (req, res) => {
    const db = await getDb();
    const rows = await db.all('SELECT * FROM prodotti');
    res.json(rows);
});

app.post('/api/prodotti', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo === 'visualizzatore' || ruolo === 'addetto scontrini') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const { codice_barre, nome, categoria } = req.body;
    const codiceGenerato = codice_barre || Math.floor(10000000 + Math.random() * 90000000).toString();
    const db = await getDb();
    
    await db.run('INSERT INTO prodotti (codice_barre, nome, categoria, quantita) VALUES (?, ?, ?, 1)', 
        [codiceGenerato, nome, categoria]);
    
    io.emit('inventario_aggiornato');
    res.json({ message: 'Prodotto salvato', codice_generato: codiceGenerato });
});

// SIMULATORE PLC
app.post('/api/plc/scansione', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo === 'visualizzatore' || ruolo === 'addetto scontrini') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const { codice_barre } = req.body;
    const db = await getDb();
    const prodotto = await db.get('SELECT * FROM prodotti WHERE codice_barre = ?', [codice_barre]);
    
    if (prodotto) {
        await db.run('UPDATE prodotti SET quantita = quantita + 1 WHERE codice_barre = ?', [codice_barre]);
        io.emit('inventario_aggiornato');
        res.json({ status: `Aggiornato: ${prodotto.nome} (+1)` });
    } else {
        res.status(404).json({ error: 'Codice a barre non trovato in magazzino' });
    }
});

// GESTIONE UTENTI (SOLO ADMIN)
app.get('/api/admin/utenti', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const db = await getDb();
    const rows = await db.all('SELECT id, username, ruolo FROM utenti');
    res.json(rows);
});

app.post('/api/admin/crea-utente', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const { newUsername, newPassword, ruolo: nuovoRuolo } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const db = await getDb();
    await db.run('INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)', [newUsername, hashedPassword, nuovoRuolo || 'Operatore']);
    res.json({ message: 'Utente creato' });
});

app.delete('/api/admin/elimina-utente/:id', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin') {
        return res.status(403).json({ error: 'Accesso negato' });
    }
    const db = await getDb();
    await db.run('DELETE FROM utenti WHERE id = ?', [req.params.id]);
    res.json({ message: 'Utente eliminato' });
});

app.put('/api/admin/cambia-ruolo', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin') {
        return res.status(403).json({ error: 'Accesso negato' });
    }

    const { id, nuovoRuolo } = req.body;
    const db = await getDb();
    await db.run('UPDATE utenti SET ruolo = ? WHERE id = ?', [nuovoRuolo, id]);
    res.json({ message: 'Ruolo aggiornato' });
});

app.put('/api/admin/cambia-password-utente', autenticaToken, async (req, res) => {
    const ruolo = req.user.ruolo ? req.user.ruolo.toLowerCase() : '';
    if (ruolo !== 'admin') {
        return res.status(403).json({ error: 'Accesso negato' });
    }

    const { id, nuovaPassword } = req.body;
    const hashed = await bcrypt.hash(nuovaPassword, 10);
    const db = await getDb();
    await db.run('UPDATE utenti SET password = ? WHERE id = ?', [hashed, id]);
    res.json({ message: 'Password utente aggiornata con successo' });
});

app.post('/api/cambia-password', autenticaToken, async (req, res) => {
    const { nuovaPassword } = req.body;
    const hashed = await bcrypt.hash(nuovaPassword, 10);
    const db = await getDb();
    await db.run('UPDATE utenti SET password = ? WHERE id = ?', [hashed, req.user.id]);
    res.json({ message: 'Password aggiornata' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server SQLite attivo su http://localhost:${PORT}`);
});