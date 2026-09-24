const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'sk_group_system_super_secret_key';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connessione al database SQLite
const db = new sqlite3.Database(path.resolve(__dirname, 'database.db'), (err) => {
    if (err) {
        console.error('Errore di connessione al database SQLite:', err.message);
    } else {
        console.log('Connesso al database SQLite.');
    }
});

// Inizializzazione tabelle
db.serialize(() => {
    db.run("PRAGMA foreign_keys = ON");

    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        ruolo TEXT DEFAULT 'Operatore'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice_barre TEXT UNIQUE,
        nome TEXT,
        categoria TEXT DEFAULT 'Generico',
        quantita INTEGER DEFAULT 0,
        prezzo REAL DEFAULT 0,
        immagine TEXT,
        descrizione TEXT,
        prodotto_padre_id INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS categorie (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL,
        colore TEXT DEFAULT '#64748b'
    )`, () => {
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Componenti PC & Schede Madri', '#3b82f6')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Costruzione Custom PC', '#8b5cf6')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Sistemi PLC & Componenti', '#10b981')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Generico', '#64748b')`);
    });

    // Account Admin predefinito
    db.get(`SELECT * FROM utenti WHERE username = ?`, ['admin'], async (err, row) => {
        if (!row) {
            const hashedPassword = await bcrypt.hash('admin', 10);
            db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, ['admin', hashedPassword, 'Admin']);
        }
    });
});

// Middleware autenticazione JWT
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Accesso non autorizzato. Token mancante." });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Token non valido o scaduto." });
        req.user = user;
        next();
    });
}

// ================= API AUTH & UTENTI =================

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM utenti WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Credenziali non valide." });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: "Credenziali non valide." });

        const token = jwt.sign({ id: user.id, username: user.username, ruolo: user.ruolo }, SECRET_KEY, { expiresIn: '2h' });
        res.json({ success: true, token, ruolo: user.ruolo, username: user.username });
    });
});

app.post('/api/admin/crea-utente', verifyToken, async (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Accesso negato. Solo l'Admin può creare account." });
    }
    
    const { newUsername, newPassword, ruolo } = req.body;
    const ruoloScelto = ruolo || req.body.role || 'Operatore';

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, [newUsername, hashedPassword, ruoloScelto], function(err) {
            if (err) return res.status(500).json({ error: "Nome utente già esistente." });
            res.json({ success: true, message: "Utente creato con successo!" });
        });
    } catch (e) {
        res.status(500).json({ error: "Errore interno del server." });
    }
});

app.get('/api/admin/utenti', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') return res.status(403).json({ error: "Accesso negato." });
    db.all(`SELECT id, username, ruolo FROM utenti`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: "Errore database." });
        res.json(rows);
    });
});

app.put('/api/admin/cambia-ruolo', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') return res.status(403).json({ error: "Accesso negato." });
    const { id, nuovoRuolo } = req.body;
    db.run(`UPDATE utenti SET ruolo = ? WHERE id = ?`, [nuovoRuolo, id], function(err) {
        if (err) return res.status(500).json({ error: "Errore aggiornamento ruolo." });
        res.json({ success: true });
    });
});

app.put('/api/admin/cambia-password-utente', verifyToken, async (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') return res.status(403).json({ error: "Accesso negato." });
    const { id, nuovaPassword } = req.body;
    try {
        const hashed = await bcrypt.hash(nuovaPassword, 10);
        db.run(`UPDATE utenti SET password = ? WHERE id = ?`, [hashed, id], function(err) {
            if (err) return res.status(500).json({ error: "Errore aggiornamento password." });
            res.json({ success: true });
        });
    } catch (e) {
        res.status(500).json({ error: "Errore server." });
    }
});

app.delete('/api/admin/elimina-utente/:id', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') return res.status(403).json({ error: "Accesso negato." });
    db.run(`DELETE FROM utenti WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: "Errore eliminazione utente." });
        res.json({ success: true });
    });
});

app.post('/api/cambia-password', verifyToken, async (req, res) => {
    const { nuovaPassword } = req.body;
    try {
        const hashed = await bcrypt.hash(nuovaPassword, 10);
        db.run(`UPDATE utenti SET password = ? WHERE id = ?`, [hashed, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: "Errore aggiornamento password." });
            res.json({ success: true });
        });
    } catch (e) {
        res.status(500).json({ error: "Errore server." });
    }
});

// ================= API CATEGORIE =================

app.get('/api/categorie', verifyToken, (req, res) => {
    db.all(`SELECT * FROM categorie`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: "Errore database." });
        res.json(rows);
    });
});

app.post('/api/categorie', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Solo l'Admin può creare o modificare le categorie." });
    }
    const { nome, colore } = req.body;
    db.run(`INSERT INTO categorie (nome, colore) VALUES (?, ?)`, [nome, colore || '#64748b'], function(err) {
        if (err) return res.status(500).json({ error: "Categoria già esistente." });
        io.emit('categorie_aggiornate');
        res.json({ success: true, id: this.lastID });
    });
});

app.delete('/api/categorie/:id', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Accesso negato." });
    }
    db.run(`DELETE FROM categorie WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: "Errore eliminazione." });
        io.emit('categorie_aggiornate');
        res.json({ success: true });
    });
});

// ================= API PRODOTTI & SHOP =================

app.get('/api/prodotti', verifyToken, (req, res) => {
    db.all(`SELECT * FROM prodotti`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: "Errore database." });
        res.json(rows);
    });
});

app.get('/api/prodotti/categoria/:categoria', (req, res) => {
    const categoriaDecodificata = decodeURIComponent(req.params.categoria);
    db.all(`SELECT * FROM prodotti WHERE categoria = ?`, [categoriaDecodificata], (err, rows) => {
        if (err) return res.status(500).json({ error: "Errore database." });
        res.json(rows);
    });
});

// Creazione o Pubblicazione Prodotti/Annunci
app.post('/api/prodotti', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin' && req.user.ruolo !== 'Ufficio' && req.user.role !== 'Ufficio' && req.user.ruolo !== 'Operatore') {
        return res.status(403).json({ error: "Non hai i permessi necessari." });
    }

    const { prodotto_id, codice_barre, nome, categoria, prezzo, quantita, immagine, descrizione } = req.body;
    const qtyInput = parseInt(quantita) || 1;

    if (prodotto_id) {
        db.get(`SELECT * FROM prodotti WHERE id = ?`, [prodotto_id], (err, dbProd) => {
            if (err || !dbProd) return res.status(400).json({ error: "Prodotto selezionato non trovato nel database." });
            
            if (qtyInput > dbProd.quantita) {
                return res.status(400).json({ error: `Quantità non valida! Disponibile a magazzino nel database: ${dbProd.quantita}` });
            }

            db.run(`UPDATE prodotti SET categoria = ?, quantita = ?, prezzo = ?, immagine = ?, descrizione = ?, prodotto_padre_id = ? WHERE id = ?`,
                [categoria, qtyInput, prezzo || 0, immagine || '', descrizione || '', dbProd.id, prodotto_id], function(err) {
                if (err) return res.status(500).json({ error: "Errore nell'aggiornamento dell'annuncio." });
                io.emit('inventario_aggiornato');
                res.json({ success: true, id: prodotto_id });
            });
        });
    } else {
        const codiceGenerato = codice_barre || Math.floor(10000000 + Math.random() * 90000000).toString();
        db.run(`INSERT INTO prodotti (codice_barre, nome, categoria, quantita, prezzo, immagine, descrizione) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [codiceGenerato, nome, categoria || 'Componenti PC & Schede Madri', qtyInput, prezzo || 0, immagine || '', descrizione || ''], function(err) {
            if (err) return res.status(500).json({ error: "Errore nel salvataggio del prodotto." });
            io.emit('inventario_aggiornato');
            res.json({ success: true, id: this.lastID, codice_generato: codiceGenerato });
        });
    }
});

// Endpoint specifico per pubblicazione Annunci targati su target page
app.post('/api/annunci', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin' && req.user.ruolo !== 'Ufficio' && req.user.role !== 'Ufficio') {
        return res.status(403).json({ error: "Non hai i permessi necessari." });
    }

    const { prodottoId, categoria, prezzo, urlImmagine, descrizione } = req.body;

    let targetPage = 'index.html';
    switch (categoria) {
        case 'componenti-pc':
            targetPage = 'componenti-pc.html';
            break;
        case 'custom-pc':
            targetPage = 'assemblaggio-custom-pc.html';
            break;
        case 'sistemi-plc':
            targetPage = 'sistemi-plc.html';
            break;
    }

    db.run(`UPDATE prodotti SET categoria = ?, prezzo = ?, immagine = ?, descrizione = ? WHERE id = ?`,
        [categoria, prezzo || 0, urlImmagine || '', descrizione || '', prodottoId], function(err) {
            if (err) return res.status(500).json({ error: "Errore durante il salvataggio dell'annuncio." });
            io.emit('inventario_aggiornato');
            res.json({ success: true, message: `Annuncio pubblicato con successo per ${targetPage}` });
        });
});

// MODIFICA ANNUNCIO / PRODOTTO
app.put('/api/prodotti/:id', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin' && req.user.ruolo !== 'Ufficio' && req.user.role !== 'Ufficio') {
        return res.status(403).json({ error: "Accesso negato." });
    }

    const { nome, categoria, prezzo, quantita, immagine, descrizione } = req.body;
    const qtyInput = parseInt(quantita) || 0;

    db.get(`SELECT quantita FROM prodotti WHERE id = ?`, [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).json({ error: "Prodotto non trovato." });

        db.run(`UPDATE prodotti SET nome = ?, categoria = ?, prezzo = ?, quantita = ?, immagine = ?, descrizione = ? WHERE id = ?`,
            [nome, categoria, prezzo || 0, qtyInput, immagine || '', descrizione || '', req.params.id], function(err) {
            if (err) return res.status(500).json({ error: "Errore nell'aggiornamento dell'annuncio." });
            io.emit('inventario_aggiornato');
            res.json({ success: true });
        });
    });
});

// ELIMINAZIONE DIRETTA ANNUNCIO (Ufficio / Admin)
app.delete('/api/prodotti/annuncio/:id', verifyToken, (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin' && req.user.ruolo !== 'Ufficio' && req.user.role !== 'Ufficio') {
        return res.status(403).json({ error: "Accesso negato." });
    }

    db.run(`DELETE FROM prodotti WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: "Errore eliminazione." });
        io.emit('inventario_aggiornato');
        res.json({ success: true });
    });
});

// Eliminazione Magazzino con Password Admin
app.delete('/api/prodotti/:id', verifyToken, async (req, res) => {
    if (req.user.ruolo !== 'Admin' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Solo l'Admin può eliminare i prodotti da questa sezione." });
    }
    const { password } = req.body;
    db.get(`SELECT password FROM utenti WHERE id = ?`, [req.user.id], async (err, row) => {
        if (err || !row) return res.status(400).json({ error: "Utente non trovato." });
        const match = await bcrypt.compare(password, row.password);
        if (!match) return res.status(400).json({ error: "Password errata." });

        db.run(`DELETE FROM prodotti WHERE id = ?`, [req.params.id], function(err) {
            if (err) return res.status(500).json({ error: "Errore eliminazione." });
            io.emit('inventario_aggiornato');
            res.json({ success: true });
        });
    });
});

app.post('/api/checkout', (req, res) => {
    const { prodottoId } = req.body;
    db.get(`SELECT * FROM prodotti WHERE id = ?`, [prodottoId], (err, prod) => {
        if (err || !prod) return res.status(404).json({ success: false, error: "Prodotto non trovato." });
        if (prod.quantita <= 0) return res.status(400).json({ success: false, error: "Prodotto esaurito." });

        db.run(`UPDATE prodotti SET quantita = quantita - 1 WHERE id = ?`, [prodottoId], (updateErr) => {
            if (updateErr) return res.status(500).json({ success: false, error: "Errore durante l'ordine." });
            io.emit('inventario_aggiornato');
            res.json({ success: true, message: `Ordine effettuato con successo per ${prod.nome}!` });
        });
    });
});

app.post('/api/plc/scansione', verifyToken, (req, res) => {
    const { codice_barre } = req.body;
    db.get(`SELECT * FROM prodotti WHERE codice_barre = ?`, [codice_barre], (err, prod) => {
        if (err || !prod) return res.status(404).json({ error: "Prodotto non trovato sul nastro PLC." });

        db.run(`UPDATE prodotti SET quantita = quantita + 1 WHERE id = ?`, [prod.id], (updateErr) => {
            if (updateErr) return res.status(500).json({ error: "Errore aggiornamento quantità." });
            io.emit('inventario_aggiornato');
            res.json({ success: true, status: `Scansione PLC riuscita: ${prod.nome} (+1)` });
        });
    });
});

// Endpoint per registrare l'acquisto di un annuncio e scalare la giacenza
app.post('/api/prodotti/acquista/:id', verifyToken, (req, res) => {
    const annuncioId = req.params.id;

    db.get('SELECT * FROM prodotti WHERE id = ?', [annuncioId], (err, item) => {
        if (err || !item) return res.status(404).json({ error: 'Annuncio non trovato' });
        if (item.quantita <= 0) return res.status(400).json({ error: 'Quantità esaurita nello shop' });

        // 1. Riduci la quantità dell'annuncio di 1
        db.run('UPDATE prodotti SET quantita = quantita - 1 WHERE id = ?', [annuncioId], (updateErr) => {
            if (updateErr) return res.status(500).json({ error: updateErr.message });

            // 2. Se collegato a un prodotto padre in inventario, riduci la quantità anche da lì
            if (item.prodotto_padre_id) {
                db.run('UPDATE prodotti SET quantita = MAX(0, quantita - 1) WHERE id = ?', [item.prodotto_padre_id]);
            }

            // 3. Notifica via WebSocket
            io.emit('inventario_aggiornato');
            res.json({ success: true, message: 'Vendita registrata e inventario aggiornato' });
        });
    });
});

server.listen(PORT, () => {
    console.log(`Server avviato e in ascolto sulla porta ${PORT}`);
});