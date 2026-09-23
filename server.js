const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'sk_group_system_super_secret_key'; // Chiave segreta per i token JWT

// Middleware per leggere il JSON e servire i file statici
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Connessione e inizializzazione del database SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Errore di connessione al database SQLite:', err.message);
    } else {
        console.log('Connesso al database SQLite.');
    }
});

// Creazione delle tabelle necessarie all'avvio
db.serialize(() => {
    // Tabella Utenti (con ruolo admin, Ufficio, ecc.)
    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )`);

    // Tabella Prodotti per lo Shop e Magazzino
    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        categoria TEXT,
        prezzo REAL,
        quantita INTEGER,
        immagine TEXT,
        descrizione TEXT
    )`);

    // Crea automaticamente un account admin di default se non esiste
    db.get(`SELECT * FROM utenti WHERE username = ?`, ['admin'], async (err, row) => {
        if (!row) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            db.run(`INSERT INTO utenti (username, password, role) VALUES (?, ?, ?)`, 
                ['admin', hashedPassword, 'admin'], 
                (err) => {
                    if (!err) console.log("Account Admin predefinito creato (admin / admin123)");
                }
            );
        }
    });
});

// ==========================================
// MIDDLEWARE DI AUTENTICAZIONE (JWT)
// ==========================================
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

    if (!token) return res.status(401).json({ error: "Accesso non autorizzato. Token mancante." });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Token non valido o scaduto." });
        req.user = user; // Salva i dati dell'utente (id, username, role) nella richiesta
        next();
    });
}

// ==========================================
// ROTTE API - AUTENTICAZIONE & UTENTI
// ==========================================

// Login (Genera il token JWT)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM utenti WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: "Credenziali non valide." });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: "Credenziali non valide." });
        }

        // Genera il token valido per 2 ore
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '2h' });
        res.json({ success: true, token, role: user.role });
    });
});

// Creazione utente "Ufficio" (Consentita SOLO all'Admin autenticato)
app.post('/api/admin/crea-utente', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Accesso negato. Solo l'Admin può creare account Ufficio." });
    }
    
    const { username, password, role } = req.body;
    
    if (role !== 'Ufficio') {
        return res.status(400).json({ error: "Ruolo non valido. Può essere creato solo il ruolo 'Ufficio'." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO utenti (username, password, role) VALUES (?, ?, ?)`, [username, hashedPassword, role], function(err) {
            if (err) {
                return res.status(500).json({ error: "Errore: nome utente già esistente o database occupato." });
            }
            res.json({ success: true, message: "Utente Ufficio creato con successo!" });
        });
    } catch (e) {
        res.status(500).json({ error: "Errore interno del server." });
    }
});

// ==========================================
// ROTTE API - PRODOTTI & SHOP
// ==========================================

// Ottieni i prodotti in base alla categoria (es: componenti-pc, custom-pc, plc-sistemi)
app.get('/api/prodotti/:categoria', (req, res) => {
    const categoria = req.params.categoria;
    db.all(`SELECT * FROM prodotti WHERE categoria = ?`, [categoria], (err, rows) => {
        if (err) return res.status(500).json({ error: "Errore durante il recupero dei prodotti." });
        res.json(rows);
    });
});

// Aggiungi un nuovo prodotto (Consentito SOLO ad Admin e Ufficio)
app.post('/api/prodotti', verifyToken, (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'Ufficio') {
        return res.status(403).json({ error: "Non hai i permessi necessari per aggiungere prodotti." });
    }

    const { nome, categoria, prezzo, quantita, immagine, descrizione } = req.body;
    const query = `INSERT INTO prodotti (nome, categoria, prezzo, quantita, immagine, descrizione) VALUES (?, ?, ?, ?, ?, ?)`;
    
    db.run(query, [nome, categoria, prezzo, quantita, immagine, descrizione], function(err) {
        if (err) return res.status(500).json({ error: "Errore nel salvataggio del prodotto nel database." });
        res.json({ success: true, id: this.lastID, message: "Prodotto aggiunto con successo!" });
    });
});

// Gestione Checkout / Ordine (Controlla e scala la quantità di 1 nel database)
app.post('/api/checkout', (req, res) => {
    const { prodottoId } = req.body;

    db.get(`SELECT quantita, nome FROM prodotti WHERE id = ?`, [prodottoId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: "Prodotto non trovato." });

        if (row.quantita <= 0) {
            return res.status(400).json({ error: `Spiacenti, ${row.nome} è attualmente esaurito!` });
        }

        // Scala la quantità di 1
        db.run(`UPDATE prodotti SET quantita = quantita - 1 WHERE id = ?`, [prodottoId], (updateErr) => {
            if (updateErr) return res.status(500).json({ error: "Errore durante l'aggiornamento dello stock." });
            res.json({ success: true, message: `Ordine completato per ${row.nome}! Quantità aggiornata nel database centrale.` });
        });
    });
});

// Avvio del Server
app.listen(PORT, () => {
    console.log(`Server avviato e in ascolto sulla porta ${PORT}`);
});