const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./database');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const SECRET_KEY = 'super_segreto_plc_key';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Middleware Autenticazione JWT
function autenticaToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Accesso non autorizzato (Token mancante)' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token non valido o scaduto' });
        req.user = user;
        next();
    });
}

// Middleware Controllo Ruoli (Case-Insensitive)
function controllaRuoli(...ruoliPermessi) {
    return (req, res, next) => {
        if (!req.user || !req.user.ruolo) {
            return res.status(403).json({ error: 'Permesso negato' });
        }
        const ruoloUtente = req.user.ruolo.toLowerCase();
        const permessiLower = ruoliPermessi.map(r => r.toLowerCase());

        if (!permessiLower.includes(ruoloUtente)) {
            return res.status(403).json({ error: 'Permesso negato per questo ruolo' });
        }
        next();
    };
}

// ---------------------------------------------------------
// ROTTE CATEGORIE (GESTIONE DINAMICA)
// ---------------------------------------------------------
app.get('/api/categorie', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM categorie ORDER BY nome ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categorie', autenticaToken, controllaRuoli('Admin', 'Ufficio', 'Operatore'), (req, res) => {
    const { nome } = req.body;
    if (!nome || nome.trim() === '') {
        return res.status(400).json({ error: 'Inserire il nome della categoria' });
    }
    db.run(`INSERT INTO categorie (nome) VALUES (?)`, [nome.trim()], function(err) {
        if (err) return res.status(400).json({ error: 'Categoria già esistente' });
        io.emit('categorie_aggiornate');
        res.json({ status: 'Categoria creata con successo', id: this.lastID, nome: nome.trim() });
    });
});

app.delete('/api/categorie/:id', autenticaToken, controllaRuoli('Admin', 'Ufficio'), (req, res) => {
    db.run(`DELETE FROM categorie WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('categorie_aggiornate');
        res.json({ status: 'Categoria eliminata' });
    });
});

// ---------------------------------------------------------
// ROTTE AUTENTICAZIONE & UTENTI
// ---------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM utenti WHERE LOWER(username) = LOWER(?)`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Utente non trovato' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Password errata' });

        const token = jwt.sign({ id: user.id, username: user.username, ruolo: user.ruolo }, SECRET_KEY, { expiresIn: '8h' });
        res.json({ token, username: user.username, ruolo: user.ruolo });
    });
});

// ---------------------------------------------------------
// ROTTE MAGAZZINO
// ---------------------------------------------------------
app.get('/api/prodotti', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM prodotti`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/prodotti', autenticaToken, controllaRuoli('Admin', 'Operatore', 'Ufficio'), (req, res) => {
    const { nome, categoria } = req.body;
    let codice_barre = req.body.codice_barre || Math.floor(10000000 + Math.random() * 90000000).toString();

    db.get(`SELECT * FROM prodotti WHERE codice_barre = ?`, [codice_barre], (err, row) => {
        if (row) {
            db.run(`UPDATE prodotti SET quantita = quantita + 1 WHERE id = ?`, [row.id], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                io.emit('inventario_aggiornato');
                res.json({ status: 'Quantità incrementata', codice_generato: codice_barre });
            });
        } else {
            db.run(`INSERT INTO prodotti (codice_barre, nome, categoria, quantita) VALUES (?, ?, ?, 1)`, [codice_barre, nome, categoria], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                io.emit('inventario_aggiornato');
                res.json({ status: 'Prodotto creato', codice_generato: codice_barre, id: this.lastID });
            });
        }
    });
});

app.delete('/api/prodotti/:id', autenticaToken, controllaRuoli('Admin'), (req, res) => {
    db.run(`DELETE FROM prodotti WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('inventario_aggiornato');
        res.json({ status: 'Prodotto eliminato' });
    });
});

// ---------------------------------------------------------
// ROTTE SHOP / UFFICIO
// ---------------------------------------------------------
app.get('/api/shop/annunci', autenticaToken, (req, res) => {
    const query = `
        SELECT a.*, p.nome as prodotto_nome, p.quantita as quantita_magazzino 
        FROM annunci_shop a
        JOIN prodotti p ON a.prodotto_id = p.id
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/shop/annunci', autenticaToken, controllaRuoli('Admin', 'Ufficio'), (req, res) => {
    const { prodotto_id, categoria, prezzo, quantita, immagine, descrizione } = req.body;

    if (!prodotto_id || !prezzo || !quantita || !categoria) {
        return res.status(400).json({ error: 'Compilare tutti i campi obbligatori' });
    }

    db.get(`SELECT quantita FROM prodotti WHERE id = ?`, [prodotto_id], (err, prod) => {
        if (err || !prod) return res.status(400).json({ error: 'Prodotto magazzino non trovato' });

        if (parseInt(quantita) > prod.quantita) {
            return res.status(400).json({ error: `La quantità supera quella in magazzino (${prod.quantita})` });
        }

        const query = `INSERT INTO annunci_shop (prodotto_id, categoria, prezzo, quantita, immagine, descrizione) VALUES (?, ?, ?, ?, ?, ?)`;
        db.run(query, [prodotto_id, categoria, prezzo, quantita, immagine, descrizione], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            io.emit('inventario_aggiornato');
            res.json({ status: 'Annuncio pubblicato con successo!', id: this.lastID });
        });
    });
});

app.delete('/api/shop/annunci/:id', autenticaToken, controllaRuoli('Admin', 'Ufficio'), (req, res) => {
    db.run(`DELETE FROM annunci_shop WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('inventario_aggiornato');
        res.json({ status: 'Annuncio eliminato' });
    });
});

// ---------------------------------------------------------
// ROTTE PUBBLICHE
// ---------------------------------------------------------
app.get('/api/public/annunci', (req, res) => {
    const query = `
        SELECT a.*, p.nome as prodotto_nome 
        FROM annunci_shop a
        JOIN prodotti p ON a.prodotto_id = p.id
        WHERE a.quantita > 0
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/public/acquista', (req, res) => {
    const { annuncio_id, quantita_acquistata } = req.body;
    const qty = parseInt(quantita_acquistata) || 1;

    db.get(`SELECT * FROM annunci_shop WHERE id = ?`, [annuncio_id], (err, annuncio) => {
        if (err || !annuncio) return res.status(404).json({ error: 'Annuncio non trovato' });

        if (annuncio.quantita < qty) {
            return res.status(400).json({ error: 'Quantità non disponibile' });
        }

        db.run(`UPDATE prodotti SET quantita = quantita - ? WHERE id = ?`, [qty, annuncio.prodotto_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            db.run(`UPDATE annunci_shop SET quantita = quantita - ? WHERE id = ?`, [qty, annuncio_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                io.emit('inventario_aggiornato');
                res.json({ status: 'Acquisto completato!' });
            });
        });
    });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server attivo su http://localhost:${PORT}`);
});