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

// Middleware di Autenticazione JWT
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

// Middleware Controllo Ruoli
function controllaRuoli(...ruoliPermessi) {
    return (req, res, next) => {
        if (!req.user || !ruoliPermessi.includes(req.user.ruolo)) {
            return res.status(403).json({ error: 'Permesso negato per questo ruolo' });
        }
        next();
    };
}

// ---------------------------------------------------------
// ROTTE AUTENTICAZIONE & UTENTI
// ---------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM utenti WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Utente non trovato' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Password errata' });

        const token = jwt.sign({ id: user.id, username: user.username, ruolo: user.ruolo }, SECRET_KEY, { expiresIn: '8h' });
        res.json({ token, username: user.username, ruolo: user.ruolo });
    });
});

app.post('/api/cambia-password', autenticaToken, async (req, res) => {
    const { nuovaPassword } = req.body;
    const hash = await bcrypt.hash(nuovaPassword, 10);
    db.run(`UPDATE utenti SET password = ? WHERE id = ?`, [hash, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: 'Errore durante l\'aggiornamento password' });
        res.json({ status: 'Password aggiornata con successo' });
    });
});

app.get('/api/admin/utenti', autenticaToken, controllaRuoli('Admin'), (req, res) => {
    db.all(`SELECT id, username, ruolo FROM utenti`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/admin/crea-utente', autenticaToken, controllaRuoli('Admin'), async (req, res) => {
    const { newUsername, newPassword, ruolo } = req.body;
    const hash = await bcrypt.hash(newPassword, 10);
    db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, [newUsername, hash, ruolo], function(err) {
        if (err) return res.status(400).json({ error: 'Username già esistente' });
        res.json({ status: 'Utente creato', id: this.lastID });
    });
});

app.put('/api/admin/cambia-ruolo', autenticaToken, controllaRuoli('Admin'), (req, res) => {
    const { id, nuovoRuolo } = req.body;
    db.run(`UPDATE utenti SET ruolo = ? WHERE id = ?`, [nuovoRuolo, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: 'Ruolo aggiornato' });
    });
});

app.delete('/api/admin/elimina-utente/:id', autenticaToken, controllaRuoli('Admin'), (req, res) => {
    db.run(`DELETE FROM utenti WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: 'Utente eliminato' });
    });
});

// ---------------------------------------------------------
// ROTTE MAGAZZINO & CATEGORIE
// ---------------------------------------------------------
app.get('/api/prodotti', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM prodotti`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/prodotti', autenticaToken, controllaRuoli('Admin', 'Operatore'), (req, res) => {
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
    const { password } = req.body;
    db.get(`SELECT * FROM utenti WHERE id = ?`, [req.user.id], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Utente non valido' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Password Admin errata' });

        db.run(`DELETE FROM prodotti WHERE id = ?`, [req.params.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            io.emit('inventario_aggiornato');
            res.json({ status: 'Prodotto eliminato' });
        });
    });
});

app.get('/api/categorie', autenticaToken, (req, res) => {
    db.all(`SELECT * FROM categorie`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categorie', autenticaToken, controllaRuoli('Admin', 'Operatore'), (req, res) => {
    const { nome, colore } = req.body;
    db.run(`INSERT INTO categorie (nome, colore) VALUES (?, ?)`, [nome, colore], function(err) {
        if (err) return res.status(400).json({ error: 'Categoria già esistente' });
        io.emit('categorie_aggiornate');
        res.json({ status: 'Categoria creata', id: this.lastID });
    });
});

app.delete('/api/categorie/:id', autenticaToken, controllaRuoli('Admin', 'Operatore'), (req, res) => {
    db.run(`DELETE FROM categorie WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('categorie_aggiornate');
        res.json({ status: 'Categoria eliminata' });
    });
});

// ---------------------------------------------------------
// ROTTE GESTIONE SHOP / UFFICIO / ANNUNCI
// ---------------------------------------------------------
app.get('/api/shop/annunci', autenticaToken, controllaRuoli('Admin', 'Ufficio'), (req, res) => {
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

    if (!prodotto_id || !prezzo || !quantita) {
        return res.status(400).json({ error: 'Compilare tutti i campi obbligatori' });
    }

    db.get(`SELECT quantita FROM prodotti WHERE id = ?`, [prodotto_id], (err, prod) => {
        if (err || !prod) return res.status(400).json({ error: 'Prodotto magazzino non trovato' });

        if (parseInt(quantita) > prod.quantita) {
            return res.status(400).json({ error: `La quantità (${quantita}) supera quella presente in magazzino (${prod.quantita})` });
        }

        const query = `INSERT INTO annunci_shop (prodotto_id, categoria, prezzo, quantita, immagine, descrizione) VALUES (?, ?, ?, ?, ?, ?)`;
        db.run(query, [prodotto_id, categoria, prezzo, quantita, immagine, descrizione], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ status: 'Annuncio pubblicato con successo!', id: this.lastID });
        });
    });
});

app.put('/api/shop/annunci/:id', autenticaToken, controllaRuoli('Admin', 'Ufficio'), (req, res) => {
    const { prezzo, quantita, immagine, descrizione } = req.body;
    const query = `UPDATE annunci_shop SET prezzo = ?, quantita = ?, immagine = ?, descrizione = ? WHERE id = ?`;
    db.run(query, [prezzo, quantita, immagine, descrizione, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: 'Annuncio aggiornato' });
    });
});

app.delete('/api/shop/annunci/:id', autenticaToken, controllaRuoli('Admin', 'Ufficio'), (req, res) => {
    db.run(`DELETE FROM annunci_shop WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: 'Annuncio eliminato dallo shop' });
    });
});

// ---------------------------------------------------------
// ROTTA PUBBLICA SHOP (Accessibile da componenti-pc.html)
// ---------------------------------------------------------
app.get('/api/public/annunci', (req, res) => {
    const categoria = req.query.categoria;
    let query = `
        SELECT a.*, p.nome as prodotto_nome 
        FROM annunci_shop a
        JOIN prodotti p ON a.prodotto_id = p.id
        WHERE a.quantita > 0
    `;
    let params = [];

    if (categoria) {
        query += ` AND a.categoria = ?`;
        params.push(categoria);
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Rotta per simulazione acquisto pubblico (scala la quantità sia dall'annuncio che dalla contabilità/magazzino)
app.post('/api/public/acquista', (req, res) => {
    const { annuncio_id, quantita_acquistata } = req.body;
    const qty = parseInt(quantita_acquistata) || 1;

    db.get(`SELECT * FROM annunci_shop WHERE id = ?`, [annuncio_id], (err, annuncio) => {
        if (err || !annuncio) return res.status(404).json({ error: 'Annuncio non trovato' });

        if (annuncio.quantita < qty) {
            return res.status(400).json({ error: 'Quantità non disponibile' });
        }

        // Scala la quantità dal magazzino (contabilità)
        db.run(`UPDATE prodotti SET quantita = quantita - ? WHERE id = ?`, [qty, annuncio.prodotto_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            // Scala la quantità dall'annuncio dello shop
            db.run(`UPDATE annunci_shop SET quantita = quantita - ? WHERE id = ?`, [qty, annuncio_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                io.emit('inventario_aggiornato');
                res.json({ status: 'Acquisto completato! Inventario e contabilità aggiornati.' });
            });
        });
    });
});

// ---------------------------------------------------------
// SIMULATORE SCANNER PLC
// ---------------------------------------------------------
app.post('/api/plc/scansione', autenticaToken, controllaRuoli('Admin', 'Operatore'), (req, res) => {
    const { codice_barre } = req.body;
    db.get(`SELECT * FROM prodotti WHERE codice_barre = ?`, [codice_barre], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Codice non trovato nel sistema' });
        db.run(`UPDATE prodotti SET quantita = quantita + 1 WHERE id = ?`, [row.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            io.emit('inventario_aggiornato');
            res.json({ status: `Scansione OK: ${row.nome} (Q.tà: ${row.quantita + 1})` });
        });
    });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server avviato su http://localhost:${PORT}`);
});