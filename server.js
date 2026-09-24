const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const db = require('./database');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Socket.io connection
io.on('connection', (socket) => {
    console.log('Utente connesso alla dashboard via Socket.io');
});

// --- ROTTE CATEGORIE ---
app.get('/api/categorie', (req, res) => {
    db.all(`SELECT * FROM categorie ORDER BY nome ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categorie', (req, res) => {
    const { nome, colore } = req.body;
    if (!nome || nome.trim() === '') {
        return res.status(400).json({ error: "Il nome della categoria è obbligatorio." });
    }

    const coloreCategoria = colore || '#3b82f6';

    db.run(`INSERT INTO categorie (nome, colore) VALUES (?, ?)`, [nome.trim(), coloreCategoria], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(400).json({ error: "Questa categoria esiste già." });
            }
            return res.status(500).json({ error: err.message });
        }
        
        // Notifica Socket.io per aggiornare la dashboard in tempo reale
        io.emit('categorie_aggiornate');
        res.json({ id: this.lastID, nome: nome.trim(), colore: coloreCategoria });
    });
});

app.delete('/api/categorie/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM categorie WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('categorie_aggiornate');
        res.json({ message: "Categoria eliminata con successo" });
    });
});

// --- ROTTE PRODOTTI ---
app.get('/api/prodotti', (req, res) => {
    db.all(`SELECT * FROM prodotti ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/prodotti', (req, res) => {
    let { codice_barre, nome, quantita, categoria } = req.body;
    
    if (!codice_barre || codice_barre.trim() === '') {
        codice_barre = Math.floor(10000000 + Math.random() * 90000000).toString();
    }

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

app.delete('/api/prodotti/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM prodotti WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('inventario_aggiornato');
        res.json({ message: "Prodotto eliminato" });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server avviato sulla porta ${PORT}`);
});