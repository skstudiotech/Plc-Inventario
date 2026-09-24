const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./database.db');

db.serialize(async () => {
    // Tabella Utenti
    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        ruolo TEXT
    )`, async () => {
        // Genera utente admin di default se la tabella è vuota
        db.get(`SELECT COUNT(*) as count FROM utenti`, async (err, row) => {
            if (row && row.count === 0) {
                const passwordHash = await bcrypt.hash('admin', 10);
                db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, ['admin', passwordHash, 'Admin']);
                console.log('--- Account Admin creato con successo! Username: admin | Password: admin ---');
            }
        });
    });

    // Tabella Categorie
    db.run(`CREATE TABLE IF NOT EXISTS categorie (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE
    )`, () => {
        db.get(`SELECT COUNT(*) as count FROM categorie`, (err, row) => {
            if (row && row.count === 0) {
                const categorieIniziali = [
                    'Componenti PC & Schede Madri',
                    'Sistemi PLC & Componenti',
                    'Accessori & Cavi',
                    'Sensori & Automazione'
                ];
                const stmt = db.prepare(`INSERT INTO categorie (nome) VALUES (?)`);
                categorieIniziali.forEach(cat => stmt.run(cat));
                stmt.finalize();
            }
        });
    });

    // Tabella Prodotti Magazzino
    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice_barre TEXT UNIQUE,
        nome TEXT,
        categoria TEXT,
        quantita INTEGER DEFAULT 1
    )`);

    // Tabella Annunci Shop
    db.run(`CREATE TABLE IF NOT EXISTS annunci_shop (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prodotto_id INTEGER,
        categoria TEXT,
        prezzo REAL,
        quantita INTEGER,
        immagine TEXT,
        descrizione TEXT,
        FOREIGN KEY (prodotto_id) REFERENCES prodotti(id)
    )`);
});

module.exports = db;