const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.resolve(__dirname, 'inventario.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Errore di connessione al DB:', err.message);
    else console.log('Connessione al database SQLite stabilita.');
});

db.serialize(() => {
    // Tabella Prodotti Magazzino
    db.run(`
        CREATE TABLE IF NOT EXISTS prodotti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codice_barre TEXT UNIQUE,
            nome TEXT NOT NULL,
            categoria TEXT,
            quantita INTEGER DEFAULT 1
        )
    `);

    // Tabella Categorie Magazzino
    db.run(`
        CREATE TABLE IF NOT EXISTS categorie (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            colore TEXT DEFAULT '#3b82f6'
        )
    `);

    // Tabella Utenti
    db.run(`
        CREATE TABLE IF NOT EXISTS utenti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            ruolo TEXT NOT NULL
        )
    `, async () => {
        db.get(`SELECT * FROM utenti WHERE username = 'admin'`, async (err, row) => {
            if (!row) {
                const passHash = await bcrypt.hash('admin123', 10);
                db.run(`INSERT INTO utenti (username, password, ruolo) VALUES ('admin', ?, 'Admin')`, [passHash]);
            }
        });
        db.get(`SELECT * FROM utenti WHERE username = 'Mario'`, async (err, row) => {
            if (!row) {
                const passHash = await bcrypt.hash('mario123', 10);
                db.run(`INSERT INTO utenti (username, password, ruolo) VALUES ('Mario', ?, 'Ufficio')`, [passHash]);
            }
        });
    });

    // Tabella Annunci Shop Pubblico
    db.run(`
        CREATE TABLE IF NOT EXISTS annunci_shop (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prodotto_id INTEGER NOT NULL,
            categoria TEXT NOT NULL,
            prezzo REAL NOT NULL,
            quantita INTEGER NOT NULL,
            immagine TEXT,
            descrizione TEXT,
            FOREIGN KEY (prodotto_id) REFERENCES prodotti(id) ON DELETE CASCADE
        )
    `);
});

module.exports = db;