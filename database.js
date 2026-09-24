const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

// Disattiva il journal WAL temporaneo per salvare subito nel file fisso database.db
db.run("PRAGMA journal_mode = DELETE;");

db.serialize(() => {
    // TABELLA UTENTI
    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        ruolo TEXT
    )`, async () => {
        db.get(`SELECT COUNT(*) as count FROM utenti`, async (err, row) => {
            if (row && row.count === 0) {
                const passwordHash = await bcrypt.hash('admin', 10);
                db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, ['admin', passwordHash, 'Admin']);
                console.log('--- Account Admin creato (User: admin | Pass: admin) ---');
            }
        });
    });

    // TABELLA CATEGORIE
    db.run(`CREATE TABLE IF NOT EXISTS categorie (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL,
        colore TEXT DEFAULT '#64748b'
    )`, () => {
        db.get(`SELECT COUNT(*) as count FROM categorie`, (err, row) => {
            if (row && row.count === 0) {
                const categorieIniziali = [
                    ['Componenti PC & Schede Madri', '#8b5cf6'],
                    ['Sistemi PLC & Componenti', '#3b82f6'],
                    ['Accessori & Cavi', '#10b981'],
                    ['Sensori & Automazione', '#64748b']
                ];
                const stmt = db.prepare(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES (?, ?)`);
                categorieIniziali.forEach(cat => stmt.run(cat[0], cat[1]));
                stmt.finalize();
            }
        });
    });

    // TABELLA PRODOTTI / MAGAZZINO
    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice_barre TEXT UNIQUE,
        nome TEXT,
        quantita INTEGER DEFAULT 0,
        categoria TEXT DEFAULT 'Generico'
    )`);

    // TABELLA ANNUNCI SHOP
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