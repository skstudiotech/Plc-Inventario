const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

// Abilita la modalità WAL per garantire che i dati vengano salvati subito sul disco
db.run("PRAGMA journal_mode = WAL;");

db.serialize(() => {
    // 1. TABELLA UTENTI
    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        ruolo TEXT
    )`, async () => {
        // Inserisce utente admin di default solo se la tabella è vuota
        db.get(`SELECT COUNT(*) as count FROM utenti`, async (err, row) => {
            if (row && row.count === 0) {
                const passwordHash = await bcrypt.hash('admin', 10);
                db.run(`INSERT INTO utenti (username, password, ruolo) VALUES (?, ?, ?)`, ['admin', passwordHash, 'Admin']);
                console.log('--- Account Admin creato (User: admin | Pass: admin) ---');
            }
        });
    });

    // 2. TABELLA CATEGORIE
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
                const stmt = db.prepare(`INSERT OR IGNORE INTO categorie (nome) VALUES (?)`);
                categorieIniziali.forEach(cat => stmt.run(cat));
                stmt.finalize();
            }
        });
    });

    // 3. TABELLA PRODUZIONE / MAGAZZINO
    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice_barre TEXT UNIQUE,
        nome TEXT,
        categoria TEXT,
        quantita INTEGER DEFAULT 1
    )`);

    // 4. TABELLA ANNUNCI SHOP
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