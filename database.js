const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'inventario.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run("PRAGMA foreign_keys = ON");

    // Tabella Prodotti estesa per supportare sia l'inventario PLC sia gli annunci dello Shop
    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice_barre TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        categoria TEXT DEFAULT 'Generico',
        quantita INTEGER DEFAULT 0,
        prezzo REAL DEFAULT 0.0,
        descrizione TEXT DEFAULT '',
        immagine TEXT DEFAULT '',
        categoria_shop TEXT DEFAULT '',
        pubblicato_shop INTEGER DEFAULT 0
    )`);

    // Tabella Utenti
    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        ruolo TEXT DEFAULT 'operatore'
    )`);

    // Tabella Categorie
    db.run(`CREATE TABLE IF NOT EXISTS categorie (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL,
        colore TEXT DEFAULT '#64748b'
    )`, () => {
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Elettronica', '#3b82f6')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Schede Video', '#8b5cf6')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Componenti PLC', '#10b981')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Generico', '#64748b')`);
    });
});

module.exports = db;