const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'inventario.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run("PRAGMA foreign_keys = ON");

    // 1. Tabella Prodotti
    db.run(`CREATE TABLE IF NOT EXISTS prodotti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice_barre TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        categoria TEXT DEFAULT 'Generico',
        quantita INTEGER DEFAULT 0
    )`);

    // 2. Tabella Utenti
    db.run(`CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        ruolo TEXT DEFAULT 'operatore'
    )`);

    // 3. Tabella Categorie con Colore
    db.run(`CREATE TABLE IF NOT EXISTS categorie (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL,
        colore TEXT DEFAULT '#64748b'
    )`, () => {
        // Categorie predefinite di base se il database è nuovo
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Elettronica', '#3b82f6')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Schede Video', '#8b5cf6')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Componenti PLC', '#10b981')`);
        db.run(`INSERT OR IGNORE INTO categorie (nome, colore) VALUES ('Generico', '#64748b')`);
    });
});

module.exports = db;