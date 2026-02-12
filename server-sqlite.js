const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Initialize SQLite Database
const db = new sqlite3.Database('./numbers.db', (err) => {
    if (err) {
        console.error('❌ Errore connessione database:', err);
    } else {
        console.log('✅ Database SQLite connesso');
        initializeDatabase();
    }
});

// JWT Secret
const JWT_SECRET = 'local-dev-secret-change-in-production';

// Initialize database schema
function initializeDatabase() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Companies table
        db.run(`CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            address TEXT,
            email TEXT,
            tax_id TEXT,
            payment_info TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        // Customers table
        db.run(`CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            address TEXT,
            vat TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
        )`);

        // Invoices table
        db.run(`CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            invoice_number TEXT NOT NULL,
            date TEXT NOT NULL,
            due_date TEXT,
            items TEXT NOT NULL,
            subtotal REAL NOT NULL,
            tax REAL DEFAULT 0,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            UNIQUE(company_id, invoice_number)
        )`);

        // Expenses table
        db.run(`CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            category TEXT,
            date TEXT NOT NULL,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
        )`);

        // Reminders table
        db.run(`CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            invoice_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            due_date TEXT NOT NULL,
            completed INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
            FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
        )`);

        console.log('✅ Schema database inizializzato');
    });
}

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token mancante' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token non valido' });
        }
        req.user = user;
        next();
    });
};

// ============= AUTH ROUTES =============

// Register
app.post('/api/auth/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('name').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;

    try {
        // Check if user exists
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Errore database' });
            }
            if (row) {
                return res.status(400).json({ error: 'Email già registrata' });
            }

            // Hash password
            const passwordHash = await bcrypt.hash(password, 10);

            // Create user
            db.run('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)',
                [email, passwordHash, name],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Errore durante la registrazione' });
                    }

                    const user = {
                        id: this.lastID,
                        email,
                        name,
                        created_at: new Date().toISOString()
                    };

                    // Generate token
                    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

                    res.status(201).json({ user, token });
                });
        });
    } catch (error) {
        console.error('Errore registrazione:', error);
        res.status(500).json({ error: 'Errore durante la registrazione' });
    }
});

// Login
app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Credenziali non valide' });
            }

            // Check password
            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                return res.status(401).json({ error: 'Credenziali non valide' });
            }

            // Generate token
            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

            res.json({
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    created_at: user.created_at
                },
                token
            });
        });
    } catch (error) {
        console.error('Errore login:', error);
        res.status(500).json({ error: 'Errore durante il login' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    db.get('SELECT id, email, name, created_at FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'Utente non trovato' });
        }
        res.json(user);
    });
});

// ============= COMPANIES ROUTES =============

app.get('/api/companies', authenticateToken, (req, res) => {
    db.all('SELECT * FROM companies WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Errore nel recupero aziende' });
        }
        res.json(rows);
    });
});

app.post('/api/companies', authenticateToken, [
    body('name').notEmpty().trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, address, email, tax_id, payment_info } = req.body;

    db.run('INSERT INTO companies (user_id, name, address, email, tax_id, payment_info) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, name, address, email, tax_id, payment_info],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore nella creazione azienda' });
            }
            db.get('SELECT * FROM companies WHERE id = ?', [this.lastID], (err, row) => {
                res.status(201).json(row);
            });
        });
});

app.put('/api/companies/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, address, email, tax_id, payment_info } = req.body;

    db.get('SELECT id FROM companies WHERE id = ? AND user_id = ?', [id, req.user.id], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        db.run('UPDATE companies SET name = ?, address = ?, email = ?, tax_id = ?, payment_info = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [name, address, email, tax_id, payment_info, id],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Errore aggiornamento azienda' });
                }
                db.get('SELECT * FROM companies WHERE id = ?', [id], (err, row) => {
                    res.json(row);
                });
            });
    });
});

app.delete('/api/companies/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.get('SELECT id FROM companies WHERE id = ? AND user_id = ?', [id, req.user.id], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        db.run('DELETE FROM companies WHERE id = ?', [id], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore eliminazione azienda' });
            }
            res.json({ message: 'Azienda eliminata con successo' });
        });
    });
});

// ============= CUSTOMERS ROUTES =============

app.get('/api/companies/:companyId/customers', authenticateToken, (req, res) => {
    const { companyId } = req.params;

    db.get('SELECT id FROM companies WHERE id = ? AND user_id = ?', [companyId, req.user.id], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        db.all('SELECT * FROM customers WHERE company_id = ? ORDER BY created_at DESC', [companyId], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Errore recupero clienti' });
            }
            res.json(rows);
        });
    });
});

app.post('/api/companies/:companyId/customers', authenticateToken, [
    body('name').notEmpty().trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { companyId } = req.params;
    const { name, address, vat } = req.body;

    db.get('SELECT id FROM companies WHERE id = ? AND user_id = ?', [companyId, req.user.id], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        db.run('INSERT INTO customers (company_id, name, address, vat) VALUES (?, ?, ?, ?)',
            [companyId, name, address, vat],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Errore creazione cliente' });
                }
                db.get('SELECT * FROM customers WHERE id = ?', [this.lastID], (err, row) => {
                    res.status(201).json(row);
                });
            });
    });
});

app.put('/api/customers/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, address, vat } = req.body;

    db.run('UPDATE customers SET name = ?, address = ?, vat = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [name, address, vat, id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore aggiornamento cliente' });
            }
            db.get('SELECT * FROM customers WHERE id = ?', [id], (err, row) => {
                res.json(row);
            });
        });
});

app.delete('/api/customers/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM customers WHERE id = ?', [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Errore eliminazione cliente' });
        }
        res.json({ message: 'Cliente eliminato con successo' });
    });
});

// ============= INVOICES ROUTES =============

app.get('/api/companies/:companyId/invoices', authenticateToken, (req, res) => {
    const { companyId } = req.params;

    db.all(`SELECT i.*, c.name as customer_name
            FROM invoices i
            JOIN customers c ON i.customer_id = c.id
            WHERE i.company_id = ?
            ORDER BY i.date DESC`,
        [companyId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Errore recupero fatture' });
            }
            res.json(rows);
        });
});

app.post('/api/companies/:companyId/invoices', authenticateToken, (req, res) => {
    const { companyId } = req.params;
    const { customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes } = req.body;

    db.run('INSERT INTO invoices (company_id, customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [companyId, customer_id, invoice_number, date, due_date, JSON.stringify(items), subtotal, tax, total, status, notes],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore creazione fattura' });
            }
            db.get('SELECT * FROM invoices WHERE id = ?', [this.lastID], (err, row) => {
                res.status(201).json(row);
            });
        });
});

app.put('/api/invoices/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes } = req.body;

    db.run('UPDATE invoices SET customer_id = ?, invoice_number = ?, date = ?, due_date = ?, items = ?, subtotal = ?, tax = ?, total = ?, status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [customer_id, invoice_number, date, due_date, JSON.stringify(items), subtotal, tax, total, status, notes, id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore aggiornamento fattura' });
            }
            db.get('SELECT * FROM invoices WHERE id = ?', [id], (err, row) => {
                res.json(row);
            });
        });
});

app.delete('/api/invoices/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM invoices WHERE id = ?', [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Errore eliminazione fattura' });
        }
        res.json({ message: 'Fattura eliminata con successo' });
    });
});

// ============= EXPENSES ROUTES =============

app.get('/api/companies/:companyId/expenses', authenticateToken, (req, res) => {
    db.all('SELECT * FROM expenses WHERE company_id = ? ORDER BY date DESC', [req.params.companyId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Errore recupero spese' });
        }
        res.json(rows);
    });
});

app.post('/api/companies/:companyId/expenses', authenticateToken, (req, res) => {
    const { companyId } = req.params;
    const { description, amount, category, date, notes } = req.body;

    db.run('INSERT INTO expenses (company_id, description, amount, category, date, notes) VALUES (?, ?, ?, ?, ?, ?)',
        [companyId, description, amount, category, date, notes],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore creazione spesa' });
            }
            db.get('SELECT * FROM expenses WHERE id = ?', [this.lastID], (err, row) => {
                res.status(201).json(row);
            });
        });
});

app.put('/api/expenses/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { description, amount, category, date, notes } = req.body;

    db.run('UPDATE expenses SET description = ?, amount = ?, category = ?, date = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [description, amount, category, date, notes, id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore aggiornamento spesa' });
            }
            db.get('SELECT * FROM expenses WHERE id = ?', [id], (err, row) => {
                res.json(row);
            });
        });
});

app.delete('/api/expenses/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM expenses WHERE id = ?', [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Errore eliminazione spesa' });
        }
        res.json({ message: 'Spesa eliminata con successo' });
    });
});

// ============= REMINDERS ROUTES =============

app.get('/api/companies/:companyId/reminders', authenticateToken, (req, res) => {
    db.all('SELECT * FROM reminders WHERE company_id = ? ORDER BY due_date ASC', [req.params.companyId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Errore recupero promemoria' });
        }
        res.json(rows);
    });
});

app.post('/api/companies/:companyId/reminders', authenticateToken, (req, res) => {
    const { companyId } = req.params;
    const { invoice_id, title, description, due_date, completed } = req.body;

    db.run('INSERT INTO reminders (company_id, invoice_id, title, description, due_date, completed) VALUES (?, ?, ?, ?, ?, ?)',
        [companyId, invoice_id, title, description, due_date, completed || 0],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore creazione promemoria' });
            }
            db.get('SELECT * FROM reminders WHERE id = ?', [this.lastID], (err, row) => {
                res.status(201).json(row);
            });
        });
});

app.put('/api/reminders/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { title, description, due_date, completed } = req.body;

    db.run('UPDATE reminders SET title = ?, description = ?, due_date = ?, completed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [title, description, due_date, completed, id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Errore aggiornamento promemoria' });
            }
            db.get('SELECT * FROM reminders WHERE id = ?', [id], (err, row) => {
                res.json(row);
            });
        });
});

app.delete('/api/reminders/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM reminders WHERE id = ?', [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Errore eliminazione promemoria' });
        }
        res.json({ message: 'Promemoria eliminato con successo' });
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 ========================================`);
    console.log(`   Numbers Server LOCALE running!`);
    console.log(`   http://localhost:${PORT}`);
    console.log(`========================================\n`);
    console.log(`📱 Apri nel browser:`);
    console.log(`   http://localhost:${PORT}/auth.html\n`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    db.close();
    process.exit(0);
});
