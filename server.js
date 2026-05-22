const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
require('dotenv').config();

// Multer: memory storage, 5MB max, only images/pdf
const receiptUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ok = /^image\/(png|jpe?g|gif|webp|heic|heif)$|^application\/pdf$/i.test(file.mimetype);
        if (!ok) return cb(new Error('Formato non supportato. Solo immagini o PDF.'));
        cb(null, true);
    }
});

// Configure SendGrid
if (process.env.SENDGRID_API_KEY) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

const app = express();
const PORT = process.env.PORT || 3000;

// CORS - solo origini autorizzate
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:3000'];

app.use(cors({
    origin: function (origin, callback) {
        // Permetti richieste senza origin (es. curl, Postman, same-origin)
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Non autorizzato da CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());
app.use(express.static('../frontend'));

// Rate limiting - protezione brute force
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minuti
    max: 20, // max 20 tentativi per finestra
    message: { error: 'Troppi tentativi. Riprova tra 15 minuti.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret - nessun fallback insicuro
if (!process.env.JWT_SECRET) {
    console.error('ERRORE: JWT_SECRET non configurato! Imposta la variabile d\'ambiente.');
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

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
app.post('/api/auth/register', authLimiter, [
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
        const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'Email già registrata' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create user
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name, created_at',
            [email, passwordHash, name]
        );

        const user = result.rows[0];

        // Generate token
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({ user, token });
    } catch (error) {
        console.error('Errore registrazione:', error);
        res.status(500).json({ error: 'Errore durante la registrazione' });
    }
});

// Login
app.post('/api/auth/login', authLimiter, [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        // Find user
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }

        const user = result.rows[0];

        // Check password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }

        // Generate token
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at
            },
            token
        });
    } catch (error) {
        console.error('Errore login:', error);
        res.status(500).json({ error: 'Errore durante il login' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, email, name, created_at FROM users WHERE id = $1',
            [req.user.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Utente non trovato' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Errore get user:', error);
        res.status(500).json({ error: 'Errore nel recupero utente' });
    }
});

// Forgot Password - Request reset
app.post('/api/auth/forgot-password', authLimiter, [
    body('email').isEmail().normalizeEmail()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
        // Find user
        const userResult = await pool.query('SELECT id, email, name FROM users WHERE email = $1', [email]);

        // Always return success (security: don't reveal if email exists)
        if (userResult.rows.length === 0) {
            return res.json({ message: 'Se l\'email esiste, riceverai un link per il reset della password' });
        }

        const user = userResult.rows[0];

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour

        // Save hashed token to database
        await pool.query(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.id, tokenHash, expiresAt]
        );

        // Send email with SendGrid
        if (process.env.SENDGRID_API_KEY) {
            const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password.html?token=${resetToken}`;

            // Escape user name per prevenire XSS nell'email
            const safeName = (user.name || 'User').replace(/[&<>"']/g, c => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            })[c]);

            const msg = {
                to: user.email,
                from: process.env.SENDGRID_FROM_EMAIL || 'noreply@numbers.app',
                subject: 'Reset Password - Numbers',
                html: `
                    <div style="font-family: 'Manrope', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #0A0A0A; color: #FFFFFF;">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <div style="display: inline-block; width: 56px; height: 56px; background: #00FF00; border-radius: 12px; line-height: 56px; font-size: 32px; font-weight: 900; color: #000;">N</div>
                            <h1 style="margin-top: 16px; font-size: 28px; font-weight: 800;">Numbers</h1>
                        </div>
                        <div style="background: #1A1A1A; border-radius: 16px; padding: 30px; border: 1px solid #2A2A2A;">
                            <h2 style="color: #00FF00; margin-bottom: 20px;">Reset Password</h2>
                            <p style="color: #A0A0A0; line-height: 1.6; margin-bottom: 20px;">
                                Ciao ${safeName},<br><br>
                                Hai richiesto di resettare la tua password. Clicca il pulsante qui sotto per procedere:
                            </p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="${resetUrl}" style="display: inline-block; background: #00FF00; color: #000000; padding: 14px 32px; text-decoration: none; border-radius: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">
                                    Reset Password
                                </a>
                            </div>
                            <p style="color: #A0A0A0; font-size: 14px; line-height: 1.6;">
                                Oppure copia questo link nel browser:<br>
                                <a href="${resetUrl}" style="color: #00FF00; word-break: break-all;">${resetUrl}</a>
                            </p>
                            <p style="color: #A0A0A0; font-size: 13px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #2A2A2A;">
                                Questo link scade tra 1 ora.<br>
                                Se non hai richiesto questo reset, ignora questa email.
                            </p>
                        </div>
                    </div>
                `
            };

            await sgMail.send(msg);
        }

        res.json({ message: 'Se l\'email esiste, riceverai un link per il reset della password' });
    } catch (error) {
        console.error('Errore forgot password:', error);
        res.status(500).json({ error: 'Errore durante la richiesta di reset' });
    }
});

// Reset Password - Verify token and update password
app.post('/api/auth/reset-password', authLimiter, [
    body('token').notEmpty(),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { token, newPassword } = req.body;

    try {
        // Hash the incoming token to compare with stored hash
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // Find valid token
        const tokenResult = await pool.query(
            'SELECT * FROM password_reset_tokens WHERE token = $1 AND used = FALSE AND expires_at > NOW()',
            [tokenHash]
        );

        if (tokenResult.rows.length === 0) {
            return res.status(400).json({ error: 'Token non valido o scaduto' });
        }

        const resetToken = tokenResult.rows[0];

        // Hash new password
        const passwordHash = await bcrypt.hash(newPassword, 10);

        // Update user password
        await pool.query(
            'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [passwordHash, resetToken.user_id]
        );

        // Mark token as used
        await pool.query(
            'UPDATE password_reset_tokens SET used = TRUE WHERE id = $1',
            [resetToken.id]
        );

        res.json({ message: 'Password aggiornata con successo' });
    } catch (error) {
        console.error('Errore reset password:', error);
        res.status(500).json({ error: 'Errore durante il reset della password' });
    }
});

// ============= COMPANIES ROUTES =============

// Get all companies for user
app.get('/api/companies', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM companies WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get companies:', error);
        res.status(500).json({ error: 'Errore nel recupero aziende' });
    }
});

// Create company
app.post('/api/companies', authenticateToken, [
    body('name').notEmpty().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, address, email, tax_id, payment_info } = req.body;

    try {
        const result = await pool.query(
            'INSERT INTO companies (user_id, name, address, email, tax_id, payment_info) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [req.user.id, name, address, email, tax_id, payment_info]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Errore create company:', error);
        res.status(500).json({ error: 'Errore nella creazione azienda' });
    }
});

// Update company
app.put('/api/companies/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, address, email, tax_id, payment_info } = req.body;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [id, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'UPDATE companies SET name = $1, address = $2, email = $3, tax_id = $4, payment_info = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 RETURNING *',
            [name, address, email, tax_id, payment_info, id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Errore update company:', error);
        res.status(500).json({ error: 'Errore nell\'aggiornamento azienda' });
    }
});

// Delete company
app.delete('/api/companies/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [id, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        await pool.query('DELETE FROM companies WHERE id = $1', [id]);
        res.json({ message: 'Azienda eliminata con successo' });
    } catch (error) {
        console.error('Errore delete company:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione azienda' });
    }
});

// ============= CUSTOMERS ROUTES =============

// Get all customers for company
app.get('/api/companies/:companyId/customers', authenticateToken, async (req, res) => {
    const { companyId } = req.params;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'SELECT * FROM customers WHERE company_id = $1 ORDER BY created_at DESC',
            [companyId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get customers:', error);
        res.status(500).json({ error: 'Errore nel recupero clienti' });
    }
});

// Create customer
app.post('/api/companies/:companyId/customers', authenticateToken, [
    body('name').notEmpty().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { companyId } = req.params;
    const { name, address, vat } = req.body;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'INSERT INTO customers (company_id, name, address, vat) VALUES ($1, $2, $3, $4) RETURNING *',
            [companyId, name, address, vat]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Errore create customer:', error);
        res.status(500).json({ error: 'Errore nella creazione cliente' });
    }
});

// Update customer
app.put('/api/customers/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, address, vat } = req.body;

    try {
        // Check ownership through company
        const check = await pool.query(
            'SELECT c.id FROM customers c JOIN companies co ON c.company_id = co.id WHERE c.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Cliente non trovato' });
        }

        const result = await pool.query(
            'UPDATE customers SET name = $1, address = $2, vat = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 RETURNING *',
            [name, address, vat, id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Errore update customer:', error);
        res.status(500).json({ error: 'Errore nell\'aggiornamento cliente' });
    }
});

// Delete customer
app.delete('/api/customers/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Check ownership through company
        const check = await pool.query(
            'SELECT c.id FROM customers c JOIN companies co ON c.company_id = co.id WHERE c.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Cliente non trovato' });
        }

        // Set customer_id to NULL on invoices before deleting (preserve invoice history)
        await pool.query('UPDATE invoices SET customer_id = NULL WHERE customer_id = $1', [id]);
        await pool.query('DELETE FROM customers WHERE id = $1', [id]);
        res.json({ message: 'Cliente eliminato con successo' });
    } catch (error) {
        console.error('Errore delete customer:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione cliente' });
    }
});

// ============= INVOICES ROUTES =============

// Get all invoices for company
app.get('/api/companies/:companyId/invoices', authenticateToken, async (req, res) => {
    const { companyId } = req.params;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'SELECT i.*, c.name as customer_name FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.company_id = $1 ORDER BY i.date DESC',
            [companyId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get invoices:', error);
        res.status(500).json({ error: 'Errore nel recupero fatture' });
    }
});

// Create invoice
app.post('/api/companies/:companyId/invoices', authenticateToken, async (req, res) => {
    const { companyId } = req.params;
    const { customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes, currency } = req.body;

    // Validazione numerica
    if (isNaN(parseFloat(subtotal)) || isNaN(parseFloat(total))) {
        return res.status(400).json({ error: 'Subtotale e totale devono essere numeri validi' });
    }

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'INSERT INTO invoices (company_id, customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes, currency) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *',
            [companyId, customer_id, invoice_number, date, due_date, JSON.stringify(items), subtotal, tax, total, status, notes, currency || 'EUR']
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Errore create invoice:', error);
        res.status(500).json({ error: 'Errore nella creazione fattura' });
    }
});

// Update invoice
app.put('/api/invoices/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes, currency } = req.body;

    // Validazione numerica
    if (isNaN(parseFloat(subtotal)) || isNaN(parseFloat(total))) {
        return res.status(400).json({ error: 'Subtotale e totale devono essere numeri validi' });
    }

    try {
        // Check ownership
        const check = await pool.query(
            'SELECT i.id FROM invoices i JOIN companies co ON i.company_id = co.id WHERE i.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Fattura non trovata' });
        }

        const result = await pool.query(
            'UPDATE invoices SET customer_id = $1, invoice_number = $2, date = $3, due_date = $4, items = $5, subtotal = $6, tax = $7, total = $8, status = $9, notes = $10, currency = $11, updated_at = CURRENT_TIMESTAMP WHERE id = $12 RETURNING *',
            [customer_id, invoice_number, date, due_date, JSON.stringify(items), subtotal, tax, total, status, notes, currency || 'EUR', id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Errore update invoice:', error);
        res.status(500).json({ error: 'Errore nell\'aggiornamento fattura' });
    }
});

// Delete invoice
app.delete('/api/invoices/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Check ownership
        const check = await pool.query(
            'SELECT i.id FROM invoices i JOIN companies co ON i.company_id = co.id WHERE i.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Fattura non trovata' });
        }

        // Set invoice_id to NULL on reminders before deleting (preserve reminder history)
        await pool.query('UPDATE reminders SET invoice_id = NULL WHERE invoice_id = $1', [id]);
        // Rimuovi le spese-rimborso automatiche delle note collegate e riporta le note "in sospeso"
        await pool.query(`DELETE FROM expenses WHERE expense_note_id IN (SELECT id FROM expense_notes WHERE invoice_id = $1)`, [id]);
        await pool.query('UPDATE expense_notes SET completed = FALSE, invoice_id = NULL WHERE invoice_id = $1', [id]);
        await pool.query('DELETE FROM invoices WHERE id = $1', [id]);
        res.json({ message: 'Fattura eliminata con successo' });
    } catch (error) {
        console.error('Errore delete invoice:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione fattura' });
    }
});

// ============= EXPENSES ROUTES =============

// Get all expenses for company
app.get('/api/companies/:companyId/expenses', authenticateToken, async (req, res) => {
    const { companyId } = req.params;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'SELECT * FROM expenses WHERE company_id = $1 ORDER BY date DESC',
            [companyId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get expenses:', error);
        res.status(500).json({ error: 'Errore nel recupero spese' });
    }
});

// Create expense
app.post('/api/companies/:companyId/expenses', authenticateToken, async (req, res) => {
    const { companyId } = req.params;
    const { description, amount, category, date, notes } = req.body;

    if (!description || !description.trim()) {
        return res.status(400).json({ error: 'La descrizione è obbligatoria' });
    }
    if (isNaN(parseFloat(amount)) || parseFloat(amount) < 0) {
        return res.status(400).json({ error: 'L\'importo deve essere un numero valido' });
    }

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'INSERT INTO expenses (company_id, description, amount, category, date, notes) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [companyId, description, amount, category, date, notes]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Errore create expense:', error);
        res.status(500).json({ error: 'Errore nella creazione spesa' });
    }
});

// Update expense
app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { description, amount, category, date, notes } = req.body;

    if (isNaN(parseFloat(amount)) || parseFloat(amount) < 0) {
        return res.status(400).json({ error: 'L\'importo deve essere un numero valido' });
    }

    try {
        // Check ownership
        const check = await pool.query(
            'SELECT e.id FROM expenses e JOIN companies co ON e.company_id = co.id WHERE e.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Spesa non trovata' });
        }

        const result = await pool.query(
            'UPDATE expenses SET description = $1, amount = $2, category = $3, date = $4, notes = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 RETURNING *',
            [description, amount, category, date, notes, id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Errore update expense:', error);
        res.status(500).json({ error: 'Errore nell\'aggiornamento spesa' });
    }
});

// Delete expense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Check ownership
        const check = await pool.query(
            'SELECT e.id FROM expenses e JOIN companies co ON e.company_id = co.id WHERE e.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Spesa non trovata' });
        }

        await pool.query('DELETE FROM expenses WHERE id = $1', [id]);
        res.json({ message: 'Spesa eliminata con successo' });
    } catch (error) {
        console.error('Errore delete expense:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione spesa' });
    }
});

// ============= REMINDERS ROUTES =============

// Get all reminders for company
app.get('/api/companies/:companyId/reminders', authenticateToken, async (req, res) => {
    const { companyId } = req.params;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'SELECT * FROM reminders WHERE company_id = $1 ORDER BY due_date ASC',
            [companyId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get reminders:', error);
        res.status(500).json({ error: 'Errore nel recupero promemoria' });
    }
});

// Create reminder
app.post('/api/companies/:companyId/reminders', authenticateToken, async (req, res) => {
    const { companyId } = req.params;
    const { invoice_id, title, description, due_date, completed } = req.body;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'INSERT INTO reminders (company_id, invoice_id, title, description, due_date, completed) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [companyId, invoice_id, title, description, due_date, completed || false]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Errore create reminder:', error);
        res.status(500).json({ error: 'Errore nella creazione promemoria' });
    }
});

// Update reminder
app.put('/api/reminders/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, due_date, completed } = req.body;

    try {
        // Check ownership
        const check = await pool.query(
            'SELECT r.id FROM reminders r JOIN companies co ON r.company_id = co.id WHERE r.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Promemoria non trovato' });
        }

        const result = await pool.query(
            'UPDATE reminders SET title = $1, description = $2, due_date = $3, completed = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 RETURNING *',
            [title, description, due_date, completed, id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Errore update reminder:', error);
        res.status(500).json({ error: 'Errore nell\'aggiornamento promemoria' });
    }
});

// Delete reminder
app.delete('/api/reminders/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Check ownership
        const check = await pool.query(
            'SELECT r.id FROM reminders r JOIN companies co ON r.company_id = co.id WHERE r.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Promemoria non trovato' });
        }

        await pool.query('DELETE FROM reminders WHERE id = $1', [id]);
        res.json({ message: 'Promemoria eliminato con successo' });
    } catch (error) {
        console.error('Errore delete reminder:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione promemoria' });
    }
});

// ============= EXPENSE NOTES (RIMBORSI) ROUTES =============

// Get all expense notes for company
app.get('/api/companies/:companyId/expense-notes', authenticateToken, async (req, res) => {
    const { companyId } = req.params;
    try {
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }
        const result = await pool.query(
            `SELECT n.*, COALESCE(r.cnt, 0)::int AS receipts_count
             FROM expense_notes n
             LEFT JOIN (SELECT expense_note_id, COUNT(*) AS cnt FROM expense_note_receipts GROUP BY expense_note_id) r
               ON r.expense_note_id = n.id
             WHERE n.company_id = $1
             ORDER BY n.created_at DESC`,
            [companyId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get expense notes:', error);
        res.status(500).json({ error: 'Errore nel recupero note spese' });
    }
});

// Create expense note
app.post('/api/companies/:companyId/expense-notes', authenticateToken, async (req, res) => {
    const { companyId } = req.params;
    const { description, amount, action_type, customer_name, date, notes } = req.body;
    try {
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }
        const result = await pool.query(
            'INSERT INTO expense_notes (company_id, description, amount, action_type, customer_name, date, notes, completed) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE) RETURNING *',
            [companyId, description, amount, action_type || 'reimburse', customer_name, date, notes]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Errore create expense note:', error);
        res.status(500).json({ error: 'Errore nella creazione nota spesa' });
    }
});

// Update expense note
app.put('/api/expense-notes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { description, amount, action_type, customer_name, date, notes, completed, invoice_id } = req.body;
    try {
        const check = await pool.query(
            'SELECT n.id FROM expense_notes n JOIN companies co ON n.company_id = co.id WHERE n.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Nota spesa non trovata' });
        }
        const result = await pool.query(
            'UPDATE expense_notes SET description = $1, amount = $2, action_type = $3, customer_name = $4, date = $5, notes = $6, completed = $7, invoice_id = $8, updated_at = CURRENT_TIMESTAMP WHERE id = $9 RETURNING *',
            [description, amount, action_type, customer_name, date, notes, completed, invoice_id !== undefined ? invoice_id : null, id]
        );
        const note = result.rows[0];

        // Sincronizza la voce di spesa automatica collegata alla nota
        await syncReimbursementExpense(note);

        res.json(note);
    } catch (error) {
        console.error('Errore update expense note:', error);
        res.status(500).json({ error: 'Errore nell\'aggiornamento nota spesa' });
    }
});

// Crea/aggiorna/elimina la voce di spesa automatica per una nota fatturata
async function syncReimbursementExpense(note) {
    try {
        if (note.completed && note.action_type === 'invoice' && note.invoice_id) {
            const invRes = await pool.query('SELECT invoice_number FROM invoices WHERE id = $1', [note.invoice_id]);
            const invNum = invRes.rows[0] ? invRes.rows[0].invoice_number : note.invoice_id;
            const desc = ('Spese rimborsate Fatt. #' + invNum + ' - ' + note.description).substring(0, 255);
            const expDate = note.date || new Date();
            const existing = await pool.query('SELECT id FROM expenses WHERE expense_note_id = $1', [note.id]);
            if (existing.rows.length) {
                await pool.query(
                    'UPDATE expenses SET description = $1, amount = $2, category = $3, date = $4, updated_at = CURRENT_TIMESTAMP WHERE expense_note_id = $5',
                    [desc, note.amount, 'Rimborso fatturato', expDate, note.id]
                );
            } else {
                await pool.query(
                    'INSERT INTO expenses (company_id, description, amount, category, date, expense_note_id) VALUES ($1, $2, $3, $4, $5, $6)',
                    [note.company_id, desc, note.amount, 'Rimborso fatturato', expDate, note.id]
                );
            }
        } else {
            // Non più fatturata: rimuovi la spesa collegata se esiste
            await pool.query('DELETE FROM expenses WHERE expense_note_id = $1', [note.id]);
        }
    } catch (e) {
        console.error('Errore sync spesa rimborso:', e.message);
    }
}

// Delete expense note
app.delete('/api/expense-notes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const check = await pool.query(
            'SELECT n.id FROM expense_notes n JOIN companies co ON n.company_id = co.id WHERE n.id = $1 AND co.user_id = $2',
            [id, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Nota spesa non trovata' });
        }
        await pool.query('DELETE FROM expense_notes WHERE id = $1', [id]);
        res.json({ message: 'Nota spesa eliminata con successo' });
    } catch (error) {
        console.error('Errore delete expense note:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione nota spesa' });
    }
});

// ============= EXPENSE NOTE RECEIPTS ROUTES =============

// Helper: verify expense note belongs to authenticated user
async function checkNoteOwnership(noteId, userId) {
    const r = await pool.query(
        'SELECT n.id FROM expense_notes n JOIN companies co ON n.company_id = co.id WHERE n.id = $1 AND co.user_id = $2',
        [noteId, userId]
    );
    return r.rows.length > 0;
}

// List receipts for a note (metadata only, no blob)
app.get('/api/expense-notes/:id/receipts', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        if (!(await checkNoteOwnership(id, req.user.id))) {
            return res.status(404).json({ error: 'Nota spesa non trovata' });
        }
        const result = await pool.query(
            'SELECT id, filename, mime_type, size_bytes, created_at FROM expense_note_receipts WHERE expense_note_id = $1 ORDER BY created_at ASC',
            [id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get receipts:', error);
        res.status(500).json({ error: 'Errore nel recupero ricevute' });
    }
});

// Upload one or more receipts for a note
app.post('/api/expense-notes/:id/receipts', authenticateToken, (req, res) => {
    receiptUpload.array('files', 10)(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });
        const { id } = req.params;
        try {
            if (!(await checkNoteOwnership(id, req.user.id))) {
                return res.status(404).json({ error: 'Nota spesa non trovata' });
            }
            if (!req.files || req.files.length === 0) {
                return res.status(400).json({ error: 'Nessun file caricato' });
            }
            const inserted = [];
            for (const f of req.files) {
                const r = await pool.query(
                    'INSERT INTO expense_note_receipts (expense_note_id, filename, mime_type, size_bytes, file_data) VALUES ($1, $2, $3, $4, $5) RETURNING id, filename, mime_type, size_bytes, created_at',
                    [id, f.originalname, f.mimetype, f.size, f.buffer]
                );
                inserted.push(r.rows[0]);
            }
            res.status(201).json(inserted);
        } catch (error) {
            console.error('Errore upload receipts:', error);
            res.status(500).json({ error: 'Errore nel caricamento ricevute' });
        }
    });
});

// List all receipts attached to expense notes linked to an invoice
app.get('/api/invoices/:invoiceId/receipts', authenticateToken, async (req, res) => {
    const { invoiceId } = req.params;
    try {
        const check = await pool.query(
            'SELECT i.id FROM invoices i JOIN companies co ON i.company_id = co.id WHERE i.id = $1 AND co.user_id = $2',
            [invoiceId, req.user.id]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Fattura non trovata' });
        }
        const result = await pool.query(
            `SELECT r.id, r.filename, r.mime_type, r.size_bytes, n.description AS note_description
             FROM expense_note_receipts r
             JOIN expense_notes n ON r.expense_note_id = n.id
             WHERE n.invoice_id = $1
             ORDER BY r.created_at ASC`,
            [invoiceId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Errore get invoice receipts:', error);
        res.status(500).json({ error: 'Errore nel recupero ricevute fattura' });
    }
});

// Download a single receipt (returns the file inline)
app.get('/api/receipts/:receiptId', authenticateToken, async (req, res) => {
    const { receiptId } = req.params;
    try {
        const r = await pool.query(
            `SELECT r.filename, r.mime_type, r.file_data
             FROM expense_note_receipts r
             JOIN expense_notes n ON r.expense_note_id = n.id
             JOIN companies co ON n.company_id = co.id
             WHERE r.id = $1 AND co.user_id = $2`,
            [receiptId, req.user.id]
        );
        if (r.rows.length === 0) {
            return res.status(404).json({ error: 'Ricevuta non trovata' });
        }
        const row = r.rows[0];
        res.setHeader('Content-Type', row.mime_type);
        res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(row.filename)}"`);
        res.send(row.file_data);
    } catch (error) {
        console.error('Errore download receipt:', error);
        res.status(500).json({ error: 'Errore nel download ricevuta' });
    }
});

// Delete a receipt
app.delete('/api/receipts/:receiptId', authenticateToken, async (req, res) => {
    const { receiptId } = req.params;
    try {
        const r = await pool.query(
            `SELECT r.id FROM expense_note_receipts r
             JOIN expense_notes n ON r.expense_note_id = n.id
             JOIN companies co ON n.company_id = co.id
             WHERE r.id = $1 AND co.user_id = $2`,
            [receiptId, req.user.id]
        );
        if (r.rows.length === 0) {
            return res.status(404).json({ error: 'Ricevuta non trovata' });
        }
        await pool.query('DELETE FROM expense_note_receipts WHERE id = $1', [receiptId]);
        res.json({ message: 'Ricevuta eliminata' });
    } catch (error) {
        console.error('Errore delete receipt:', error);
        res.status(500).json({ error: 'Errore nell\'eliminazione ricevuta' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Root route
app.get('/', (req, res) => {
    res.json({
        message: 'Numbers API Server',
        version: '1.0.0',
        endpoints: ['/api/auth/register', '/api/auth/login', '/api/health']
    });
});

// Migrations
async function runMigrations() {
    const results = [];

    // Migration 1: invoices.customer_id → allow NULL, SET NULL on customer delete
    try {
        await pool.query(`ALTER TABLE invoices ALTER COLUMN customer_id DROP NOT NULL`);
        results.push('M1a: customer_id NOT NULL dropped');
    } catch (e) { results.push('M1a skipped: ' + e.message); }
    try {
        await pool.query(`ALTER TABLE invoices DROP CONSTRAINT IF EXISTS invoices_customer_id_fkey`);
        results.push('M1b: old fkey dropped');
    } catch (e) { results.push('M1b skipped: ' + e.message); }
    try {
        await pool.query(`ALTER TABLE invoices ADD CONSTRAINT invoices_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL`);
        results.push('M1c: new fkey SET NULL added ✅');
    } catch (e) { results.push('M1c skipped: ' + e.message); }

    // Migration 2: invoices.currency → aggiunge colonna currency
    try {
        await pool.query(`ALTER TABLE invoices ADD COLUMN currency VARCHAR(10) DEFAULT 'EUR'`);
        results.push('M2: currency column added');
    } catch (e) { results.push('M2 skipped: ' + e.message); }

    // Migration 3: reminders.invoice_id → allow NULL, SET NULL on invoice delete
    try {
        await pool.query(`ALTER TABLE reminders ALTER COLUMN invoice_id DROP NOT NULL`);
        results.push('M2a: invoice_id NOT NULL dropped');
    } catch (e) { results.push('M2a skipped: ' + e.message); }
    try {
        await pool.query(`ALTER TABLE reminders DROP CONSTRAINT IF EXISTS reminders_invoice_id_fkey`);
        results.push('M2b: old fkey dropped');
    } catch (e) { results.push('M2b skipped: ' + e.message); }
    try {
        await pool.query(`ALTER TABLE reminders ADD CONSTRAINT reminders_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE SET NULL`);
        results.push('M2c: new fkey SET NULL added ✅');
    } catch (e) { results.push('M2c skipped: ' + e.message); }

    // Migration 6: expense_notes.invoice_id → collega nota alla fattura
    try {
        await pool.query(`ALTER TABLE expense_notes ADD COLUMN IF NOT EXISTS invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL`);
        results.push('M6: expense_notes.invoice_id added ✅');
    } catch (e) { results.push('M6 skipped: ' + e.message); }

    // Migration 5: expense_note_receipts table (file BLOBs)
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS expense_note_receipts (
            id SERIAL PRIMARY KEY,
            expense_note_id INTEGER NOT NULL REFERENCES expense_notes(id) ON DELETE CASCADE,
            filename VARCHAR(255) NOT NULL,
            mime_type VARCHAR(100) NOT NULL,
            size_bytes INTEGER NOT NULL,
            file_data BYTEA NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_receipts_note_id ON expense_note_receipts(expense_note_id)`);
        results.push('M5: expense_note_receipts table created ✅');
    } catch (e) { results.push('M5 skipped: ' + e.message); }

    // Migration 4: expense_notes table
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS expense_notes (
            id SERIAL PRIMARY KEY,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            description VARCHAR(255) NOT NULL,
            amount DECIMAL(10, 2) NOT NULL,
            action_type VARCHAR(50) DEFAULT 'reimburse',
            customer_name VARCHAR(255),
            date DATE,
            notes TEXT,
            completed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        results.push('M4: expense_notes table created');
    } catch (e) { results.push('M4 skipped: ' + e.message); }

    // Migration 7: expenses.expense_note_id → spesa automatica collegata alla nota fatturata (dopo M4/M5/M6)
    try {
        await pool.query(`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS expense_note_id INTEGER REFERENCES expense_notes(id) ON DELETE CASCADE`);
        results.push('M7a: expenses.expense_note_id added ✅');
    } catch (e) { results.push('M7a skipped: ' + e.message); }
    // Backfill: crea spese per le note gia' fatturate che non ce l'hanno ancora
    try {
        const bf = await pool.query(`
            INSERT INTO expenses (company_id, description, amount, category, date, expense_note_id)
            SELECT n.company_id,
                   LEFT('Spese rimborsate Fatt. #' || COALESCE(i.invoice_number, n.invoice_id::text) || ' - ' || n.description, 255),
                   n.amount, 'Rimborso fatturato',
                   COALESCE(n.date, n.created_at::date, CURRENT_DATE),
                   n.id
            FROM expense_notes n
            LEFT JOIN invoices i ON n.invoice_id = i.id
            WHERE n.completed = TRUE AND n.action_type = 'invoice' AND n.invoice_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM expenses e WHERE e.expense_note_id = n.id)
            RETURNING id`);
        results.push('M7b: backfill rimborsi -> ' + bf.rowCount + ' spese create ✅');
    } catch (e) { results.push('M7b skipped: ' + e.message); }

    console.log('Migrations:', results.join(' | '));
    return results;
}

// Manual migration endpoint (protetto, solo con autenticazione)
app.get('/api/migrate', authenticateToken, async (req, res) => {
    const results = await runMigrations();
    res.json({ results });
});

// Start server
const server = app.listen(PORT, async () => {
    console.log(`Numbers server running on port ${PORT}`);
    await runMigrations();
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        pool.end();
        process.exit(0);
    });
});
