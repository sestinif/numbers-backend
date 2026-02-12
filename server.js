const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

// Configure SendGrid
if (process.env.SENDGRID_API_KEY) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('../frontend'));

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

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
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({ user, token });
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
app.post('/api/auth/forgot-password', [
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
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour

        // Save token to database
        await pool.query(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.id, resetToken, expiresAt]
        );

        // Send email with SendGrid
        if (process.env.SENDGRID_API_KEY) {
            const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password.html?token=${resetToken}`;

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
                                Ciao ${user.name || 'User'},<br><br>
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
                                ⚠️ Questo link scade tra 1 ora.<br>
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
app.post('/api/auth/reset-password', [
    body('token').notEmpty(),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { token, newPassword } = req.body;

    try {
        // Find valid token
        const tokenResult = await pool.query(
            'SELECT * FROM password_reset_tokens WHERE token = $1 AND used = FALSE AND expires_at > NOW()',
            [token]
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
            'SELECT i.*, c.name as customer_name FROM invoices i JOIN customers c ON i.customer_id = c.id WHERE i.company_id = $1 ORDER BY i.date DESC',
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
    const { customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes } = req.body;

    try {
        // Check ownership
        const check = await pool.query('SELECT id FROM companies WHERE id = $1 AND user_id = $2', [companyId, req.user.id]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: 'Azienda non trovata' });
        }

        const result = await pool.query(
            'INSERT INTO invoices (company_id, customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *',
            [companyId, customer_id, invoice_number, date, due_date, JSON.stringify(items), subtotal, tax, total, status, notes]
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
    const { customer_id, invoice_number, date, due_date, items, subtotal, tax, total, status, notes } = req.body;

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
            'UPDATE invoices SET customer_id = $1, invoice_number = $2, date = $3, due_date = $4, items = $5, subtotal = $6, tax = $7, total = $8, status = $9, notes = $10, updated_at = CURRENT_TIMESTAMP WHERE id = $11 RETURNING *',
            [customer_id, invoice_number, date, due_date, JSON.stringify(items), subtotal, tax, total, status, notes, id]
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

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Numbers server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    pool.end();
    process.exit(0);
});
