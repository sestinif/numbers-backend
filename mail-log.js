// Numbers — registro delle email partite da Numbers.
//
// Ogni email inviata lascia una riga: a chi, oggetto, quando, quali allegati. Serve a Federico
// per vedere cosa è partito senza aprire Gmail, e a fermare l'invio oltre il tetto del giorno.
// Il testo completo NON si salva qui (sta negli «Inviati» della casella): solo l'inizio.

const EXCERPT_CHARS = 400;

async function ensureTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS sent_emails (
            id SERIAL PRIMARY KEY,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            recipients TEXT NOT NULL,
            subject VARCHAR(300) NOT NULL,
            excerpt TEXT,
            attachments TEXT,
            invoice_id INTEGER,
            gmail_id VARCHAR(64),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sent_emails_company ON sent_emails(company_id, created_at DESC)`);
}

async function countToday(pool, companyId) {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM sent_emails WHERE company_id = $1 AND created_at >= CURRENT_DATE`, [companyId]);
    return r.rows[0].n;
}

async function record(pool, companyId, { to, subject, text, attachments, invoiceId, gmailId }) {
    const r = await pool.query(
        `INSERT INTO sent_emails (company_id, recipients, subject, excerpt, attachments, invoice_id, gmail_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [companyId, to.join(', '), String(subject).trim().slice(0, 300), String(text).trim().slice(0, EXCERPT_CHARS),
         (attachments || []).map(a => a.filename).join(', ') || null,
         Number.isInteger(Number(invoiceId)) && Number(invoiceId) > 0 ? Number(invoiceId) : null, gmailId || null]
    );
    return r.rows[0];
}

async function list(pool, companyId, limit = 100) {
    const r = await pool.query(
        `SELECT id, recipients, subject, excerpt, attachments, invoice_id, created_at
         FROM sent_emails WHERE company_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
        [companyId, limit]
    );
    return r.rows;
}

module.exports = { ensureTable, countToday, record, list };
