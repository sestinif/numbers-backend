// Numbers — i prelievi: quanto esce dal conto business verso i conti personali di Federico.
//
// Serve a una stima per eccesso di quanto spende nel mese: se bonifica 100 € su Revolut e ne
// spende 80, il conteggio dice 100. Lo vuole così (21/10/2026: «una stima per eccesso, ma sti cazzi»).
//
// Cosa conta lo decide lui, beneficiario per beneficiario, in «Nomi beneficiari»:
//   «Sì, tutto»  → il bonifico conta per intero (Revolut Personale);
//   «Sì, metà»   → conta per metà (l'affitto, che divide in due);
//   «No»         → non conta (Intesa, fornitori, tutto il resto).
// La percentuale si applica quando si legge il totale, non quando si registra il bonifico:
// se cambia idea su un beneficiario, i mesi già registrati si ricalcolano da soli.
//
// Si parte dal 1 novembre 2026. Prima di quella data niente conta.
//
// Da dove arrivano i bonifici:
//   - quelli fatti da Numbers, appena risultano partiti (recordPaid);
//   - quelli fatti dall'app di Wise, leggendo l'estratto del conto (syncFromStatement). Se Wise
//     non lascia leggere l'estratto, contano solo quelli fatti da Numbers, e lo si dice.
// Il bonifico si registra una volta sola: la chiave è il numero del bonifico su Wise.
//
// A leggere i totali è Personals, con una chiave sua di sola lettura (NUMBERS_EXPORT_KEY).

const crypto = require('node:crypto');

const START_DATE = '2026-11-01';
const START_MONTH = '2026-11';
const MIN_KEY_LENGTH = 24;
const MAX_NEW_PER_SYNC = 40; // bonifici nuovi guardati a ogni lettura dell'estratto: il resto alla prossima

// ===== Funzioni pure =====

function dayInRome(value) {
    const d = value instanceof Date ? value : new Date(value);
    if (!value || isNaN(d.getTime())) return null;
    // en-CA scrive la data come AAAA-MM-GG.
    return new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Rome', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
}

function isInScope(day) {
    return typeof day === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(day) && day >= START_DATE;
}

function isMonth(value) {
    return typeof value === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(value);
}

function monthInScope(month) {
    return isMonth(month) && month >= START_MONTH;
}

function currentMonth(now = new Date()) {
    return dayInRome(now).slice(0, 7);
}

function shareFrom(value) {
    if (value === 'all' || value === 1 || value === '1' || value === '1.00') return 1;
    if (value === 'half' || value === 0.5 || value === '0.5' || value === '0.50') return 0.5;
    return null;
}

function shareName(value) {
    const share = shareFrom(typeof value === 'string' && /^[\d.]+$/.test(value) ? value : value);
    return share === 1 ? 'all' : share === 0.5 ? 'half' : 'none';
}

function transferIdFromReference(ref) {
    const m = /^TRANSFER-(\d+)$/.exec(String(ref == null ? '' : ref));
    return m ? Number(m[1]) : null;
}

function counted(amountEur, share) {
    if (share == null) return 0;
    return Math.round(Number(amountEur) * Number(share) * 100) / 100;
}

// items: [{ date, label, amount_eur, share, … }] → riepilogo del mese con la cifra che conta di ognuno.
function summarize(items, month) {
    const rows = items.map(i => ({ ...i, counted_eur: counted(i.amount_eur, i.share) }));
    const total = Math.round(rows.reduce((sum, r) => sum + r.counted_eur, 0) * 100) / 100;
    return { month, total_eur: total, items: rows };
}

function exportEnabled(env) {
    const key = env && typeof env.NUMBERS_EXPORT_KEY === 'string' ? env.NUMBERS_EXPORT_KEY.trim() : '';
    return key.length >= MIN_KEY_LENGTH;
}

// Confronto a tempo costante e senza rivelare la lunghezza (impronte SHA-256).
function keyMatches(input, env) {
    if (!exportEnabled(env)) return false;
    const given = typeof input === 'string' ? input.trim() : '';
    if (!given) return false;
    const a = crypto.createHash('sha256').update(given, 'utf8').digest();
    const b = crypto.createHash('sha256').update(env.NUMBERS_EXPORT_KEY.trim(), 'utf8').digest();
    return crypto.timingSafeEqual(a, b);
}

// ===== Database =====

async function ensureTables(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS wise_outgoing (
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            transfer_id BIGINT NOT NULL,
            transfer_date DATE NOT NULL,
            recipient_id BIGINT NOT NULL,
            recipient_name VARCHAR(255),
            target_amount NUMERIC(14, 2) NOT NULL,
            target_currency VARCHAR(3) NOT NULL,
            amount_eur NUMERIC(14, 2) NOT NULL,
            source VARCHAR(12) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (company_id, transfer_id)
        )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_wise_outgoing_date ON wise_outgoing(company_id, transfer_date)`);
    await pool.query(`ALTER TABLE wise_recipient_labels ADD COLUMN IF NOT EXISTS withdrawal_share NUMERIC(3, 2)`);
}

async function toEur(amount, currency, day, toEurRate) {
    if (currency === 'EUR') return Math.round(Number(amount) * 100) / 100;
    const rate = await toEurRate(currency, 'latest');
    return Math.round(Number(amount) * rate.rate * 100) / 100;
}

// Registra un bonifico in uscita. true se è nuovo, false se c'era già o è fuori periodo.
async function recordOutgoing(pool, companyId, t, toEurRate) {
    if (!isInScope(t.day)) return false;
    const amountEur = await toEur(t.targetAmount, t.targetCurrency, t.day, toEurRate);
    const r = await pool.query(
        `INSERT INTO wise_outgoing (company_id, transfer_id, transfer_date, recipient_id, recipient_name, target_amount, target_currency, amount_eur, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (company_id, transfer_id) DO NOTHING`,
        [companyId, t.transferId, t.day, t.recipientId, (t.recipientName || '').slice(0, 255), t.targetAmount, t.targetCurrency, amountEur, t.source]
    );
    return r.rowCount > 0;
}

// Un bonifico di Numbers appena partito: da registrare. `row` è una riga di wise_payments.
async function recordPaid(pool, row, toEurRate, now = new Date()) {
    return recordOutgoing(pool, row.company_id, {
        transferId: row.wise_transfer_id,
        day: dayInRome(now),
        recipientId: row.recipient_id,
        recipientName: row.recipient_name,
        targetAmount: row.target_amount,
        targetCurrency: row.target_currency,
        source: 'numbers',
    }, toEurRate);
}

// Legge l'estratto di ogni saldo e registra i bonifici in uscita che non conosce ancora.
// Ritorna { added, error }: se Wise non lascia leggere l'estratto, error dice perché e non si rompe niente.
async function syncFromStatement(pool, client, companyId, toEurRate, now = new Date()) {
    const out = { added: 0, error: null };
    // Prima del 1 novembre non c'è niente da leggere (e Wise rifiuterebbe un periodo che parte nel futuro).
    if (!isInScope(dayInRome(now))) return out;
    try {
        const known = new Set((await pool.query(`SELECT transfer_id FROM wise_outgoing WHERE company_id = $1`, [companyId])).rows.map(r => String(r.transfer_id)));
        const names = new Map((await client.recipients()).map(r => [String(r.id), r.name]));
        const balances = await client.balances();
        for (const balance of balances) {
            const lines = await client.statement(balance.id, balance.currency, `${START_DATE}T00:00:00.000Z`, now.toISOString());
            for (const line of lines) {
                if (known.has(String(line.transferId))) continue;
                if (out.added >= MAX_NEW_PER_SYNC) return out;
                const day = dayInRome(line.date);
                if (!isInScope(day)) continue;
                const transfer = await client.getTransfer(line.transferId);
                if (!transfer || !transfer.targetAccount) continue;
                const isNew = await recordOutgoing(pool, companyId, {
                    transferId: line.transferId,
                    day,
                    recipientId: transfer.targetAccount,
                    recipientName: names.get(String(transfer.targetAccount)) || '',
                    targetAmount: transfer.targetValue,
                    targetCurrency: transfer.targetCurrency,
                    source: 'statement',
                }, toEurRate);
                known.add(String(line.transferId));
                if (isNew) out.added++;
            }
        }
    } catch (e) {
        out.error = e && e.message ? e.message : 'Errore nella lettura dell\'estratto';
    }
    return out;
}

// I bonifici del mese che contano, ognuno con il nome dato al beneficiario e la sua percentuale.
async function monthItems(pool, companyId, month) {
    const r = await pool.query(
        `SELECT to_char(o.transfer_date, 'YYYY-MM-DD') AS date, o.transfer_id, o.recipient_name, o.amount_eur,
                o.target_amount, o.target_currency, o.source, l.label, l.withdrawal_share AS share
         FROM wise_outgoing o
         JOIN wise_recipient_labels l ON l.company_id = o.company_id AND l.recipient_id = o.recipient_id
         WHERE o.company_id = $1 AND to_char(o.transfer_date, 'YYYY-MM') = $2 AND l.withdrawal_share IS NOT NULL
         ORDER BY o.transfer_date DESC, o.transfer_id DESC`,
        [companyId, month]
    );
    return r.rows.map(row => ({
        date: row.date,
        transfer_id: String(row.transfer_id),
        name: row.label || row.recipient_name || '',
        amount_eur: Number(row.amount_eur),
        share: Number(row.share),
        source: row.source,
    }));
}

// Bonifici del mese verso beneficiari che non contano (o senza una quota scelta): solo per far vedere che ci sono.
async function monthNotCounted(pool, companyId, month) {
    const r = await pool.query(
        `SELECT COUNT(*)::int AS n, COALESCE(SUM(o.amount_eur), 0) AS total
         FROM wise_outgoing o
         LEFT JOIN wise_recipient_labels l ON l.company_id = o.company_id AND l.recipient_id = o.recipient_id
         WHERE o.company_id = $1 AND to_char(o.transfer_date, 'YYYY-MM') = $2 AND l.withdrawal_share IS NULL`,
        [companyId, month]
    );
    return { count: r.rows[0].n, total_eur: Math.round(Number(r.rows[0].total) * 100) / 100 };
}

// Tutti i prelievi che contano, da novembre 2026 in poi: li usa la Dashboard di Numbers per i «compensi personali».
async function allItems(pool, companyId) {
    const r = await pool.query(
        `SELECT to_char(o.transfer_date, 'YYYY-MM-DD') AS date, o.transfer_id, o.recipient_name, o.amount_eur, l.label, l.withdrawal_share AS share
         FROM wise_outgoing o
         JOIN wise_recipient_labels l ON l.company_id = o.company_id AND l.recipient_id = o.recipient_id
         WHERE o.company_id = $1 AND o.transfer_date >= $2 AND l.withdrawal_share IS NOT NULL
         ORDER BY o.transfer_date DESC, o.transfer_id DESC`,
        [companyId, START_DATE]
    );
    return r.rows.map(row => {
        const item = { date: row.date, transfer_id: String(row.transfer_id), name: row.label || row.recipient_name || '', amount_eur: Number(row.amount_eur), share: Number(row.share) };
        return { ...item, counted_eur: counted(item.amount_eur, item.share) };
    });
}

// Totale che conta di ogni mese con almeno un prelievo: [{ month: '2026-11', total_eur }], dal più vecchio.
async function monthTotals(pool, companyId) {
    const r = await pool.query(
        `SELECT to_char(o.transfer_date, 'YYYY-MM') AS month, SUM(o.amount_eur * l.withdrawal_share) AS total
         FROM wise_outgoing o
         JOIN wise_recipient_labels l ON l.company_id = o.company_id AND l.recipient_id = o.recipient_id
         WHERE o.company_id = $1 AND o.transfer_date >= $2 AND l.withdrawal_share IS NOT NULL
         GROUP BY 1 ORDER BY 1`,
        [companyId, START_DATE]
    );
    return r.rows.map(row => ({ month: row.month, total_eur: Math.round(Number(row.total) * 100) / 100 }));
}

async function monthSummary(pool, companyId, month) {
    if (!monthInScope(month)) return summarize([], month);
    return summarize(await monthItems(pool, companyId, month), month);
}

module.exports = {
    START_DATE, START_MONTH, MIN_KEY_LENGTH,
    dayInRome, isInScope, isMonth, monthInScope, currentMonth, shareFrom, shareName,
    transferIdFromReference, counted, summarize, exportEnabled, keyMatches,
    ensureTables, recordOutgoing, recordPaid, syncFromStatement, monthItems, monthNotCounted, allItems, monthTotals, monthSummary,
};
