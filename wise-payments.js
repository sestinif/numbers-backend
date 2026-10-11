// Numbers — i bonifici preparati su Wise, lato database.
//
// Ogni bonifico preparato da Numbers ha una riga in wise_payments: serve a mostrare la lista
// con lo stato, a non crearne due uguali (chiave anti-doppione) e a segnare la spesa UNA volta,
// quando i soldi sono partiti davvero. Chi parla con Wise è wise.js; qui c'è solo il registro.
// Numbers prepara e basta: a far partire i soldi è Federico, dall'app di Wise.

const wise = require('./wise');

const REFRESH_LIMIT = 25; // quanti bonifici non chiusi si ricontrollano a ogni apertura della pagina

async function ensureTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS wise_payments (
            id SERIAL PRIMARY KEY,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            client_key VARCHAR(64) NOT NULL,
            wise_transfer_id BIGINT,
            recipient_id BIGINT NOT NULL,
            recipient_name VARCHAR(255) NOT NULL,
            target_amount NUMERIC(14, 2) NOT NULL,
            target_currency VARCHAR(3) NOT NULL,
            source_amount NUMERIC(14, 2),
            source_currency VARCHAR(3),
            fee NUMERIC(14, 2),
            reference VARCHAR(140),
            category VARCHAR(100),
            track_expense BOOLEAN NOT NULL DEFAULT TRUE,
            status VARCHAR(40) NOT NULL DEFAULT 'incoming_payment_waiting',
            expense_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_wise_payments_key ON wise_payments(company_id, client_key)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_wise_payments_company ON wise_payments(company_id, created_at DESC)`);
    // I nomi che Federico dà ai beneficiari («Assistente», «Mio conto N26»): vivono solo in Numbers,
    // su Wise il beneficiario resta col suo nome legale.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS wise_recipient_labels (
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            recipient_id BIGINT NOT NULL,
            label VARCHAR(60) NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (company_id, recipient_id)
        )`);
}

function cleanLabel(value) {
    return String(value == null ? '' : value).replace(/\s+/g, ' ').trim().slice(0, 60);
}

// { '<id beneficiario>': 'nome dato in Numbers' }
async function getLabels(pool, companyId) {
    const r = await pool.query(`SELECT recipient_id, label FROM wise_recipient_labels WHERE company_id = $1`, [companyId]);
    const out = {};
    for (const row of r.rows) out[String(row.recipient_id)] = row.label;
    return out;
}

// list = [{ recipientId, label }]. Un nome vuoto toglie quello che c'era.
async function saveLabels(pool, companyId, list) {
    let saved = 0;
    for (const item of Array.isArray(list) ? list.slice(0, 500) : []) {
        const id = String(item && item.recipientId != null ? item.recipientId : '').trim();
        if (!/^\d{1,18}$/.test(id)) continue;
        const label = cleanLabel(item.label);
        if (!label) {
            await pool.query(`DELETE FROM wise_recipient_labels WHERE company_id = $1 AND recipient_id = $2`, [companyId, id]);
        } else {
            await pool.query(
                `INSERT INTO wise_recipient_labels (company_id, recipient_id, label) VALUES ($1, $2, $3)
                 ON CONFLICT (company_id, recipient_id) DO UPDATE SET label = EXCLUDED.label, updated_at = CURRENT_TIMESTAMP`,
                [companyId, id, label]
            );
        }
        saved++;
    }
    return saved;
}

function publicPayment(row, labels) {
    const info = wise.statusInfo(row.status);
    return {
        id: row.id,
        recipient_name: row.recipient_name,
        recipient_label: (labels && labels[String(row.recipient_id)]) || null,
        target_amount: row.target_amount,
        target_currency: row.target_currency,
        source_amount: row.source_amount,
        source_currency: row.source_currency,
        fee: row.fee,
        reference: row.reference,
        category: row.category,
        status: row.status,
        state: info.state,
        status_label: info.label,
        expense_id: row.expense_id,
        created_at: row.created_at,
    };
}

async function listPayments(pool, companyId, limit = 50) {
    const r = await pool.query(
        `SELECT * FROM wise_payments WHERE company_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
        [companyId, limit]
    );
    return r.rows;
}

// La spesa del bonifico, in euro. Una per bonifico: la chiave unica delle spese automatiche
// (company_id, auto_source, auto_period) fa da paracadute contro i doppioni.
async function trackExpense(pool, payment, toEurRate, now = new Date()) {
    const fromSource = payment.source_amount != null;
    let eur = parseFloat(fromSource ? payment.source_amount : payment.target_amount);
    const currency = fromSource ? payment.source_currency : payment.target_currency;
    let exchange = '';
    if (currency !== 'EUR') {
        const rate = await toEurRate(currency, 'latest');
        exchange = ` Cambio ${currency}→EUR ${rate.rate} del ${rate.date}.`;
        eur = Math.round(eur * rate.rate * 100) / 100;
    }
    const day = now.toISOString().slice(0, 10);
    const description = payment.recipient_name + (payment.reference ? ` — ${payment.reference}` : '');
    const notes = `Bonifico Wise n. ${payment.wise_transfer_id}: ${payment.target_amount} ${payment.target_currency} a ${payment.recipient_name}` +
        (fromSource ? `, usciti ${payment.source_amount} ${payment.source_currency}` : '') +
        (payment.fee != null && fromSource ? ` (costo Wise ${payment.fee} ${payment.source_currency})` : '') +
        `.${exchange} Segnata in automatico quando il bonifico è partito.`;
    const source = `wise:${payment.wise_transfer_id}`;
    const ins = await pool.query(
        `INSERT INTO expenses (company_id, description, amount, category, date, notes, auto_source, auto_period, account)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Wise')
         ON CONFLICT (company_id, auto_source, auto_period) WHERE auto_source IS NOT NULL DO NOTHING
         RETURNING id`,
        [payment.company_id, description.slice(0, 250), eur, payment.category || 'Altro', day, notes, source, day.slice(0, 7)]
    );
    let expenseId = ins.rows[0] && ins.rows[0].id;
    if (!expenseId) {
        const old = await pool.query(
            `SELECT id FROM expenses WHERE company_id = $1 AND auto_source = $2 ORDER BY id LIMIT 1`,
            [payment.company_id, source]
        );
        expenseId = old.rows[0] && old.rows[0].id;
    }
    if (expenseId) {
        await pool.query(`UPDATE wise_payments SET expense_id = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`, [expenseId, payment.id]);
    }
    return expenseId || null;
}

// Ricontrolla su Wise i bonifici non ancora chiusi e segna le spese di quelli partiti.
// Un errore su un bonifico non blocca gli altri: si riprova alla prossima apertura.
async function refresh(pool, client, companyId, toEurRate, now = new Date()) {
    const open = await pool.query(
        `SELECT * FROM wise_payments
         WHERE company_id = $1 AND wise_transfer_id IS NOT NULL
           AND (status NOT IN ('outgoing_payment_sent', 'cancelled', 'funds_refunded', 'charged_back')
                OR (track_expense = TRUE AND expense_id IS NULL AND status = 'outgoing_payment_sent'))
         ORDER BY created_at DESC LIMIT $2`,
        [companyId, REFRESH_LIMIT]
    );
    let changed = 0;
    for (const row of open.rows) {
        try {
            let current = row;
            if (!wise.statusInfo(row.status).final) {
                const t = await client.getTransfer(row.wise_transfer_id);
                if (t && t.status && t.status !== row.status) {
                    const up = await pool.query(
                        `UPDATE wise_payments SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
                        [t.status, row.id]
                    );
                    current = up.rows[0];
                    changed++;
                }
            }
            if (wise.shouldTrackExpense(current)) {
                await trackExpense(pool, current, toEurRate, now);
                changed++;
            }
        } catch (e) {
            console.error(`Wise: bonifico ${row.wise_transfer_id} non aggiornato:`, e.message);
        }
    }
    return changed;
}

// Prepara un bonifico: preventivo fresco, poi il bonifico su Wise, poi la riga nel registro.
// La riga nasce PRIMA di chiamare Wise, con la chiave anti-doppione: due tocchi sullo stesso
// modulo, o una richiesta ripetuta, portano allo stesso bonifico e non a due.
//
// limits = freni di sicurezza: { maxPerDay, maxAmount }. Oltre il tetto del giorno o della cifra
// Numbers si rifiuta di preparare, qualunque cosa arrivi dalla pagina.
async function prepare(pool, client, companyId, input, limits = {}) {
    const key = String(input.clientKey || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(key)) {
        throw new wise.WiseError('Richiesta non valida: ricarica la pagina e riprova.', 400);
    }
    const amount = wise.positiveAmount(input.amount);
    if (amount == null) throw new wise.WiseError('L\'importo deve essere un numero maggiore di zero.', 400);
    if (limits.maxAmount && amount > limits.maxAmount) {
        throw new wise.WiseError(`Importo sopra il tetto di sicurezza (${limits.maxAmount} per bonifico). Questo bonifico va fatto da Wise.`, 400);
    }
    const reference = String(input.reference == null ? '' : input.reference).trim().slice(0, 140);

    const byKey = () => pool.query(`SELECT * FROM wise_payments WHERE company_id = $1 AND client_key = $2`, [companyId, key]);
    const existing = (await byKey()).rows[0];
    if (existing && existing.wise_transfer_id) return existing;

    if (limits.maxPerDay) {
        const today = await pool.query(
            `SELECT COUNT(*)::int AS n FROM wise_payments WHERE company_id = $1 AND created_at >= CURRENT_DATE`,
            [companyId]
        );
        if (today.rows[0].n >= limits.maxPerDay) {
            throw new wise.WiseError(`Tetto di sicurezza raggiunto: oggi sono già stati preparati ${today.rows[0].n} bonifici. Riprova domani o falli da Wise.`, 429);
        }
    }

    const recipient = (await client.recipients()).find(r => String(r.id) === String(input.recipientId));
    if (!recipient) throw new wise.WiseError('Beneficiario non trovato su Wise.', 400);

    const quote = await client.quote({
        recipientId: recipient.id,
        amount,
        targetCurrency: recipient.currency,
        sourceCurrency: String(input.sourceCurrency || recipient.currency).toUpperCase(),
    });

    let row = existing;
    if (!row) {
        const ins = await pool.query(
            `INSERT INTO wise_payments (company_id, client_key, recipient_id, recipient_name, target_amount, target_currency,
                                        source_amount, source_currency, fee, reference, category, track_expense)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (company_id, client_key) DO NOTHING RETURNING *`,
            [companyId, key, recipient.id, recipient.name, quote.targetAmount, quote.targetCurrency,
             quote.sourceAmount, quote.sourceCurrency, quote.fee, reference || null,
             String(input.category || '').trim().slice(0, 100) || null, input.trackExpense !== false]
        );
        row = ins.rows[0] || (await byKey()).rows[0];
        if (row.wise_transfer_id) return row;
    }

    let transfer;
    try {
        transfer = await client.createTransfer({ recipientId: recipient.id, quoteId: quote.id, reference, key });
    } catch (e) {
        // Wise ha detto no: la riga vuota non serve a niente e bloccherebbe un secondo tentativo corretto.
        if (e.status >= 400 && e.status < 500) {
            await pool.query(`DELETE FROM wise_payments WHERE id = $1 AND wise_transfer_id IS NULL`, [row.id]);
        }
        throw e;
    }
    const up = await pool.query(
        `UPDATE wise_payments SET wise_transfer_id = $1, status = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *`,
        [transfer.id, transfer.status || 'incoming_payment_waiting', row.id]
    );
    return up.rows[0];
}

// Annulla un bonifico ancora in attesa (dopo, Wise non lo permette più).
async function cancel(pool, client, companyId, paymentId) {
    const r = await pool.query(`SELECT * FROM wise_payments WHERE id = $1 AND company_id = $2`, [paymentId, companyId]);
    const row = r.rows[0];
    if (!row || !row.wise_transfer_id) throw new wise.WiseError('Bonifico non trovato.', 404);
    const t = await client.cancelTransfer(row.wise_transfer_id);
    const up = await pool.query(
        `UPDATE wise_payments SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
        [(t && t.status) || 'cancelled', row.id]
    );
    return up.rows[0];
}

module.exports = { ensureTable, listPayments, publicPayment, trackExpense, refresh, prepare, cancel, getLabels, saveLabels, cleanLabel };
