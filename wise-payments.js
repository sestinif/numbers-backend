// Numbers — i bonifici preparati su Wise, lato database.
//
// Ogni bonifico preparato da Numbers ha una riga in wise_payments: serve a mostrare la lista
// con lo stato, a non crearne due uguali (chiave anti-doppione) e a segnare la spesa UNA volta,
// quando i soldi sono partiti davvero. Chi parla con Wise è wise.js; qui c'è solo il registro.
// Un bonifico preparato aspetta su Wise finché qualcuno lo paga: dall'app di Wise, oppure da
// Numbers con send() qui sotto. send() è chiamata SOLO dalla rotta protetta dal PIN (server.js).

const wise = require('./wise');
const withdrawals = require('./withdrawals');

const REFRESH_LIMIT = 25; // quanti bonifici non chiusi si ricontrollano a ogni apertura della pagina

// I bonifici NON finiscono nelle Spese di Numbers (Federico, 11/10/2026: «toglile, non farle andare»).
// Si vedono solo nella pagina Pagamenti. Il codice che segnava la spesa resta sotto, spento: per
// riaccenderlo basta questo interruttore, ma è una decisione da rifare con lui.
const TRACK_EXPENSES = false;

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

// Wise è collegato a UN'azienda: quella del token. Le altre non devono vedere né muovere quei soldi.
// `configured` = WISE_COMPANY_ID su Render; `detected` = l'azienda che ha già bonifici o nomi di beneficiari
// (serve finché la variabile non c'è). Se non c'è né l'una né l'altra, nessuna restrizione (collegamento nuovo).
function wiseCompanyAllowed(configured, detected, companyId) {
    const fixed = parseInt(configured, 10);
    const owner = fixed > 0 ? fixed : (detected == null ? null : Number(detected));
    return owner === null || String(owner) === String(companyId);
}

function cleanLabel(value) {
    return String(value == null ? '' : value).replace(/\s+/g, ' ').trim().slice(0, 60);
}

// { '<id beneficiario>': 'nome dato in Numbers' } (i beneficiari senza nome, con solo la quota prelievo, non ci sono)
async function getLabels(pool, companyId) {
    const r = await pool.query(`SELECT recipient_id, label FROM wise_recipient_labels WHERE company_id = $1`, [companyId]);
    const out = {};
    for (const row of r.rows) if (row.label) out[String(row.recipient_id)] = row.label;
    return out;
}

// { '<id beneficiario>': 'all' | 'half' } — chi non c'è, non conta nei prelievi.
async function getShares(pool, companyId) {
    const r = await pool.query(
        `SELECT recipient_id, withdrawal_share FROM wise_recipient_labels WHERE company_id = $1 AND withdrawal_share IS NOT NULL`,
        [companyId]
    );
    const out = {};
    for (const row of r.rows) out[String(row.recipient_id)] = withdrawals.shareName(Number(row.withdrawal_share));
    return out;
}

// list = [{ recipientId, label, share? }]. Nome vuoto e nessuna quota toglie la riga.
// `share` ('all' | 'half' | 'none') è la quota che conta nei prelievi; se manca, resta quella che c'era.
async function saveLabels(pool, companyId, list) {
    let saved = 0;
    for (const item of Array.isArray(list) ? list.slice(0, 500) : []) {
        const id = String(item && item.recipientId != null ? item.recipientId : '').trim();
        if (!/^\d{1,18}$/.test(id)) continue;
        const label = cleanLabel(item.label);
        const hasShare = Object.prototype.hasOwnProperty.call(item, 'share');
        const share = hasShare ? withdrawals.shareFrom(item.share) : undefined;
        const current = (await pool.query(
            `SELECT withdrawal_share FROM wise_recipient_labels WHERE company_id = $1 AND recipient_id = $2`, [companyId, id]
        )).rows[0];
        const finalShare = hasShare ? share : (current && current.withdrawal_share != null ? Number(current.withdrawal_share) : null);
        if (!label && finalShare == null) {
            await pool.query(`DELETE FROM wise_recipient_labels WHERE company_id = $1 AND recipient_id = $2`, [companyId, id]);
        } else {
            await pool.query(
                `INSERT INTO wise_recipient_labels (company_id, recipient_id, label, withdrawal_share) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (company_id, recipient_id) DO UPDATE
                 SET label = EXCLUDED.label, withdrawal_share = EXCLUDED.withdrawal_share, updated_at = CURRENT_TIMESTAMP`,
                [companyId, id, label, finalShare]
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
                OR ($3::boolean AND track_expense = TRUE AND expense_id IS NULL AND status = 'outgoing_payment_sent'))
         ORDER BY created_at DESC LIMIT $2`,
        [companyId, REFRESH_LIMIT, TRACK_EXPENSES]
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
                    if (row.status === 'incoming_payment_waiting') await recordIfPaid(pool, current, toEurRate, now);
                }
            }
            if (TRACK_EXPENSES && wise.shouldTrackExpense(current)) {
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
async function prepare(pool, client, companyId, input, limits = {}, opts = {}) {
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

    // Se il bonifico deve partire subito e il saldo non basta, non nasce niente: né su Wise né qui.
    if (opts.requireBalance) await ensureBalance(client, quote.sourceCurrency, quote.sourceAmount);

    let row = existing;
    if (!row) {
        const ins = await pool.query(
            `INSERT INTO wise_payments (company_id, client_key, recipient_id, recipient_name, target_amount, target_currency,
                                        source_amount, source_currency, fee, reference, category, track_expense)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (company_id, client_key) DO NOTHING RETURNING *`,
            [companyId, key, recipient.id, recipient.name, quote.targetAmount, quote.targetCurrency,
             quote.sourceAmount, quote.sourceCurrency, quote.fee, reference || null,
             String(input.category || '').trim().slice(0, 100) || null, TRACK_EXPENSES && input.trackExpense !== false]
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

function fmtMoney(value, currency) {
    return `${Number(value).toLocaleString('it-IT', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;
}

// Prima di far partire dei soldi: nel saldo da cui si paga ce n'è abbastanza? Se no, si ferma qui,
// con la cifra che serve e quella che c'è. Se il saldo non si riesce a leggere, non si procede.
async function ensureBalance(client, currency, needed) {
    const balances = await client.balances();
    const found = balances.find(b => b.currency === currency);
    const have = found ? Number(found.amount) : 0;
    if (have + 0.000001 < Number(needed)) {
        throw new wise.WiseError(`Il saldo Wise non basta: per questo bonifico servono ${fmtMoney(needed, currency)}, nel saldo ${currency} ci sono ${fmtMoney(have, currency)}.`, 422);
    }
}

// Un bonifico che ha lasciato «in attesa» e non è finito male entra nei prelievi del mese.
// Mai un errore verso chi chiama: se qui qualcosa va storto, il conto lo recupera l'estratto di Wise.
const NOT_PAID = new Set(['incoming_payment_waiting', 'sending', 'cancelled', 'funds_refunded', 'charged_back']);
async function recordIfPaid(pool, row, toEurRate, now) {
    if (!row || !row.wise_transfer_id || NOT_PAID.has(row.status)) return;
    try {
        await withdrawals.recordPaid(pool, row, toEurRate || require('./ai-costs').toEurRate, now);
    } catch (e) {
        console.error(`Prelievi: bonifico ${row.wise_transfer_id} non registrato:`, e.message);
    }
}

// FA PARTIRE un bonifico preparato: lo paga dal saldo Wise. Da chiamare solo dopo aver controllato il PIN.
// Il passaggio da «in attesa» a «in invio» è una sola UPDATE condizionata: due richieste insieme
// (doppio tocco, riprova) non possono pagare due volte, perché solo una trova la riga ancora in attesa.
// Se Wise rifiuta, la riga torna in attesa e il bonifico si può confermare dall'app o riprovare.
async function send(pool, client, companyId, paymentId, limits = {}) {
    const found = await pool.query(`SELECT * FROM wise_payments WHERE id = $1 AND company_id = $2`, [paymentId, companyId]);
    const row = found.rows[0];
    if (!row || !row.wise_transfer_id) throw new wise.WiseError('Bonifico non trovato.', 404);
    if (limits.maxAmount && Number(row.target_amount) > limits.maxAmount) {
        throw new wise.WiseError(`Importo sopra il tetto di sicurezza (${limits.maxAmount} per bonifico). Questo bonifico va confermato dall'app di Wise.`, 400);
    }
    // Il saldo si controlla prima di prenotare l'invio: se non basta, il bonifico resta com'è (in attesa).
    if (row.source_amount != null && row.source_currency) await ensureBalance(client, row.source_currency, row.source_amount);

    const claim = await pool.query(
        `UPDATE wise_payments SET status = 'sending', updated_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND company_id = $2 AND status = 'incoming_payment_waiting' RETURNING *`,
        [paymentId, companyId]
    );
    if (!claim.rows[0]) throw new wise.WiseError('Il bonifico non è più in attesa: è già partito, è in invio o è stato annullato.', 409);

    let outcome;
    try {
        outcome = await client.fundTransfer(row.wise_transfer_id);
    } catch (e) {
        // Il pagamento non è partito: la riga torna in attesa (solo se nessuno l'ha già cambiata).
        await pool.query(
            `UPDATE wise_payments SET status = 'incoming_payment_waiting', updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'sending'`,
            [paymentId]
        );
        throw e;
    }
    // Lo stato vero lo dice Wise; se ancora «in attesa» o non risponde, il bonifico è pagato ma non
    // ancora preso in carico: «in lavorazione», e la prossima apertura della pagina lo aggiorna.
    let status = 'processing';
    try {
        const t = await client.getTransfer(row.wise_transfer_id);
        if (t && t.status && t.status !== 'incoming_payment_waiting') status = t.status;
    } catch (e) { /* si riallinea alla prossima apertura */ }
    const up = await pool.query(
        `UPDATE wise_payments SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
        [status, paymentId]
    );
    await recordIfPaid(pool, up.rows[0], null, new Date());
    return { row: up.rows[0], already: !!(outcome && outcome.already) };
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

module.exports = { TRACK_EXPENSES, ensureTable, listPayments, publicPayment, trackExpense, refresh, prepare, send, cancel, getLabels, getShares, saveLabels, cleanLabel, wiseCompanyAllowed };
