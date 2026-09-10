// Spese API (OpenAI + Gemini) come voci mensili automatiche nella sezione Spese.
// Una voce per fornitore per mese ("API OpenAI — settembre 2026"), aggiornata
// quando si aprono le spese dell'azienda target (al massimo una volta l'ora).
//
// Variabili d'ambiente:
// - OPENAI_ADMIN_KEY      Admin key OpenAI (sk-admin-...), serve per /v1/organization/costs
// - GCP_BILLING_SA_KEY    JSON del service account Google con accesso in lettura a BigQuery
// - GCP_BILLING_TABLE     tabella dell'export fatturazione: progetto.dataset.gcp_billing_export_v1_XXXX
// - AI_COSTS_COMPANY_ID   (opzionale) id azienda; se assente usa l'azienda "Scaling Catalyst"
// Se le chiavi di un fornitore mancano, quel fornitore viene semplicemente saltato.

const { BigQuery } = require('@google-cloud/bigquery');

const MESI = ['gennaio', 'febbraio', 'marzo', 'aprile', 'maggio', 'giugno', 'luglio',
    'agosto', 'settembre', 'ottobre', 'novembre', 'dicembre'];
const SYNC_EVERY_MS = 60 * 60 * 1000;
const SYNC_TIMEOUT_MS = 10 * 1000;
const CATEGORY = 'Software';

const lastSyncByCompany = {};
const runningByCompany = {};
const rateCache = {};

function periodOf(date) {
    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

function isoDay(date) {
    return date.toISOString().slice(0, 10);
}

function itDay(isoDate) {
    const [y, m, d] = isoDate.split('-');
    return `${d}/${m}/${y}`;
}

function fmt(n, decimals = 2) {
    return n.toLocaleString('it-IT', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}

// ===== FORNITORI =====
// Ognuno restituisce [{ period: 'YYYY-MM', amount, currency }] oppure null se non configurato.

async function openaiCosts(fromDate) {
    const key = process.env.OPENAI_ADMIN_KEY;
    if (!key) return null;

    const totals = {};
    let currency = 'USD';
    let page = null;
    do {
        const url = new URL('https://api.openai.com/v1/organization/costs');
        url.searchParams.set('start_time', Math.floor(fromDate.getTime() / 1000));
        url.searchParams.set('bucket_width', '1d');
        url.searchParams.set('limit', '62');
        if (page) url.searchParams.set('page', page);

        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${key}` },
            signal: AbortSignal.timeout(8000)
        });
        if (!res.ok) throw new Error(`OpenAI costs HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
        const body = await res.json();

        for (const bucket of body.data || []) {
            const period = periodOf(new Date(bucket.start_time * 1000));
            for (const r of bucket.results || []) {
                totals[period] = (totals[period] || 0) + Number(r.amount?.value || 0);
                if (r.amount?.currency) currency = r.amount.currency.toUpperCase();
            }
        }
        page = body.has_more ? body.next_page : null;
    } while (page);

    return Object.entries(totals).map(([period, amount]) => ({ period, amount, currency }));
}

async function geminiCosts(fromDate) {
    const table = process.env.GCP_BILLING_TABLE;
    const keyJson = process.env.GCP_BILLING_SA_KEY;
    if (!table || !keyJson) return null;
    if (!/^[\w-]+\.\w+\.\w+$/.test(table)) throw new Error('GCP_BILLING_TABLE non valida');

    const credentials = JSON.parse(keyJson);
    const bq = new BigQuery({ projectId: credentials.project_id, credentials });
    const [rows] = await bq.query({
        query: `SELECT FORMAT_TIMESTAMP('%Y-%m', usage_start_time) AS period, currency, SUM(cost) AS amount
                FROM \`${table}\`
                WHERE usage_start_time >= @from
                  AND service.description IN ('Gemini API', 'Generative Language API')
                GROUP BY period, currency`,
        params: { from: fromDate },
        jobTimeoutMs: 8000
    });
    return rows.map(r => ({ period: r.period, amount: Number(r.amount), currency: r.currency.toUpperCase() }));
}

const PROVIDERS = [
    { source: 'openai', label: 'OpenAI', fetch: openaiCosts },
    { source: 'gemini', label: 'Gemini', fetch: geminiCosts }
];

// ===== CAMBIO (BCE via Frankfurter) =====
// Mese chiuso: cambio dell'ultimo giorno del mese (fisso). Mese in corso: ultimo cambio disponibile.
async function toEurRate(currency, day) {
    const cacheKey = `${currency}:${day}`;
    const cached = rateCache[cacheKey];
    if (cached && (day !== 'latest' || Date.now() - cached.at < SYNC_EVERY_MS)) return cached;

    const res = await fetch(`https://api.frankfurter.dev/v1/${day}?from=${currency}&to=EUR`, {
        signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) throw new Error(`Cambio ${currency} HTTP ${res.status}`);
    const body = await res.json();
    const rate = { rate: body.rates.EUR, date: body.date, at: Date.now() };
    rateCache[cacheKey] = rate;
    return rate;
}

// ===== SCRITTURA NELLE SPESE =====

async function upsertExpense(pool, companyId, provider, { period, amount, currency }, now) {
    const [year, month] = period.split('-').map(Number);
    const closed = period !== periodOf(now);
    const lastDayOfMonth = isoDay(new Date(Date.UTC(year, month, 0)));
    const monthName = `${MESI[month - 1]} ${year}`;

    let eur = amount;
    let exchange = '';
    if (currency !== 'EUR') {
        const { rate, date } = await toEurRate(currency, closed ? lastDayOfMonth : 'latest');
        eur = amount * rate;
        exchange = ` = ${fmt(eur)} EUR al cambio BCE del ${itDay(date)} (1 ${currency} = ${fmt(rate, 4)} EUR)`;
    }
    eur = Math.round(eur * 100) / 100;

    const date = closed ? lastDayOfMonth : isoDay(now);
    const span = closed ? `tutto ${monthName}` : `dal 1 al ${now.getUTCDate()} ${monthName}`;
    const notes = `Consumo ${provider.label} ${span}: ${fmt(amount)} ${currency}${exchange}. ` +
        `Voce automatica: l'importo si aggiorna da solo, le modifiche a mano vengono sovrascritte.`;

    // Niente voci a zero: se il mese non ha consumi e la voce non esiste, non la creiamo
    if (eur === 0) {
        await pool.query(
            `UPDATE expenses SET amount = 0, date = $1, notes = $2, updated_at = CURRENT_TIMESTAMP
             WHERE company_id = $3 AND auto_source = $4 AND auto_period = $5`,
            [date, notes, companyId, provider.source, period]
        );
        return;
    }

    await pool.query(
        `INSERT INTO expenses (company_id, description, amount, category, date, notes, auto_source, auto_period)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (company_id, auto_source, auto_period) WHERE auto_source IS NOT NULL
         DO UPDATE SET amount = EXCLUDED.amount, date = EXCLUDED.date, notes = EXCLUDED.notes,
                       updated_at = CURRENT_TIMESTAMP`,
        [companyId, `API ${provider.label} — ${monthName}`, eur, CATEGORY, date, notes, provider.source, period]
    );
}

async function syncCompany(pool, companyId) {
    const now = new Date();
    // Mese in corso + mese precedente (gli ultimi giorni del mese chiuso arrivano in ritardo)
    const fromDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));

    const results = await Promise.allSettled(PROVIDERS.map(async provider => {
        const costs = await provider.fetch(fromDate);
        if (!costs) return `${provider.source}: non configurato`;
        for (const cost of costs) {
            await upsertExpense(pool, companyId, provider, cost, now);
        }
        return `${provider.source}: ${costs.length} mesi aggiornati`;
    }));

    results.forEach(r => {
        if (r.status === 'rejected') console.error('Spese API - errore sync:', r.reason.message);
    });
    return results.map(r => (r.status === 'fulfilled' ? r.value : `errore: ${r.reason.message}`));
}

function isTargetCompany(company) {
    if (process.env.AI_COSTS_COMPANY_ID) return String(company.id) === process.env.AI_COSTS_COMPANY_ID;
    return /scaling\s*catalyst/i.test(company.name || '');
}

// Da chiamare prima di leggere le spese. Non lancia mai errori e non blocca oltre SYNC_TIMEOUT_MS.
async function syncIfStale(pool, company) {
    if (!isTargetCompany(company)) return;
    const id = company.id;
    if (Date.now() - (lastSyncByCompany[id] || 0) < SYNC_EVERY_MS) return;

    if (!runningByCompany[id]) {
        runningByCompany[id] = syncCompany(pool, id)
            .then(() => { lastSyncByCompany[id] = Date.now(); })
            .catch(e => console.error('Spese API - sync fallito:', e.message))
            .finally(() => { delete runningByCompany[id]; });
    }
    await Promise.race([runningByCompany[id], new Promise(resolve => setTimeout(resolve, SYNC_TIMEOUT_MS))]);
}

module.exports = { syncIfStale, syncCompany, isTargetCompany };
