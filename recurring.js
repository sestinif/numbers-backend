// Spese ricorrenti fisse (abbonamenti/tool business): regole che si "materializzano"
// in voci di spesa vere, una per mese, finché la regola è attiva.
//
// Principio (concordato con Federico):
// - Ogni mese nasce una RIGA VERA in expenses, non un numero calcolato al volo.
// - Interrompere = mettere una fine (end_period). Da lì non nasce più nulla, ma le righe
//   dei mesi passati RESTANO (lo stop spegne il futuro, non tocca il passato).
// - Cambiare l'importo vale solo per i mesi NUOVI: i mesi già materializzati tengono il loro
//   importo (ON CONFLICT DO NOTHING non sovrascrive). Lo storico non si falsa mai.
//
// Le righe generate sono taggate auto_source = 'rule:<id>' + auto_period = 'YYYY-MM',
// quindi riusano l'indice unico esistente (company_id, auto_source, auto_period):
// una riga per regola per mese, zero doppioni.

const MAX_MONTHS = 600; // paracadute anti-loop (50 anni)

function ym(year, month /* 1-12 */) {
    return `${year}-${String(month).padStart(2, '0')}`;
}

function currentPeriod(now = new Date()) {
    return ym(now.getUTCFullYear(), now.getUTCMonth() + 1);
}

function parsePeriod(p) {
    const [y, m] = p.split('-').map(Number);
    return { y, m };
}

// true se a <= b (confronto 'YYYY-MM' lessicografico, sicuro perché zero-padded)
function lte(a, b) { return a <= b; }

function clampDay(year, month /* 1-12 */, day) {
    const last = new Date(Date.UTC(year, month, 0)).getUTCDate();
    return Math.min(Math.max(day || 1, 1), last);
}

function isoDate(year, month, day) {
    return `${ym(year, month)}-${String(clampDay(year, month, day)).padStart(2, '0')}`;
}

// Materializza le voci mancanti per tutte le regole attive dell'azienda.
// Idempotente: chiamabile a ogni apertura delle spese, crea solo ciò che manca.
async function materialize(pool, companyId, now = new Date()) {
    const cur = currentPeriod(now);
    const { rows: rules } = await pool.query(
        `SELECT * FROM recurring_rules WHERE company_id = $1 AND active = TRUE`,
        [companyId]
    );

    let created = 0;
    for (const rule of rules) {
        const start = rule.start_period;
        if (start > cur) continue; // parte nel futuro: ancora niente
        const stop = rule.end_period && rule.end_period < cur ? rule.end_period : cur; // fin dove arrivare
        const startM = parsePeriod(start);

        let { y, m } = startM;
        let guard = 0;
        while (lte(ym(y, m), stop) && guard++ < MAX_MONTHS) {
            const due = rule.frequency === 'yearly' ? (m === startM.m) : true;
            if (due) {
                const period = ym(y, m);
                const date = isoDate(y, m, rule.day_of_month);
                const notes = `Voce ricorrente "${rule.name}". Generata in automatico ogni mese. ` +
                    `Se interrompi la regola i mesi già segnati restano; se cambi l'importo vale solo per i mesi nuovi.`;
                const r = await pool.query(
                    `INSERT INTO expenses (company_id, description, amount, category, date, notes, auto_source, auto_period)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     ON CONFLICT (company_id, auto_source, auto_period) WHERE auto_source IS NOT NULL
                     DO NOTHING`,
                    [companyId, rule.name, rule.amount, rule.category || null, date, notes, `rule:${rule.id}`, period]
                );
                created += r.rowCount;
            }
            m++; if (m > 12) { m = 1; y++; }
        }
    }
    return created;
}

module.exports = { materialize, currentPeriod, ym, clampDay };
