// Numbers — PIN per far partire un bonifico, con blocco dei tentativi.
//
// Il PIN lo sceglie e lo mette Federico su Render, nella variabile WISE_PAY_PIN (da 4 a 8 cifre).
// Qui non viene mai scritto, né nei log né nelle risposte. Senza la variabile, o se non è fatta di
// sole cifre, il PIN risulta spento e dalla pagina non si può far partire nessun bonifico.
//
// Un PIN di 4 cifre ha 10.000 combinazioni: da solo non reggerebbe a chi prova a raffica. Per questo
// il blocco è parte del PIN, non un'aggiunta:
//   - 5 PIN sbagliati in 15 minuti → tutto fermo per 15 minuti;
//   - 20 PIN sbagliati in 24 ore  → tutto fermo fino al giorno dopo.
// Il conto dei tentativi è PER AZIENDA, non per indirizzo: cambiare rete o computer non lo aggira.
// Sta in memoria: un riavvio del server lo azzera, ma il riavvio non lo può chiedere chi prova il PIN.
// Per entrare in Numbers serve comunque il codice di accesso: il PIN è il secondo ostacolo.

const crypto = require('node:crypto');

const PIN_RE = /^\d{4,8}$/;

function configured(env) {
    const value = env && typeof env.WISE_PAY_PIN === 'string' ? env.WISE_PAY_PIN.trim() : '';
    return PIN_RE.test(value) ? value : null;
}

function isEnabled(env) {
    return configured(env) !== null;
}

// Confronto a tempo costante e senza rivelare la lunghezza: si confrontano due impronte SHA-256.
// Accetta solo stringhe e numeri: un oggetto con un toString() furbo non passa.
function matches(input, env) {
    const pin = configured(env);
    if (!pin) return false;
    if (typeof input !== 'string' && typeof input !== 'number') return false;
    const given = String(input).trim();
    if (!given) return false;
    const a = crypto.createHash('sha256').update(given, 'utf8').digest();
    const b = crypto.createHash('sha256').update(pin, 'utf8').digest();
    return crypto.timingSafeEqual(a, b);
}

const MAX_KEPT = 50; // tentativi ricordati per azienda: più di così non servono

function createGuard({ now, windowMs = 15 * 60 * 1000, maxPerWindow = 5, dayMs = 24 * 60 * 60 * 1000, maxPerDay = 20 } = {}) {
    const clock = now || Date.now;
    const failures = new Map(); // chiave → [timestamp, …] dal più vecchio

    function recent(key) {
        const t = clock();
        const list = (failures.get(key) || []).filter(x => t - x < dayMs);
        failures.set(key, list);
        return list;
    }

    // { allowed, retryAfterSec }: se è chiuso, tra quanti secondi si può riprovare.
    function check(key) {
        const t = clock();
        const list = recent(key);
        if (list.length >= maxPerDay) {
            const until = list[list.length - maxPerDay] + dayMs;
            return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((until - t) / 1000)) };
        }
        const inWindow = list.filter(x => t - x < windowMs);
        if (inWindow.length >= maxPerWindow) {
            const until = inWindow[inWindow.length - maxPerWindow] + windowMs;
            return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((until - t) / 1000)) };
        }
        return { allowed: true, retryAfterSec: 0 };
    }

    function fail(key) {
        const list = recent(key);
        list.push(clock());
        if (list.length > MAX_KEPT) list.splice(0, list.length - MAX_KEPT);
    }

    function succeed(key) {
        failures.delete(key);
    }

    function size(key) {
        return (failures.get(key) || []).length;
    }

    return { check, fail, succeed, size };
}

// Il controllo completo di una richiesta che vuole far partire un bonifico.
// Ritorna null se si può procedere, altrimenti { status, error } da rimandare alla pagina.
// Mai 401/403: la pagina di Numbers a quei due codici fa uscire l'utente, e un PIN sbagliato no.
function checkRequest({ guard, companyId, pin, env, log }) {
    if (!isEnabled(env)) {
        return { status: 400, error: 'L\'invio con il PIN non è attivo: i bonifici si confermano dall\'app di Wise.' };
    }
    const key = `company:${companyId}`;
    const gate = guard.check(key);
    if (!gate.allowed) {
        const minutes = Math.ceil(gate.retryAfterSec / 60);
        return {
            status: 429,
            error: minutes > 60
                ? 'Troppi PIN sbagliati: l\'invio è fermo fino a domani.'
                : `Troppi PIN sbagliati: l'invio è fermo, riprova tra ${minutes} minuti.`,
        };
    }
    if (!matches(pin, env)) {
        guard.fail(key);
        if (log) log(`PIN sbagliato per l'azienda ${companyId}`);
        return { status: 400, error: 'PIN sbagliato.' };
    }
    guard.succeed(key);
    return null;
}

module.exports = { isEnabled, matches, createGuard, checkRequest };
