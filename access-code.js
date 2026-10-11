// Numbers — accesso con un codice solo, come Calendar.
//
// Niente email, niente nome utente: si entra con un codice lungo e casuale che sta in una
// variabile d'ambiente su Render (NUMBERS_ACCESS_CODE). Il codice lo sceglie e lo mette
// Federico; qui non viene mai scritto, né nei log né nelle risposte.
//
// Finché la variabile non c'è, tutto resta com'era (accesso con email e password): è il
// paracadute se qualcosa va storto. Quando c'è:
//   - si entra solo col codice; registrazione, accesso con email e recupero password sono chiusi;
//   - ogni gettone di accesso porta l'impronta del codice con cui è nato: cambiare il codice
//     su Render butta fuori tutti all'istante. È l'interruttore d'emergenza.
//
// Facoltativa: NUMBERS_OWNER_EMAIL, l'utente dentro cui si entra. Se manca, è l'unico utente
// che possiede un'azienda; se ce n'è più d'uno, va indicata.

const crypto = require('node:crypto');

const MIN_LENGTH = 24; // sotto questa lunghezza un codice si può indovinare a tentativi

function configured(env) {
    const code = env && typeof env.NUMBERS_ACCESS_CODE === 'string' ? env.NUMBERS_ACCESS_CODE.trim() : '';
    return code || null;
}

function isEnabled(env) {
    return configured(env) !== null;
}

function isStrong(env) {
    const code = configured(env);
    return !!code && code.length >= MIN_LENGTH;
}

// Confronto a tempo costante e senza rivelare la lunghezza: si confrontano due impronte
// SHA-256 (sempre 32 byte), non le stringhe. Stessa tecnica di Calendar.
function matches(input, env) {
    const code = configured(env);
    if (!code) return false;
    const given = typeof input === 'string' ? input.trim() : '';
    if (!given) return false;
    const a = crypto.createHash('sha256').update(given, 'utf8').digest();
    const b = crypto.createHash('sha256').update(code, 'utf8').digest();
    return crypto.timingSafeEqual(a, b);
}

// Impronta corta del codice in uso: sta dentro il gettone, non permette di risalire al codice.
function version(env) {
    const code = configured(env);
    if (!code) return null;
    return crypto.createHash('sha256').update('numbers-access-code:' + code, 'utf8').digest('hex').slice(0, 16);
}

function tokenStillValid(payload, env) {
    if (!isEnabled(env)) return true;
    return !!payload && payload.cv === version(env);
}

async function resolveOwner(pool, env) {
    const wanted = env && typeof env.NUMBERS_OWNER_EMAIL === 'string' ? env.NUMBERS_OWNER_EMAIL.trim().toLowerCase() : '';
    if (wanted) {
        const r = await pool.query('SELECT id, email, name FROM users WHERE email = $1', [wanted]);
        if (r.rows.length !== 1) throw new Error('NUMBERS_OWNER_EMAIL non corrisponde a nessun utente');
        return r.rows[0];
    }
    const r = await pool.query(
        `SELECT u.id, u.email, u.name FROM users u
         WHERE EXISTS (SELECT 1 FROM companies c WHERE c.user_id = u.id) ORDER BY u.id LIMIT 2`
    );
    if (r.rows.length !== 1) {
        throw new Error('Non è chiaro in quale utente entrare: imposta NUMBERS_OWNER_EMAIL su Render');
    }
    return r.rows[0];
}

module.exports = { MIN_LENGTH, isEnabled, isStrong, matches, version, tokenStillValid, resolveOwner };
