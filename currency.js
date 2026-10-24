// Spese in euro o in dollari (24/10/2026, Federico: «le spese mi devi dare modo di metterle
// sia in euro che in dollari»).
//
// Principio: `expenses.amount` resta SEMPRE in euro, così totali, Dashboard e report non
// cambiano. Una spesa in dollari tiene anche la cifra scritta (`amount_original`) e la sua
// valuta (`currency`); gli euro si calcolano al cambio BCE del giorno della spesa (o di oggi,
// se la data è nel futuro). Per una spesa in euro `amount_original` resta vuoto.

const SUPPORTED = ['EUR', 'USD'];

function normalizeCurrency(value, fallback = 'EUR') {
    const c = String(value || '').trim().toUpperCase();
    return SUPPORTED.includes(c) ? c : fallback;
}

const round2 = n => Math.round(n * 100) / 100;

function isoToday(now = new Date()) {
    return now.toISOString().slice(0, 10);
}

// { eur, original }: gli euro da salvare in `amount` e la cifra originale (null se è già in euro).
// `toEurRate(currency, day|'latest')` → { rate } è quella di ai-costs.js (Frankfurter/BCE).
async function toEurAmount(amount, currency, day, toEurRate, now = new Date()) {
    const value = round2(parseFloat(amount));
    const cur = normalizeCurrency(currency);
    if (cur === 'EUR') return { eur: value, original: null, currency: 'EUR' };
    const d = String(day || '').slice(0, 10);
    const when = /^\d{4}-\d{2}-\d{2}$/.test(d) && d <= isoToday(now) ? d : 'latest';
    const { rate } = await toEurRate(cur, when);
    return { eur: round2(value * rate), original: value, currency: cur };
}

module.exports = { SUPPORTED, normalizeCurrency, toEurAmount };
