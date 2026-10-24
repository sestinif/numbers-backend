const test = require('node:test');
const assert = require('node:assert');
const C = require('../currency.js');
const R = require('../recurring.js');

const NOW = new Date(Date.UTC(2026, 9, 24));
// Finto cambio: 1 USD = 0.89 EUR, e si ricorda per che giorno è stato chiesto.
function fakeRate() {
    const asked = [];
    const fn = async (cur, day) => { asked.push([cur, day]); return { rate: 0.89, date: day }; };
    fn.asked = asked;
    return fn;
}

test('normalizeCurrency accetta solo euro e dollari', () => {
    assert.strictEqual(C.normalizeCurrency('usd'), 'USD');
    assert.strictEqual(C.normalizeCurrency('EUR'), 'EUR');
    assert.strictEqual(C.normalizeCurrency('GBP'), 'EUR');
    assert.strictEqual(C.normalizeCurrency(undefined), 'EUR');
    assert.strictEqual(C.normalizeCurrency(null, 'USD'), 'USD');
});

test('una spesa in euro resta com\'è, senza cifra originale', async () => {
    const rate = fakeRate();
    assert.deepStrictEqual(await C.toEurAmount('30', 'EUR', '2026-10-10', rate, NOW), { eur: 30, original: null, currency: 'EUR' });
    assert.strictEqual(rate.asked.length, 0);
});

test('una spesa in dollari si converte al cambio del suo giorno', async () => {
    const rate = fakeRate();
    assert.deepStrictEqual(await C.toEurAmount('30', 'USD', '2026-10-10', rate, NOW), { eur: 26.7, original: 30, currency: 'USD' });
    assert.deepStrictEqual(rate.asked, [['USD', '2026-10-10']]);
});

test('con la data nel futuro si usa il cambio di adesso', async () => {
    const rate = fakeRate();
    await C.toEurAmount(10, 'USD', '2026-11-15', rate, NOW);
    assert.deepStrictEqual(rate.asked, [['USD', 'latest']]);
});

test('se il cambio non arriva la spesa non si salva con una cifra sbagliata', async () => {
    await assert.rejects(C.toEurAmount(10, 'USD', '2026-10-10', async () => { throw new Error('down'); }, NOW));
});

function fakePool() {
    const calls = [];
    return {
        calls,
        async query(sql, params) {
            calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
            if (/FROM recurring_rules/.test(sql)) return { rows: [{
                id: 9, company_id: 1, name: 'Higgsfield', amount: '29.00', category: 'Software', frequency: 'monthly',
                day_of_month: 5, start_period: '2026-10', end_period: null, active: true, account: 'Mercury', cost_type: 'fixed', currency: 'USD'
            }] };
            return { rows: [], rowCount: 1 };
        }
    };
}

test('una regola in dollari genera la voce in euro e tiene i dollari scritti', async () => {
    const pool = fakePool();
    await R.materialize(pool, 1, NOW, fakeRate());
    const ins = pool.calls.find(c => /INSERT INTO expenses/.test(c.sql));
    assert.ok(ins, 'la voce di ottobre nasce');
    const p = ins.params;
    assert.strictEqual(p[2], 25.81);          // amount in euro: 29 × 0.89
    assert.strictEqual(p[11], 'USD');         // currency
    assert.strictEqual(p[12], 29);            // amount_original
});

test('senza cambio la voce in dollari aspetta, non nasce sbagliata', async () => {
    const pool = fakePool();
    await R.materialize(pool, 1, NOW, async () => { throw new Error('down'); });
    assert.strictEqual(pool.calls.filter(c => /INSERT INTO expenses/.test(c.sql)).length, 0);
});
