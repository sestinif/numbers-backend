const test = require('node:test');
const assert = require('node:assert');
const R = require('../recurring.js');

// Finto pool: registra le query e risponde con quello che gli si prepara.
function fakePool(answers = []) {
    const calls = [];
    return {
        calls,
        async query(sql, params) {
            calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
            const hit = answers.find(a => a.match.test(sql));
            return hit ? hit.result : { rows: [], rowCount: 1 };
        }
    };
}
const OTT = new Date(Date.UTC(2026, 9, 9));
const regola = over => Object.assign({
    id: 7, company_id: 1, name: 'Render', amount: '25.00', category: 'Software', frequency: 'monthly',
    day_of_month: 14, start_period: '2026-10', end_period: null, active: true, account: 'Revolut Business', cost_type: 'fixed'
}, over);

test('normalizeCostType accetta solo fisso o variabile', () => {
    assert.strictEqual(R.normalizeCostType('variable'), 'variable');
    assert.strictEqual(R.normalizeCostType('fixed'), 'fixed');
    assert.strictEqual(R.normalizeCostType('VARIABLE'), 'variable');
    assert.strictEqual(R.normalizeCostType('boh'), 'fixed');
    assert.strictEqual(R.normalizeCostType(undefined), 'fixed');
    assert.strictEqual(R.normalizeCostType(undefined, 'variable'), 'variable');
});

test('cleanAccount toglie gli spazi, taglia a 120 e rende null il vuoto', () => {
    assert.strictEqual(R.cleanAccount('  Revolut Business '), 'Revolut Business');
    assert.strictEqual(R.cleanAccount(''), null);
    assert.strictEqual(R.cleanAccount('   '), null);
    assert.strictEqual(R.cleanAccount(null), null);
    assert.strictEqual(R.cleanAccount('x'.repeat(200)).length, 120);
});

test('una regola fissa genera una voce già confermata, con conto e tipo', async () => {
    const pool = fakePool([{ match: /FROM recurring_rules/, result: { rows: [regola()] } }]);
    const created = await R.materialize(pool, 1, OTT);
    assert.strictEqual(created, 1);
    const ins = pool.calls.find(c => c.sql.startsWith('INSERT INTO expenses'));
    assert.match(ins.sql, /account, cost_type, amount_confirmed/);
    assert.deepStrictEqual(ins.params.slice(-3), ['Revolut Business', 'fixed', true]);
    assert.strictEqual(ins.params[7], '2026-10');
    assert.strictEqual(ins.params[4], '2026-10-14');
});

test('una regola variabile genera una voce da confermare', async () => {
    const pool = fakePool([{ match: /FROM recurring_rules/, result: { rows: [regola({ cost_type: 'variable' })] } }]);
    await R.materialize(pool, 1, OTT);
    const ins = pool.calls.find(c => c.sql.startsWith('INSERT INTO expenses'));
    assert.deepStrictEqual(ins.params.slice(-3), ['Revolut Business', 'variable', false]);
});

test('una regola di prima della migrazione (senza conto né tipo) vale come fissa', async () => {
    const pool = fakePool([{ match: /FROM recurring_rules/, result: { rows: [regola({ account: undefined, cost_type: undefined })] } }]);
    await R.materialize(pool, 1, OTT);
    const ins = pool.calls.find(c => c.sql.startsWith('INSERT INTO expenses'));
    assert.deepStrictEqual(ins.params.slice(-3), [null, 'fixed', true]);
});

test('salvare la voce di una regola variabile la conferma, senza toccare la stima della regola', async () => {
    const pool = fakePool();
    const out = await R.afterExpenseSaved(pool, { id: 90, company_id: 1, auto_source: 'rule:7', auto_period: '2026-10', cost_type: 'variable', amount: '27.84' });
    assert.deepStrictEqual(out, { confirmed: true });
    assert.strictEqual(pool.calls.length, 1);
    assert.match(pool.calls[0].sql, /UPDATE expenses SET amount_confirmed = TRUE/);
    assert.deepStrictEqual(pool.calls[0].params, [90]);
    assert.ok(!pool.calls.some(c => /recurring_rules/.test(c.sql)));
});

test('le voci fisse, manuali e delle API non vengono toccate', async () => {
    for (const exp of [
        { id: 1, company_id: 1, auto_source: 'rule:7', auto_period: '2026-10', cost_type: 'fixed', amount: '25' },
        { id: 2, company_id: 1, auto_source: null, auto_period: null, cost_type: null, amount: '10' },
        { id: 3, company_id: 1, auto_source: 'openai', auto_period: '2026-10', cost_type: null, amount: '12' }
    ]) {
        const pool = fakePool();
        assert.deepStrictEqual(await R.afterExpenseSaved(pool, exp), { confirmed: false });
        assert.strictEqual(pool.calls.length, 0);
    }
});
