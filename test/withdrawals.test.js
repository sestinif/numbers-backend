const test = require('node:test');
const assert = require('node:assert');
const w = require('../withdrawals');

test('si parte dal 1 novembre 2026: prima non conta niente', () => {
    assert.strictEqual(w.START_DATE, '2026-11-01');
    assert.strictEqual(w.isInScope('2026-10-31'), false);
    assert.strictEqual(w.isInScope('2026-11-01'), true);
    assert.strictEqual(w.isInScope('2027-02-10'), true);
    assert.strictEqual(w.isInScope('boh'), false);
    assert.strictEqual(w.isInScope(null), false);
});

test('la scelta del prelievo: tutto, metà, oppure niente', () => {
    assert.strictEqual(w.shareFrom('all'), 1);
    assert.strictEqual(w.shareFrom('half'), 0.5);
    assert.strictEqual(w.shareFrom(1), 1);
    assert.strictEqual(w.shareFrom('0.5'), 0.5);
    for (const none of ['none', '', null, undefined, 0, 'boh', 0.3, 2]) assert.strictEqual(w.shareFrom(none), null, String(none));
    assert.strictEqual(w.shareName(1), 'all');
    assert.strictEqual(w.shareName('0.50'), 'half');
    assert.strictEqual(w.shareName(null), 'none');
});

test('dal riferimento di Wise si ricava il numero del bonifico', () => {
    assert.strictEqual(w.transferIdFromReference('TRANSFER-1234567'), 1234567);
    assert.strictEqual(w.transferIdFromReference('CARD-55'), null);
    assert.strictEqual(w.transferIdFromReference('TRANSFER-abc'), null);
    assert.strictEqual(w.transferIdFromReference(null), null);
});

test('il giorno si legge in ora italiana: le 23:30 UTC del 31/10 sono già il 1 novembre', () => {
    assert.strictEqual(w.dayInRome('2026-10-31T23:30:00.000Z'), '2026-11-01');
    assert.strictEqual(w.dayInRome('2026-11-03T09:00:00.000Z'), '2026-11-03');
    assert.strictEqual(w.dayInRome(new Date('2026-11-30T22:59:00.000Z')), '2026-11-30');
    assert.strictEqual(w.dayInRome('boh'), null);
});

test('il mese è scritto AAAA-MM, e il mese in corso è quello italiano', () => {
    assert.strictEqual(w.isMonth('2026-11'), true);
    assert.strictEqual(w.isMonth('2026-13'), false);
    assert.strictEqual(w.isMonth('2026-1'), false);
    assert.strictEqual(w.currentMonth(new Date('2026-11-30T23:30:00.000Z')), '2026-12');
});

test('la cifra che conta: intero o metà, arrotondata ai centesimi', () => {
    assert.strictEqual(w.counted(850, 1), 850);
    assert.strictEqual(w.counted(850, 0.5), 425);
    assert.strictEqual(w.counted(333.33, 0.5), 166.67);
    assert.strictEqual(w.counted(10, null), 0);
});

test('il riepilogo del mese somma solo quello che conta, e dice quanto è la metà', () => {
    const items = [
        { date: '2026-11-03', label: 'Federico – Revolut Personale', amount_eur: 800, share: 1 },
        { date: '2026-11-05', label: 'Affitto', amount_eur: 600, share: 0.5 },
        { date: '2026-11-20', label: 'Federico – Revolut Personale', amount_eur: 150.5, share: 1 },
    ];
    const out = w.summarize(items, '2026-11');
    assert.strictEqual(out.month, '2026-11');
    assert.strictEqual(out.total_eur, 1250.5);
    assert.deepStrictEqual(out.items.map(i => i.counted_eur), [800, 300, 150.5]);
    assert.strictEqual(w.summarize([], '2026-11').total_eur, 0);
});

test('un mese prima di novembre 2026 non ha niente da mostrare', () => {
    assert.strictEqual(w.monthInScope('2026-10'), false);
    assert.strictEqual(w.monthInScope('2026-11'), true);
    assert.strictEqual(w.monthInScope('2027-01'), true);
});

test('la chiave per leggere i prelievi: a tempo costante, e spenta se è corta o manca', () => {
    const env = { NUMBERS_EXPORT_KEY: 'k3Vq9ZpT1xYw7LmN4sRb8HdF2gJc' };
    assert.strictEqual(w.exportEnabled(env), true);
    assert.strictEqual(w.exportEnabled({ NUMBERS_EXPORT_KEY: 'corta' }), false);
    assert.strictEqual(w.exportEnabled({}), false);
    assert.strictEqual(w.keyMatches('k3Vq9ZpT1xYw7LmN4sRb8HdF2gJc', env), true);
    assert.strictEqual(w.keyMatches(' k3Vq9ZpT1xYw7LmN4sRb8HdF2gJc ', env), true);
    assert.strictEqual(w.keyMatches('k3Vq9ZpT1xYw7LmN4sRb8HdF2gJd', env), false);
    assert.strictEqual(w.keyMatches('', env), false);
    assert.strictEqual(w.keyMatches(undefined, env), false);
    assert.strictEqual(w.keyMatches('qualsiasi', {}), false);
    assert.strictEqual(w.keyMatches('', { NUMBERS_EXPORT_KEY: '' }), false);
});
