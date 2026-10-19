const test = require('node:test');
const assert = require('node:assert');
const pin = require('../pay-pin');

// Un PIN finto, solo per i test: quello vero sta su Render e non entra mai nel repo.
const ENV = { WISE_PAY_PIN: '4827' };

test('il PIN è attivo solo se su Render c\'è e sono da 4 a 8 cifre', () => {
    assert.strictEqual(pin.isEnabled(ENV), true);
    assert.strictEqual(pin.isEnabled({ WISE_PAY_PIN: ' 4827 ' }), true, 'spazi ai lati: copia e incolla');
    assert.strictEqual(pin.isEnabled({}), false);
    assert.strictEqual(pin.isEnabled({ WISE_PAY_PIN: '' }), false);
    assert.strictEqual(pin.isEnabled({ WISE_PAY_PIN: '123' }), false, 'troppo corto');
    assert.strictEqual(pin.isEnabled({ WISE_PAY_PIN: '123456789' }), false, 'troppo lungo');
    assert.strictEqual(pin.isEnabled({ WISE_PAY_PIN: 'abcd' }), false, 'solo cifre');
});

test('passa solo il PIN giusto, e uno scritto con spazi ai lati', () => {
    assert.strictEqual(pin.matches('4827', ENV), true);
    assert.strictEqual(pin.matches(' 4827\n', ENV), true);
    assert.strictEqual(pin.matches(4827, ENV), true, 'arriva anche come numero dal JSON');
    assert.strictEqual(pin.matches('4828', ENV), false);
    assert.strictEqual(pin.matches('48270', ENV), false);
    assert.strictEqual(pin.matches('482', ENV), false);
    assert.strictEqual(pin.matches('', ENV), false);
    assert.strictEqual(pin.matches(null, ENV), false);
    assert.strictEqual(pin.matches(undefined, ENV), false);
    assert.strictEqual(pin.matches({ toString: () => '4827' }, ENV), false, 'un oggetto non è un PIN');
});

test('senza PIN configurato non passa niente, nemmeno il vuoto', () => {
    assert.strictEqual(pin.matches('', {}), false);
    assert.strictEqual(pin.matches('4827', {}), false);
    assert.strictEqual(pin.matches('', { WISE_PAY_PIN: '   ' }), false);
});

function clock(start = 1_700_000_000_000) {
    const c = { t: start, now: () => c.t, advance(ms) { c.t += ms; } };
    return c;
}
const MIN = 60 * 1000;

test('cinque PIN sbagliati bloccano per quindici minuti, e poi si riprova', () => {
    const c = clock();
    const g = pin.createGuard({ now: c.now });
    for (let i = 0; i < 5; i++) {
        assert.strictEqual(g.check('azienda-1').allowed, true, `tentativo ${i + 1} ammesso`);
        g.fail('azienda-1');
    }
    const blocked = g.check('azienda-1');
    assert.strictEqual(blocked.allowed, false);
    assert.ok(blocked.retryAfterSec > 14 * 60 && blocked.retryAfterSec <= 15 * 60, String(blocked.retryAfterSec));
    c.advance(10 * MIN);
    assert.strictEqual(g.check('azienda-1').allowed, false, 'dopo 10 minuti è ancora chiuso');
    c.advance(6 * MIN);
    assert.strictEqual(g.check('azienda-1').allowed, true, 'dopo 16 minuti si riprova');
});

test('il blocco è per azienda: cambiare indirizzo o accesso non lo aggira', () => {
    const c = clock();
    const g = pin.createGuard({ now: c.now });
    for (let i = 0; i < 5; i++) g.fail('azienda-1');
    assert.strictEqual(g.check('azienda-1').allowed, false);
    assert.strictEqual(g.check('azienda-2').allowed, true, 'un\'altra azienda non è toccata');
});

test('chi insiste tutto il giorno si ferma fino al giorno dopo', () => {
    const c = clock();
    const g = pin.createGuard({ now: c.now, maxPerDay: 12 });
    let tried = 0;
    while (tried < 100) {
        const r = g.check('a');
        if (!r.allowed) {
            if (r.retryAfterSec > 15 * 60) break;   // è scattato il blocco lungo
            c.advance(r.retryAfterSec * 1000 + 1000); // aspetta e riprova
            continue;
        }
        g.fail('a'); tried++;
    }
    assert.strictEqual(tried, 12, 'dopo 12 PIN sbagliati in 24 ore il blocco è lungo');
    const r = g.check('a');
    assert.strictEqual(r.allowed, false);
    assert.ok(r.retryAfterSec > 60 * MIN / 1000, 'ore, non minuti');
    c.advance(24 * 60 * MIN + 1000);
    assert.strictEqual(g.check('a').allowed, true, 'dopo 24 ore si riparte');
});

test('un PIN giusto azzera i tentativi sbagliati', () => {
    const c = clock();
    const g = pin.createGuard({ now: c.now });
    for (let i = 0; i < 4; i++) g.fail('a');
    g.succeed('a');
    for (let i = 0; i < 4; i++) { assert.strictEqual(g.check('a').allowed, true); g.fail('a'); }
    assert.strictEqual(g.check('a').allowed, true, 'quattro sbagli dopo il giusto: ancora ammesso');
});

test('la memoria dei tentativi non cresce senza fine', () => {
    const c = clock();
    const g = pin.createGuard({ now: c.now });
    for (let i = 0; i < 500; i++) { g.fail('a'); c.advance(1000); }
    assert.ok(g.size('a') <= 50, 'tiene solo gli ultimi tentativi: ' + g.size('a'));
});

test('una richiesta di invio: senza PIN attivo, con PIN sbagliato, con troppi sbagli, con PIN giusto', () => {
    const c = clock();
    const guard = pin.createGuard({ now: c.now });
    const logs = [];
    const ask = (given, env = ENV) => pin.checkRequest({ guard, companyId: 13, pin: given, env, log: m => logs.push(m) });

    assert.deepStrictEqual(ask('4827', {}), { status: 400, error: 'L\'invio con il PIN non è attivo: i bonifici si confermano dall\'app di Wise.' });
    assert.strictEqual(ask('4827'), null, 'PIN giusto: si procede');
    assert.deepStrictEqual(ask('0000'), { status: 400, error: 'PIN sbagliato.' });
    assert.strictEqual(logs.length, 1);
    assert.ok(!logs.join(' ').includes('0000') && !logs.join(' ').includes('4827'), 'nei log non finisce nessun PIN');

    for (let i = 0; i < 4; i++) ask('1111');
    const blocked = ask('4827');
    assert.strictEqual(blocked.status, 429, 'bloccato anche col PIN giusto: è questo che ferma chi prova a raffica');
    assert.match(blocked.error, /riprova tra \d+ minuti/);
    c.advance(16 * MIN);
    assert.strictEqual(ask('4827'), null, 'passato il blocco si riparte');
    assert.ok([400, 429].every(code => code !== 401 && code !== 403));
});

test('il blocco lungo dice «fino a domani»', () => {
    const c = clock();
    const guard = pin.createGuard({ now: c.now, maxPerDay: 6 });
    const ask = given => pin.checkRequest({ guard, companyId: 1, pin: given, env: ENV });
    let last;
    for (let i = 0; i < 40 && !(last && last.status === 429 && /domani/.test(last.error)); i++) {
        last = ask('1111');
        if (last.status === 429) c.advance(last.error.match(/(\d+) minuti/) ? (parseInt(last.error.match(/(\d+) minuti/)[1], 10) * 60 + 1) * 1000 : 1000);
    }
    assert.match(last.error, /fino a domani/);
});
