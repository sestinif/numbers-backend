const test = require('node:test');
const assert = require('node:assert');
const access = require('../access-code');

const CODE = 'k3Vq9ZpT1xYw7LmN4sRb8HdF2gJc6UeA';
const ENV = { NUMBERS_ACCESS_CODE: CODE };

test('senza codice su Render l\'accesso a codice è spento', () => {
    assert.strictEqual(access.isEnabled({}), false);
    assert.strictEqual(access.isEnabled({ NUMBERS_ACCESS_CODE: '   ' }), false);
    assert.strictEqual(access.isEnabled(ENV), true);
});

test('entra solo il codice giusto, identico carattere per carattere', () => {
    assert.strictEqual(access.matches(CODE, ENV), true);
    assert.strictEqual(access.matches(' ' + CODE + '\n', ENV), true, 'spazi e a capo ai lati non contano (copia e incolla)');
    assert.strictEqual(access.matches(CODE.toLowerCase(), ENV), false);
    assert.strictEqual(access.matches(CODE.slice(0, -1), ENV), false);
    assert.strictEqual(access.matches(CODE + 'x', ENV), false);
    assert.strictEqual(access.matches('', ENV), false);
    assert.strictEqual(access.matches(null, ENV), false);
    assert.strictEqual(access.matches(undefined, ENV), false);
});

test('se il codice non è configurato non entra nessuno, nemmeno col vuoto', () => {
    assert.strictEqual(access.matches('', {}), false);
    assert.strictEqual(access.matches('qualcosa', {}), false);
    assert.strictEqual(access.matches('   ', { NUMBERS_ACCESS_CODE: '   ' }), false);
});

test('un codice corto viene segnalato come debole', () => {
    assert.strictEqual(access.isStrong(ENV), true);
    assert.strictEqual(access.isStrong({ NUMBERS_ACCESS_CODE: 'password123' }), false);
    assert.strictEqual(access.MIN_LENGTH, 24);
});

test('la versione cambia quando cambia il codice, e non lo rivela', () => {
    const v1 = access.version(ENV);
    const v2 = access.version({ NUMBERS_ACCESS_CODE: CODE + '!' });
    assert.match(v1, /^[0-9a-f]{16}$/);
    assert.notStrictEqual(v1, v2);
    assert.strictEqual(access.version(ENV), v1);
    assert.ok(!CODE.includes(v1) && !v1.includes(CODE.slice(0, 6)));
    assert.strictEqual(access.version({}), null);
});

test('un gettone resta valido solo finché il codice è lo stesso', () => {
    const cv = access.version(ENV);
    assert.strictEqual(access.tokenStillValid({ id: 1, cv }, ENV), true);
    assert.strictEqual(access.tokenStillValid({ id: 1, cv }, { NUMBERS_ACCESS_CODE: CODE + '!' }), false, 'codice cambiato: fuori tutti');
    assert.strictEqual(access.tokenStillValid({ id: 1 }, ENV), false, 'gettone del vecchio accesso con email: fuori');
    assert.strictEqual(access.tokenStillValid({ id: 1 }, {}), true, 'accesso a codice spento: vale il gettone normale');
    assert.strictEqual(access.tokenStillValid({ id: 1, cv }, {}), true);
});

test('il proprietario è quello indicato, o l\'unico utente che ha un\'azienda', async () => {
    const pool = (rowsByQuery) => ({ query: async (sql, params) => ({ rows: rowsByQuery(sql, params) }) });
    const byEmail = pool((sql, params) => /WHERE email/.test(sql) ? (params[0] === 'fede@example.com' ? [{ id: 7, email: 'fede@example.com', name: 'Fede' }] : []) : []);
    assert.deepStrictEqual(await access.resolveOwner(byEmail, { NUMBERS_OWNER_EMAIL: ' Fede@Example.com ' }), { id: 7, email: 'fede@example.com', name: 'Fede' });
    await assert.rejects(() => access.resolveOwner(byEmail, { NUMBERS_OWNER_EMAIL: 'altro@example.com' }), /NUMBERS_OWNER_EMAIL/);

    const oneOwner = pool(() => [{ id: 3, email: 'solo@example.com', name: null }]);
    assert.deepStrictEqual(await access.resolveOwner(oneOwner, {}), { id: 3, email: 'solo@example.com', name: null });
    const twoOwners = pool(() => [{ id: 3 }, { id: 9 }]);
    await assert.rejects(() => access.resolveOwner(twoOwners, {}), /NUMBERS_OWNER_EMAIL/);
    const nobody = pool(() => []);
    await assert.rejects(() => access.resolveOwner(nobody, {}), /NUMBERS_OWNER_EMAIL/);
});
