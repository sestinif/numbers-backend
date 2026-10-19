const test = require('node:test');
const assert = require('node:assert');
const wise = require('../wise');

// Finto Wise: risponde in base a metodo e percorso, e ricorda le chiamate.
function fakeWise(routes) {
    const calls = [];
    const fetchImpl = async (url, opts = {}) => {
        const u = new URL(url);
        const key = `${opts.method || 'GET'} ${u.pathname}`;
        calls.push({ key, url, headers: opts.headers, body: opts.body ? JSON.parse(opts.body) : null });
        const hit = routes[key];
        if (!hit) return { ok: false, status: 404, text: async () => JSON.stringify({ error: 'non previsto: ' + key }) };
        const out = typeof hit === 'function' ? hit(u, opts) : hit;
        const status = out && out.__status ? out.__status : 200;
        const body = out && out.__status ? out.body : out;
        return { ok: status < 400, status, text: async () => JSON.stringify(body) };
    };
    return { fetchImpl, calls };
}

const PROFILES = [
    { id: 11, type: 'PERSONAL', fullName: 'Federico Sestini' },
    { id: 22, type: 'BUSINESS', businessName: 'Scaling Catalyst LLC' },
];

test('senza token il collegamento risulta non configurato', () => {
    assert.strictEqual(wise.isConfigured({}), false);
    assert.strictEqual(wise.isConfigured({ WISE_API_TOKEN: '  ' }), false);
    assert.strictEqual(wise.isConfigured({ WISE_API_TOKEN: 'abc' }), true);
});

test('il profilo usato è quello business, e il token viaggia solo nell\'intestazione', async () => {
    const { fetchImpl, calls } = fakeWise({ 'GET /v2/profiles': PROFILES });
    const client = wise.createClient({ token: 'tok-123', fetchImpl });
    assert.strictEqual(await client.profileId(), 22);
    assert.strictEqual(await client.profileId(), 22);
    assert.strictEqual(calls.length, 1, 'il profilo si chiede una volta sola');
    assert.strictEqual(calls[0].headers.Authorization, 'Bearer tok-123');
    assert.ok(!calls[0].url.includes('tok-123'));
});

test('se il profilo è fissato a mano non si chiede a Wise', async () => {
    const { fetchImpl, calls } = fakeWise({});
    const client = wise.createClient({ token: 't', profileId: '77', fetchImpl });
    assert.strictEqual(await client.profileId(), 77);
    assert.strictEqual(calls.length, 0);
});

test('i saldi arrivano puliti: valuta e cifra, i vuoti in fondo', async () => {
    const { fetchImpl, calls } = fakeWise({
        'GET /v2/profiles': PROFILES,
        'GET /v4/profiles/22/balances': [
            { id: 1, currency: 'GBP', amount: { value: 0, currency: 'GBP' } },
            { id: 2, currency: 'USD', amount: { value: 12480, currency: 'USD' } },
            { id: 3, currency: 'EUR', amount: { value: 3210.5, currency: 'EUR' } },
        ],
    });
    const client = wise.createClient({ token: 't', fetchImpl });
    assert.deepStrictEqual(await client.balances(), [
        { currency: 'USD', amount: 12480 },
        { currency: 'EUR', amount: 3210.5 },
        { currency: 'GBP', amount: 0 },
    ]);
    assert.ok(calls[1].url.includes('types=STANDARD'));
});

test('i beneficiari si leggono a pagine e si riassumono in nome, valuta e conto', async () => {
    const { fetchImpl } = fakeWise({
        'GET /v2/profiles': PROFILES,
        'GET /v2/accounts': (u) => u.searchParams.get('seekPosition') === '5'
            ? { content: [{ id: 6, name: { fullName: 'Video Editor' }, currency: 'USD', country: 'US', type: 'aba', active: true, details: { accountNumber: '000123456789' } }], seekPositionForNext: null }
            : { content: [
                { id: 5, name: { fullName: 'Maria Rossi' }, currency: 'EUR', country: 'IT', type: 'iban', active: true, details: { IBAN: 'IT60X0542811101000000123456' } },
                { id: 4, name: { fullName: 'Vecchio' }, currency: 'EUR', type: 'iban', active: false, details: {} },
            ], seekPositionForNext: 5 },
    });
    const client = wise.createClient({ token: 't', fetchImpl });
    assert.deepStrictEqual(await client.recipients(), [
        { id: 5, name: 'Maria Rossi', currency: 'EUR', country: 'IT', type: 'iban', account: 'IT60 •••• 3456' },
        { id: 6, name: 'Video Editor', currency: 'USD', country: 'US', type: 'aba', account: '•••• 6789' },
    ]);
});

test('un beneficiario nuovo con IBAN si crea sul profilo business', async () => {
    const { fetchImpl, calls } = fakeWise({
        'GET /v2/profiles': PROFILES,
        'POST /v1/accounts': { id: 9, accountHolderName: 'Maria Rossi', currency: 'EUR', type: 'iban', country: 'IT', details: { IBAN: 'IT60X0542811101000000123456' } },
    });
    const client = wise.createClient({ token: 't', fetchImpl });
    const made = await client.createIbanRecipient({ name: ' Maria Rossi ', iban: 'it60 x054 2811 1010 0000 0123 456', legalType: 'PRIVATE' });
    assert.deepStrictEqual(calls[1].body, {
        currency: 'EUR', type: 'iban', profile: 22, accountHolderName: 'Maria Rossi',
        details: { legalType: 'PRIVATE', IBAN: 'IT60X0542811101000000123456' },
    });
    assert.deepStrictEqual(made, { id: 9, name: 'Maria Rossi', currency: 'EUR', country: 'IT', type: 'iban', account: 'IT60 •••• 3456' });
});

test('un IBAN scritto male si ferma prima di arrivare a Wise', async () => {
    const { fetchImpl, calls } = fakeWise({ 'GET /v2/profiles': PROFILES });
    const client = wise.createClient({ token: 't', fetchImpl });
    await assert.rejects(() => client.createIbanRecipient({ name: 'Maria', iban: 'IT60X05428' }), /IBAN/);
    await assert.rejects(() => client.createIbanRecipient({ name: '', iban: 'IT60X0542811101000000123456' }), /nome/i);
    assert.strictEqual(calls.length, 0);
});

const QUOTE = {
    id: 'q-1', sourceCurrency: 'USD', targetCurrency: 'EUR', rate: 0.92,
    paymentOptions: [
        { payIn: 'BANK_TRANSFER', payOut: 'BANK_TRANSFER', disabled: false, sourceAmount: 385.1, targetAmount: 350, fee: { total: 4.6 }, formattedEstimatedDelivery: 'by Tuesday' },
        { payIn: 'BALANCE', payOut: 'BANK_TRANSFER', disabled: false, sourceAmount: 382.45, targetAmount: 350, fee: { total: 2.02 }, formattedEstimatedDelivery: 'by Monday', estimatedDelivery: '2026-10-12T10:00:00Z' },
    ],
};

test('il preventivo è quello pagato dal saldo, per la cifra che deve arrivare', async () => {
    const { fetchImpl, calls } = fakeWise({ 'GET /v2/profiles': PROFILES, 'POST /v3/profiles/22/quotes': QUOTE });
    const client = wise.createClient({ token: 't', fetchImpl });
    const q = await client.quote({ recipientId: 5, amount: 350, targetCurrency: 'EUR', sourceCurrency: 'USD' });
    assert.deepStrictEqual(calls[1].body, { sourceCurrency: 'USD', targetCurrency: 'EUR', targetAmount: 350, targetAccount: 5, payOut: 'BANK_TRANSFER' });
    assert.deepStrictEqual(q, {
        id: 'q-1', sourceCurrency: 'USD', sourceAmount: 382.45, targetCurrency: 'EUR', targetAmount: 350,
        fee: 2.02, rate: 0.92, delivery: '2026-10-12T10:00:00Z',
    });
});

test('se dal saldo non si può pagare, il preventivo lo dice chiaro', async () => {
    const blocked = { ...QUOTE, paymentOptions: [{ payIn: 'BALANCE', disabled: true, disabledReason: { message: 'Saldo insufficiente' } }] };
    const { fetchImpl } = fakeWise({ 'GET /v2/profiles': PROFILES, 'POST /v3/profiles/22/quotes': blocked });
    const client = wise.createClient({ token: 't', fetchImpl });
    await assert.rejects(() => client.quote({ recipientId: 5, amount: 350, targetCurrency: 'EUR', sourceCurrency: 'USD' }), /Saldo insufficiente/);
});

test('una cifra che non è un numero positivo non parte', async () => {
    const { fetchImpl, calls } = fakeWise({ 'GET /v2/profiles': PROFILES });
    const client = wise.createClient({ token: 't', fetchImpl });
    for (const bad of [0, -5, 'abc', null, Infinity]) {
        await assert.rejects(() => client.quote({ recipientId: 5, amount: bad, targetCurrency: 'EUR', sourceCurrency: 'EUR' }), /importo/i);
    }
    assert.strictEqual(calls.length, 0);
});

test('il bonifico si prepara con la chiave anti-doppione e la causale', async () => {
    const { fetchImpl, calls } = fakeWise({
        'POST /v1/transfers': { id: 900, status: 'incoming_payment_waiting', targetAccount: 5, sourceCurrency: 'USD', sourceValue: 382.45, targetCurrency: 'EUR', targetValue: 350, created: '2026-10-11 09:00:00', details: { reference: 'Compenso ottobre' } },
    });
    const client = wise.createClient({ token: 't', profileId: 22, fetchImpl });
    const t = await client.createTransfer({ recipientId: 5, quoteId: 'q-1', reference: 'Compenso ottobre', key: '11111111-2222-4333-8444-555555555555' });
    assert.deepStrictEqual(calls[0].body, {
        targetAccount: 5, quoteUuid: 'q-1', customerTransactionId: '11111111-2222-4333-8444-555555555555',
        details: { reference: 'Compenso ottobre' },
    });
    assert.strictEqual(t.id, 900);
    assert.strictEqual(t.status, 'incoming_payment_waiting');
});

test('preparare, leggere e annullare un bonifico non fa mai partire i soldi', async () => {
    const { fetchImpl, calls } = fakeWise({
        'GET /v2/profiles': PROFILES, 'POST /v3/profiles/22/quotes': QUOTE,
        'POST /v1/transfers': { id: 900, status: 'incoming_payment_waiting' },
        'GET /v1/transfers/900': { id: 900, status: 'incoming_payment_waiting' },
        'PUT /v1/transfers/900/cancel': { id: 900, status: 'cancelled' },
    });
    const client = wise.createClient({ token: 't', fetchImpl });
    await client.quote({ recipientId: 5, amount: 350, targetCurrency: 'EUR', sourceCurrency: 'USD' });
    await client.createTransfer({ recipientId: 5, quoteId: 'q-1', reference: 'x', key: '11111111-2222-4333-8444-555555555555' });
    await client.getTransfer(900);
    assert.strictEqual((await client.cancelTransfer(900)).status, 'cancelled');
    assert.ok(calls.every(c => !/payments/.test(c.key)), 'nessuna chiamata a /payments finché non si chiede di pagare');
});

test('far partire il bonifico: paga dal saldo, sul profilo business', async () => {
    const { fetchImpl, calls } = fakeWise({
        'GET /v2/profiles': PROFILES,
        'POST /v3/profiles/22/transfers/900/payments': { status: 'COMPLETED', type: 'BALANCE', balanceTransactionId: 5 },
    });
    const client = wise.createClient({ token: 't', fetchImpl });
    assert.deepStrictEqual(await client.fundTransfer(900), { status: 'COMPLETED', already: false });
    assert.deepStrictEqual(calls[1].body, { type: 'BALANCE' });
    assert.strictEqual(calls[1].key, 'POST /v3/profiles/22/transfers/900/payments');
});

test('se Wise rifiuta il pagamento l\'errore dice perché, in italiano', async () => {
    const reject = code => fakeWise({ 'GET /v2/profiles': PROFILES, 'POST /v3/profiles/22/transfers/900/payments': { status: 'REJECTED', errorCode: code, errorMessage: 'x' } });
    for (const [code, re] of [['balance.insufficient-funds', /saldo.*non basta/i], ['transfer.invalid-state', /non è più in attesa/i],
                              ['balance.no-balance-for-currency', /saldo.*valuta/i], ['codice.nuovo.mai.visto', /rifiutato/i]]) {
        const { fetchImpl } = reject(code);
        await assert.rejects(() => wise.createClient({ token: 't', fetchImpl }).fundTransfer(900), e => re.test(e.message) && e.status === 422, code);
    }
});

test('un bonifico già pagato non è un errore: si risincronizza e basta', async () => {
    const { fetchImpl } = fakeWise({ 'GET /v2/profiles': PROFILES, 'POST /v3/profiles/22/transfers/900/payments': { status: 'REJECTED', errorCode: 'payment.exists' } });
    assert.deepStrictEqual(await wise.createClient({ token: 't', fetchImpl }).fundTransfer(900), { status: 'COMPLETED', already: true });
});

test('se il conto non permette di pagare da API, il bonifico resta preparato e lo dice', async () => {
    const { fetchImpl } = fakeWise({ 'GET /v2/profiles': PROFILES, 'POST /v3/profiles/22/transfers/900/payments': { __status: 403, body: { error: 'forbidden' } } });
    await assert.rejects(() => wise.createClient({ token: 'tok-segreto', fetchImpl }).fundTransfer(900),
        e => /resta preparato/i.test(e.message) && e.status === 502 && !e.message.includes('tok-segreto'));
});

test('un errore di Wise diventa un messaggio leggibile, senza il token dentro', async () => {
    const { fetchImpl } = fakeWise({
        'POST /v1/transfers': { __status: 422, body: { errors: [{ code: 'x', message: 'Quote cannot be accepted with this request due to missing approval.' }] } },
        'GET /v1/transfers/1': { __status: 401, body: { error: 'invalid_token' } },
    });
    const client = wise.createClient({ token: 'tok-segreto', profileId: 22, fetchImpl });
    await assert.rejects(() => client.createTransfer({ recipientId: 5, quoteId: 'q', reference: '', key: '11111111-2222-4333-8444-555555555555' }),
        e => e.status === 422 && /missing approval/.test(e.message) && !e.message.includes('tok-segreto'));
    await assert.rejects(() => client.getTransfer(1), e => e.status === 401 && /token/i.test(e.message));
});

test('lo stato di Wise si traduce in quattro situazioni chiare', () => {
    assert.deepStrictEqual(wise.statusInfo('incoming_payment_waiting'), { state: 'waiting', label: 'Da confermare su Wise', final: false });
    assert.deepStrictEqual(wise.statusInfo('processing'), { state: 'paid', label: 'In lavorazione', final: false });
    assert.deepStrictEqual(wise.statusInfo('funds_converted'), { state: 'paid', label: 'In lavorazione', final: false });
    assert.deepStrictEqual(wise.statusInfo('outgoing_payment_sent'), { state: 'paid', label: 'Inviato', final: true });
    assert.deepStrictEqual(wise.statusInfo('sending'), { state: 'paid', label: 'In invio', final: false });
    assert.deepStrictEqual(wise.statusInfo('cancelled'), { state: 'cancelled', label: 'Annullato', final: true });
    assert.deepStrictEqual(wise.statusInfo('funds_refunded'), { state: 'returned', label: 'Tornato indietro', final: true });
    assert.deepStrictEqual(wise.statusInfo('bounced_back'), { state: 'returned', label: 'Tornato indietro', final: false });
    assert.deepStrictEqual(wise.statusInfo('boh'), { state: 'waiting', label: 'boh', final: false });
});

test('la spesa nasce solo quando i soldi sono partiti davvero', () => {
    assert.strictEqual(wise.shouldTrackExpense({ track_expense: true, expense_id: null, status: 'incoming_payment_waiting' }), false);
    assert.strictEqual(wise.shouldTrackExpense({ track_expense: true, expense_id: null, status: 'processing' }), true);
    assert.strictEqual(wise.shouldTrackExpense({ track_expense: true, expense_id: null, status: 'outgoing_payment_sent' }), true);
    assert.strictEqual(wise.shouldTrackExpense({ track_expense: true, expense_id: 7, status: 'outgoing_payment_sent' }), false);
    assert.strictEqual(wise.shouldTrackExpense({ track_expense: false, expense_id: null, status: 'outgoing_payment_sent' }), false);
    assert.strictEqual(wise.shouldTrackExpense({ track_expense: true, expense_id: null, status: 'cancelled' }), false);
});
