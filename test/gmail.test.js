const test = require('node:test');
const assert = require('node:assert');
const gmail = require('../gmail');

const ENV = { GMAIL_CLIENT_ID: 'id', GMAIL_CLIENT_SECRET: 'sec', GMAIL_REFRESH_TOKEN: 'ref', GMAIL_FROM: 'info@scalingcatalyst.com' };

test('è collegato solo se ci sono tutti e quattro i valori', () => {
    assert.strictEqual(gmail.isConfigured(ENV), true);
    assert.strictEqual(gmail.isConfigured({}), false);
    for (const k of Object.keys(ENV)) assert.strictEqual(gmail.isConfigured({ ...ENV, [k]: ' ' }), false, k);
});

test('gli indirizzi si controllano e si puliscono', () => {
    assert.deepStrictEqual(gmail.parseAddresses(' Mario@Example.com , anna@studio.it;luca@x.io '), ['mario@example.com', 'anna@studio.it', 'luca@x.io']);
    assert.deepStrictEqual(gmail.parseAddresses(['a@b.it', 'a@b.it']), ['a@b.it'], 'i doppi si tolgono');
    assert.deepStrictEqual(gmail.parseAddresses(''), []);
    assert.throws(() => gmail.parseAddresses('mario@'), /indirizzo/i);
    assert.throws(() => gmail.parseAddresses('a@b.it, non-una-email'), /non-una-email/);
    assert.throws(() => gmail.parseAddresses('a@b.it\nBcc: spia@x.it'), /indirizzo/i, 'niente a capo: non si infilano intestazioni');
});

test('l\'oggetto con accenti viaggia codificato, quello semplice resta com\'è', () => {
    assert.strictEqual(gmail.encodeHeader('Fattura n. 34'), 'Fattura n. 34');
    const enc = gmail.encodeHeader('Fattura n. 34 — è pronta');
    assert.match(enc, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
    assert.strictEqual(Buffer.from(enc.slice(10, -2), 'base64').toString('utf8'), 'Fattura n. 34 — è pronta');
    assert.strictEqual(gmail.encodeHeader('Oggetto\r\nBcc: spia@x.it'), 'Oggetto Bcc: spia@x.it', 'gli a capo spariscono');
});

test('il messaggio senza allegati è testo semplice, con mittente, destinatari e copia nascosta', () => {
    const raw = gmail.buildMime({ from: 'info@scalingcatalyst.com', fromName: 'Scaling Catalyst LLC', to: ['mario@example.com'], bcc: ['fede@example.com'], subject: 'Ciao', text: 'Buongiorno,\nriga due è qui.' });
    const [head, body] = raw.split('\r\n\r\n');
    assert.match(head, /^From: Scaling Catalyst LLC <info@scalingcatalyst\.com>$/m);
    assert.match(head, /^To: mario@example\.com$/m);
    assert.match(head, /^Bcc: fede@example\.com$/m);
    assert.match(head, /^Subject: Ciao$/m);
    assert.match(head, /^Content-Type: text\/plain; charset="UTF-8"$/m);
    assert.strictEqual(Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString('utf8'), 'Buongiorno,\r\nriga due è qui.');
});

test('con un allegato diventa un messaggio in più parti, e il PDF torna identico', () => {
    const pdf = Buffer.from('%PDF-1.4 finto contenuto è');
    const raw = gmail.buildMime({ from: 'info@scalingcatalyst.com', to: ['mario@example.com'], subject: 'Fattura', text: 'In allegato.', attachments: [{ filename: 'Fattura 34 — ottobre.pdf', mimeType: 'application/pdf', content: pdf }] });
    const boundary = /boundary="([^"]+)"/.exec(raw)[1];
    const parts = raw.split('--' + boundary);
    assert.strictEqual(parts.length, 4, 'intestazioni, testo, allegato, chiusura');
    assert.match(parts[2], /Content-Type: application\/pdf/);
    assert.match(parts[2], /Content-Disposition: attachment; filename\*=UTF-8''Fattura%2034%20%E2%80%94%20ottobre\.pdf/);
    const b64 = parts[2].split('\r\n\r\n')[1].replace(/\r\n/g, '');
    assert.ok(Buffer.from(b64, 'base64').equals(pdf));
    assert.strictEqual(parts[3].trim(), '--');
});

test('un nome di file con dentro un percorso o un a capo viene ripulito', () => {
    assert.strictEqual(gmail.safeFilename('../../etc/passwd'), 'passwd');
    assert.strictEqual(gmail.safeFilename('fattura\r\nX: y.pdf'), 'fattura X y.pdf');
    assert.strictEqual(gmail.safeFilename(''), 'allegato');
});

test('gli allegati hanno un tetto di peso e di numero', () => {
    const big = { filename: 'a.pdf', base64: Buffer.alloc(9 * 1024 * 1024).toString('base64') };
    assert.throws(() => gmail.readAttachments([big]), /troppo grand/i);
    assert.throws(() => gmail.readAttachments(new Array(6).fill({ filename: 'a.pdf', base64: 'QQ==' })), /troppi/i);
    const ok = gmail.readAttachments([{ filename: 'a.pdf', mimeType: 'application/pdf', base64: 'data:application/pdf;base64,QUJD' }]);
    assert.strictEqual(ok[0].content.toString(), 'ABC');
    assert.deepStrictEqual(gmail.readAttachments(undefined), []);
});

function fakeGoogle(routes) {
    const calls = [];
    return { calls, fetchImpl: async (url, opts = {}) => {
        calls.push({ url: String(url), opts });
        const hit = routes[String(url)];
        const out = typeof hit === 'function' ? hit(opts) : hit;
        const status = out && out.__status ? out.__status : 200;
        return { ok: status < 400, status, text: async () => JSON.stringify(out && out.__status ? out.body : out) };
    } };
}
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SEND_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';

test('per inviare prima si chiede un gettone breve, poi si manda il messaggio', async () => {
    const { fetchImpl, calls } = fakeGoogle({ [TOKEN_URL]: { access_token: 'breve', expires_in: 3600 }, [SEND_URL]: { id: 'msg-1' } });
    const client = gmail.createClient({ env: ENV, fetchImpl });
    const sent = await client.send({ to: 'mario@example.com', subject: 'Ciao', text: 'Testo' });
    assert.deepStrictEqual(sent, { id: 'msg-1' });
    assert.match(calls[0].opts.body, /grant_type=refresh_token/);
    assert.strictEqual(calls[1].opts.headers.Authorization, 'Bearer breve');
    const raw = Buffer.from(JSON.parse(calls[1].opts.body).raw, 'base64url').toString('utf8');
    assert.match(raw, /^To: mario@example\.com$/m);
    await client.send({ to: 'mario@example.com', subject: 'Due', text: 'Testo' });
    assert.strictEqual(calls.filter(c => c.url === TOKEN_URL).length, 1, 'il gettone breve si riusa finché vale');
});

test('senza destinatario, oggetto o testo non parte niente', async () => {
    const { fetchImpl, calls } = fakeGoogle({});
    const client = gmail.createClient({ env: ENV, fetchImpl });
    await assert.rejects(() => client.send({ to: '', subject: 'x', text: 'y' }), /destinatario/i);
    await assert.rejects(() => client.send({ to: 'a@b.it', subject: ' ', text: 'y' }), /oggetto/i);
    await assert.rejects(() => client.send({ to: 'a@b.it', subject: 'x', text: '' }), /testo/i);
    assert.strictEqual(calls.length, 0);
});

test('se Google revoca l\'accesso l\'errore lo dice, senza mostrare segreti', async () => {
    const { fetchImpl } = fakeGoogle({ [TOKEN_URL]: { __status: 400, body: { error: 'invalid_grant' } } });
    const client = gmail.createClient({ env: ENV, fetchImpl });
    await assert.rejects(() => client.send({ to: 'a@b.it', subject: 'x', text: 'y' }),
        e => /ricolleg/i.test(e.message) && !e.message.includes('ref') && !e.message.includes('sec'));
});

test('il modulo sa solo inviare: nessuna chiamata che legge la posta', async () => {
    const { fetchImpl, calls } = fakeGoogle({ [TOKEN_URL]: { access_token: 't', expires_in: 3600 }, [SEND_URL]: { id: 'm' } });
    const client = gmail.createClient({ env: ENV, fetchImpl });
    await client.send({ to: 'a@b.it', subject: 'x', text: 'y' });
    assert.deepStrictEqual(Object.keys(client), ['send']);
    assert.ok(calls.every(c => c.url === TOKEN_URL || c.url === SEND_URL));
});
