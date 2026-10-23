const test = require('node:test');
const assert = require('node:assert');
const inbox = require('../inbox');

const ENV = { IMAP_COMPANY_ID: '14', IMAP_HOST: 'mailserver.businessidentity.llc', IMAP_USER: 'info@oakstonethirteen.com', IMAP_PASS: 'finta-solo-per-i-test' };

test('la casella è attiva solo con id azienda, server, utente e password; e solo per quell\'azienda', () => {
    const cfg = inbox.config(ENV);
    assert.deepStrictEqual({ ...cfg, pass: '***' }, { companyId: 14, host: 'mailserver.businessidentity.llc', user: 'info@oakstonethirteen.com', pass: '***', port: 993, strict: true });
    assert.strictEqual(inbox.isEnabledFor(ENV, 14), true);
    assert.strictEqual(inbox.isEnabledFor(ENV, '14'), true);
    assert.strictEqual(inbox.isEnabledFor(ENV, 13), false, 'l\'altra LLC non la vede');
    for (const k of ['IMAP_COMPANY_ID', 'IMAP_HOST', 'IMAP_USER', 'IMAP_PASS']) {
        const env = { ...ENV }; delete env[k];
        assert.strictEqual(inbox.config(env), null, `senza ${k}`);
    }
    assert.strictEqual(inbox.config({ ...ENV, IMAP_HOST: 'mail server; rm -rf' }), null, 'host non valido');
    assert.strictEqual(inbox.config({ ...ENV, IMAP_HOST: 'localhost' }), null, 'solo nomi con dominio');
    assert.strictEqual(inbox.config({ ...ENV, IMAP_PORT: '143' }).port, 143);
    assert.strictEqual(inbox.config({ ...ENV, IMAP_PORT: 'boh' }).port, 993);
    assert.strictEqual(inbox.config({ ...ENV, IMAP_TLS_STRICT: 'false' }).strict, false);
});

test('cartella, uid e pagina arrivano dalla pagina: si controllano', () => {
    assert.strictEqual(inbox.cleanFolder(undefined), 'INBOX');
    assert.strictEqual(inbox.cleanFolder(''), 'INBOX');
    assert.strictEqual(inbox.cleanFolder('INBOX.Sent'), 'INBOX.Sent');
    assert.strictEqual(inbox.cleanFolder('a\nb'), null);
    assert.strictEqual(inbox.cleanFolder('x'.repeat(121)), null);
    assert.strictEqual(inbox.cleanUid('42'), 42);
    assert.strictEqual(inbox.cleanUid('0'), null);
    assert.strictEqual(inbox.cleanUid('-1'), null);
    assert.strictEqual(inbox.cleanUid('4294967296'), null);
    assert.strictEqual(inbox.cleanUid('1; DELETE'), null);
    assert.strictEqual(inbox.cleanPage('2'), 2);
    assert.strictEqual(inbox.cleanPage('-3'), 0);
    assert.strictEqual(inbox.cleanPage('x'), 0);
});

test('le pagine partono dai messaggi più recenti', () => {
    assert.deepStrictEqual(inbox.pageRange(100, 0), { from: 76, to: 100 });
    assert.deepStrictEqual(inbox.pageRange(100, 1), { from: 51, to: 75 });
    assert.deepStrictEqual(inbox.pageRange(100, 3), { from: 1, to: 25 });
    assert.strictEqual(inbox.pageRange(100, 4), null);
    assert.deepStrictEqual(inbox.pageRange(7, 0), { from: 1, to: 7 });
    assert.strictEqual(inbox.pageRange(0, 0), null);
});

test('l\'HTML di un\'email viene ripulito: niente script, stili, moduli, eventi; link sicuri', () => {
    const dirty = '<p onclick="x()">Ciao <b>Fede</b></p><script>alert(1)</script><style>body{background:url(http://t.co/p)}</style>'
        + '<a href="javascript:alert(1)">brutto</a> <a href="https://esempio.it/x">bello</a> <a href="http://esempio.it">http</a>'
        + '<form action="https://evil"><input name="p"></form><iframe src="https://evil"></iframe>';
    const out = inbox.sanitizeEmailHtml(dirty);
    assert.ok(!/script|alert\(1\)|onclick|<style|<form|<iframe|javascript:|background/i.test(out), out);
    assert.match(out, /<b>Fede<\/b>/);
    assert.match(out, /<a href="https:\/\/esempio\.it\/x" target="_blank" rel="noopener noreferrer nofollow">bello<\/a>/);
    assert.ok(!/href="http:\/\/esempio/.test(out), 'niente http semplice');
});

test('le immagini remote sono bloccate finché non si chiede di mostrarle', () => {
    const html = '<p>x</p><img src="https://t.example/pixel.gif" alt="logo"><img src="//t.example/p2.gif"><img src="data:image/png;base64,AAAA">';
    const blocked = inbox.sanitizeEmailHtml(html);
    assert.ok(!/t\.example/.test(blocked), blocked);
    assert.match(blocked, /\[immagine: logo\]/);
    assert.match(blocked, /data:image\/png/, 'le immagini incorporate sono già nell\'email: nessun tracciamento');
    const shown = inbox.sanitizeEmailHtml(html, { showImages: true });
    assert.match(shown, /src="https:\/\/t\.example\/pixel\.gif"/);
    assert.ok(!/src="\/\/t\.example/.test(shown), 'mai senza https');
    assert.strictEqual(inbox.hasRemoteImages(html), true);
    assert.strictEqual(inbox.hasRemoteImages('<p>solo testo</p><img src="data:image/png;base64,AA">'), false);
});

test('indirizzi scritti per esteso', () => {
    assert.strictEqual(inbox.formatAddress({ name: 'Mario Rossi', address: 'm@x.it' }), 'Mario Rossi <m@x.it>');
    assert.strictEqual(inbox.formatAddress({ address: 'm@x.it' }), 'm@x.it');
    assert.strictEqual(inbox.formatAddress(null), '');
    assert.deepStrictEqual(inbox.formatAddressList([{ address: 'a@x.it' }, null, { name: 'B', address: 'b@x.it' }]), ['a@x.it', 'B <b@x.it>']);
});

test('gli errori del server sono in italiano e non sono mai 401/403', () => {
    const cases = [
        [{ authenticationFailed: true, message: 'Command failed' }, /utente o password/],
        [{ message: 'Invalid credentials (Failure)' }, /utente o password/],
        [{ code: 'DEPTH_ZERO_SELF_SIGNED_CERT', message: 'self-signed certificate' }, /certificato/],
        [{ code: 'ENOTFOUND', message: 'getaddrinfo' }, /non esiste/],
        [{ code: 'ETIMEDOUT', message: 'x' }, /non risponde/],
        [{ responseText: 'Mailbox doesn\'t exist: Foo' }, /Cartella non trovata/],
        [{ message: 'qualcosa di strano' }, /Non riesco a leggere/],
    ];
    for (const [err, re] of cases) {
        const e = inbox.describeError(err);
        assert.match(e.message, re);
        assert.ok(![401, 403].includes(e.status), `${e.message} → ${e.status}`);
    }
    assert.ok(!/finta-solo|password:/.test(inbox.describeError({ message: 'x', pass: 'finta-solo-per-i-test' }).message), 'la password non finisce nei messaggi');
});

// ---- Una casella finta, per provare il flusso senza server vero ----
function fakeClient({ messages, raw, failConnect, unread } = {}) {
    const log = { opened: [], readOnly: [], fetched: [], loggedOut: false, flagsChanged: 0 };
    const client = {
        on() {},
        mailbox: { exists: messages ? messages.length : 0 },
        async connect() { if (failConnect) throw failConnect; },
        async logout() { log.loggedOut = true; },
        async list() { return [{ path: 'INBOX', name: 'INBOX', flags: new Set() }, { path: 'Sent', name: 'Sent', specialUse: '\\Sent', flags: new Set() }, { path: 'Gruppo', name: 'Gruppo', flags: new Set(['\\Noselect']) }]; },
        async getMailboxLock(folder, opts) { log.opened.push(folder); log.readOnly.push(opts && opts.readOnly); return { release() {} }; },
        fetch(range) { log.fetched.push(range); const [a, b] = range.split(':').map(Number); const slice = messages.slice(a - 1, b); return (async function* () { for (const m of slice) yield m; })(); },
        async fetchOne(uid) { log.fetched.push('uid:' + uid); return raw ? { source: Buffer.from(raw) } : false; },
        async search(query) { log.searched = query; return unread || []; },
        async messageFlagsAdd() { log.flagsChanged++; },
        async messageDelete() { log.flagsChanged++; },
    };
    return { client, log };
}
const mk = (n, extra) => ({ uid: 1000 + n, envelope: { subject: 'Oggetto ' + n, from: [{ name: 'Mittente', address: 'm@x.it' }], date: new Date(Date.UTC(2026, 9, n)) }, flags: new Set(n % 2 ? [] : ['\\Seen']), size: 100 + n, ...extra });

test('elenco: solo lettura, dal più recente, e chiude sempre la connessione', async () => {
    const messages = Array.from({ length: 30 }, (_, i) => mk(i + 1));
    const { client, log } = fakeClient({ messages });
    const r = await inbox.listMessages(inbox.config(ENV), 'INBOX', 0, () => client);
    assert.deepStrictEqual(log.readOnly, [true], 'la cartella si apre in sola lettura');
    assert.strictEqual(r.total, 30);
    assert.strictEqual(r.messages.length, 25);
    assert.strictEqual(r.messages[0].subject, 'Oggetto 30', 'il più recente per primo');
    assert.strictEqual(r.messages[0].seen, true);
    assert.strictEqual(r.messages[1].seen, false);
    assert.strictEqual(r.hasMore, true);
    assert.strictEqual(log.loggedOut, true);
    assert.strictEqual(log.flagsChanged, 0);
    const second = fakeClient({ messages });
    const r2 = await inbox.listMessages(inbox.config(ENV), 'INBOX', 1, () => second.client);
    assert.strictEqual(r2.messages.length, 5);
    assert.strictEqual(r2.hasMore, false);
});

test('elenco: casella vuota o pagina oltre la fine', async () => {
    const { client } = fakeClient({ messages: [] });
    const r = await inbox.listMessages(inbox.config(ENV), 'INBOX', 0, () => client);
    assert.deepStrictEqual({ total: r.total, n: r.messages.length, more: r.hasMore }, { total: 0, n: 0, more: false });
});

test('messaggio: ripulito, con allegati elencati, e senza segnarlo come letto', async () => {
    const raw = ['From: Mario Rossi <m@x.it>', 'To: info@oakstonethirteen.com', 'Subject: Fattura', 'Date: Tue, 20 Oct 2026 10:00:00 +0000', 'MIME-Version: 1.0',
        'Content-Type: multipart/mixed; boundary="b1"', '', '--b1', 'Content-Type: text/html; charset=utf-8', '', '<p>Ciao</p><script>alert(1)</script><img src="https://t.example/p.gif">',
        '--b1', 'Content-Type: application/pdf; name="fattura.pdf"', 'Content-Disposition: attachment; filename="fattura.pdf"', 'Content-Transfer-Encoding: base64', '', 'JVBERi0xLjQK', '--b1--', ''].join('\r\n');
    const { client, log } = fakeClient({ raw });
    const m = await inbox.getMessage(inbox.config(ENV), 'INBOX', 1001, {}, () => client);
    assert.strictEqual(m.subject, 'Fattura');
    assert.deepStrictEqual(m.from, ['Mario Rossi <m@x.it>']);
    assert.match(m.html, /<p>Ciao<\/p>/);
    assert.ok(!/script|t\.example/.test(m.html), m.html);
    assert.strictEqual(m.imagesBlocked, true);
    assert.strictEqual(m.attachments.length, 1);
    assert.strictEqual(m.attachments[0].filename, 'fattura.pdf');
    assert.deepStrictEqual(log.readOnly, [true]);
    assert.strictEqual(log.flagsChanged, 0);
    const again = fakeClient({ raw });
    const withImg = await inbox.getMessage(inbox.config(ENV), 'INBOX', 1001, { showImages: true }, () => again.client);
    assert.match(withImg.html, /t\.example\/p\.gif/);
    assert.strictEqual(withImg.imagesBlocked, false);
});

test('messaggio inesistente: 404 chiaro', async () => {
    const { client } = fakeClient({ raw: null });
    await assert.rejects(inbox.getMessage(inbox.config(ENV), 'INBOX', 999, {}, () => client), e => e.status === 404 && /non trovato/i.test(e.message));
});

test('se la connessione fallisce: errore chiaro, e la connessione si chiude lo stesso', async () => {
    const { client, log } = fakeClient({ failConnect: { authenticationFailed: true, message: 'x' } });
    await assert.rejects(inbox.listMessages(inbox.config(ENV), 'INBOX', 0, () => client), e => e.status === 502 && /utente o password/.test(e.message));
    assert.strictEqual(log.loggedOut, true);
});

test('cartelle: la casella arriva per prima e quelle non selezionabili non compaiono', async () => {
    const { client } = fakeClient({ messages: [] });
    const f = await inbox.listFolders(inbox.config(ENV), () => client);
    assert.deepStrictEqual(f.map(x => x.path), ['INBOX', 'Sent']);
});

test('il modulo di lettura non ha nessuna funzione che scriva sulla casella (le azioni stanno in altri file)', () => {
    const src = require('node:fs').readFileSync(require.resolve('../inbox'), 'utf8');
    assert.ok(!/messageDelete|messageFlagsAdd|messageFlagsSet|messageMove|messageCopy|append\(|\.mailboxCreate|\.mailboxDelete|mailboxRename|\.idle\(/.test(src.replace(/\/\/.*$/gm, '')), 'solo comandi di lettura');
});

test('non lette: una ricerca sola, in sola lettura, i più recenti per primi e al massimo 200', async () => {
    const { client, log } = fakeClient({ unread: [5, 90, 12] });
    const r = await inbox.unreadUids(inbox.config(ENV), () => client);
    assert.deepStrictEqual(r, { count: 3, uids: [90, 12, 5] });
    assert.deepStrictEqual(log.searched, { seen: false });
    assert.deepStrictEqual(log.readOnly, [true]);
    assert.deepStrictEqual(log.opened, ['INBOX']);
    assert.strictEqual(log.loggedOut, true);
    assert.strictEqual(log.flagsChanged, 0);
    const many = fakeClient({ unread: Array.from({ length: 300 }, (_, i) => i + 1) });
    const m = await inbox.unreadUids(inbox.config(ENV), () => many.client);
    assert.strictEqual(m.count, 300);
    assert.strictEqual(m.uids.length, 200);
    assert.strictEqual(m.uids[0], 300);
    const none = fakeClient({ unread: false });
    assert.deepStrictEqual(await inbox.unreadUids(inbox.config(ENV), () => none.client), { count: 0, uids: [] });
});
