const test = require('node:test');
const assert = require('node:assert');
const send = require('../inbox-send');
const actions = require('../inbox-actions');
const inbox = require('../inbox');

const ENV = { IMAP_COMPANY_ID: '14', IMAP_HOST: 'mailserver.businessidentity.llc', IMAP_USER: 'info@oakstonethirteen.com', IMAP_PASS: 'finta-solo-per-i-test' };
const MID = '<abc.123@esempio.it>';

test('configurazione di invio: stesso server e stessa casella della lettura, porta 465 di base', () => {
    const cfg = send.sendConfig({ ...ENV, IMAP_FROM_NAME: 'Oakstone Thirteen "LLC"' });
    assert.strictEqual(cfg.smtpHost, 'mailserver.businessidentity.llc');
    assert.strictEqual(cfg.smtpPort, 465);
    assert.strictEqual(cfg.user, 'info@oakstonethirteen.com');
    assert.ok(!/["<>]/.test(cfg.fromName), 'niente virgolette nel nome');
    assert.strictEqual(send.sendConfig({ ...ENV, SMTP_HOST: 'smtp.altro.it', SMTP_PORT: '587' }).smtpPort, 587);
    assert.strictEqual(send.sendConfig({}), null);
    assert.strictEqual(send.dailyLimit({}), 50);
    assert.strictEqual(send.dailyLimit({ INBOX_MAX_PER_DAY: '5' }), 5);
});

test('un\'email in uscita: tutto controllato prima di partire', () => {
    const ok = send.validateOutgoing({ to: 'A@x.it, b@y.com', cc: 'c@z.it', subject: '  Fattura  ', text: 'Ciao', inReplyTo: MID, references: ['<r1@x>', 'non-valido', MID] });
    assert.deepStrictEqual(ok.to, ['a@x.it', 'b@y.com']);
    assert.deepStrictEqual(ok.cc, ['c@z.it']);
    assert.strictEqual(ok.subject, 'Fattura');
    assert.strictEqual(ok.inReplyTo, MID);
    assert.deepStrictEqual(ok.references, ['<r1@x>', MID], 'gli id non validi spariscono, e quello a cui si risponde c\'è');
    const bad = body => assert.throws(() => send.validateOutgoing(body), e => e.name === 'MailError' && e.status === 400, JSON.stringify(body).slice(0, 80));
    bad({ to: '', subject: 'x', text: 'y' });
    bad({ to: 'a@x.it', subject: '', text: 'y' });
    bad({ to: 'a@x.it', subject: 'x', text: '   ' });
    bad({ to: 'nonunindirizzo', subject: 'x', text: 'y' });
    bad({ to: 'a@x.it\nBcc: spia@x.it', subject: 'x', text: 'y' });
    bad({ to: Array.from({ length: 21 }, (_, i) => `u${i}@x.it`).join(','), subject: 'x', text: 'y' });
    bad({ to: 'a@x.it', subject: 'x'.repeat(301), text: 'y' });
    bad({ to: 'a@x.it', subject: 'x', text: 'y'.repeat(100001) });
    bad({ to: 'a@x.it', subject: 'x', text: 'y', attachments: Array.from({ length: 6 }, () => ({ filename: 'a', base64: 'QQ==' })) });
    assert.strictEqual(send.validateOutgoing({ to: 'a@x.it', subject: 'x', text: 'y', inReplyTo: 'a\r\nBcc: x' }).inReplyTo, null, 'un id con a capo non passa');
});

test('il messaggio parte sempre dalla casella e porta il filo della risposta', () => {
    const cfg = send.sendConfig({ ...ENV, IMAP_FROM_NAME: 'Oakstone' });
    const out = send.validateOutgoing({ to: 'a@x.it', cc: 'c@x.it', subject: 'Re: ciao', text: 'ok', inReplyTo: MID, attachments: [{ filename: 'a.txt', mimeType: 'text/plain', base64: 'QQ==' }] });
    const m = send.buildMessage(cfg, out);
    assert.deepStrictEqual(m.from, { name: 'Oakstone', address: 'info@oakstonethirteen.com' });
    assert.deepStrictEqual(m.to, ['a@x.it']);
    assert.deepStrictEqual(m.cc, ['c@x.it']);
    assert.strictEqual(m.inReplyTo, MID);
    assert.deepStrictEqual(m.references, [MID]);
    assert.strictEqual(m.attachments.length, 1);
    assert.strictEqual(m.attachments[0].filename, 'a.txt');
    assert.ok(!('bcc' in m), 'nessuna copia nascosta');
});

test('invio: usa il trasporto, salva la copia in Inviata, e se la copia fallisce l\'invio resta riuscito', async () => {
    const cfg = send.sendConfig(ENV);
    const out = send.validateOutgoing({ to: 'a@x.it', subject: 'Ciao', text: 'Testo' });
    const sentMessages = [];
    const transport = () => ({ async sendMail(m) { sentMessages.push(m); return { messageId: '<nuovo@esempio.it>' }; } });
    const appended = [];
    const connectOk = () => ({ on() {}, async connect() {}, async logout() {}, async list() { return [{ path: 'INBOX', name: 'INBOX' }, { path: 'Sent', name: 'Sent', specialUse: '\\Sent' }]; }, async append(path, raw, flags) { appended.push({ path, size: raw.length, flags }); } });
    const r = await send.send(cfg, out, { transport, connect: connectOk });
    assert.strictEqual(sentMessages.length, 1);
    assert.deepStrictEqual({ id: r.messageId, saved: r.savedToSent }, { id: '<nuovo@esempio.it>', saved: true });
    assert.strictEqual(appended[0].path, 'Sent');
    assert.deepStrictEqual(appended[0].flags, ['\\Seen']);
    assert.ok(appended[0].size > 50);
    const connectBroken = () => ({ on() {}, async connect() { throw new Error('giù'); }, async logout() {} });
    const r2 = await send.send(cfg, out, { transport, connect: connectBroken });
    assert.strictEqual(r2.savedToSent, false, 'copia non salvata, ma niente errore');
    assert.strictEqual(r2.messageId, '<nuovo@esempio.it>');
    const noSent = () => ({ on() {}, async connect() {}, async logout() {}, async list() { return [{ path: 'INBOX', name: 'INBOX' }]; }, async append() { throw new Error('non deve succedere'); } });
    assert.strictEqual((await send.send(cfg, out, { transport, connect: noSent })).savedToSent, false);
});

test('invio: se il server rifiuta, errore chiaro in italiano e mai 401/403', async () => {
    const cfg = send.sendConfig(ENV);
    const out = send.validateOutgoing({ to: 'a@x.it', subject: 'Ciao', text: 'Testo' });
    const fail = err => () => ({ async sendMail() { throw err; } });
    const cases = [
        [{ code: 'EAUTH', message: 'Invalid login' }, /utente o password/],
        [{ code: 'ESOCKET', message: 'self signed certificate' }, /certificato/],
        [{ code: 'EENVELOPE', message: 'x' }, /indirizzo/],
        [{ code: 'ETIMEDOUT', message: 'x' }, /non risponde/],
        [{ message: 'boh' }, /Non riesco a inviare/],
    ];
    for (const [err, re] of cases) {
        await assert.rejects(send.send(cfg, out, { transport: fail(err) }), e => { assert.match(e.message, re); assert.ok(![401, 403].includes(e.status)); return true; });
    }
});

// ---- Azioni sulla casella, con una casella finta ----
function fakeBox({ folders } = {}) {
    const log = { locks: [], flagsAdd: [], flagsRemove: [], moved: [], deleted: [], loggedOut: false };
    const boxes = folders || [{ path: 'INBOX', name: 'INBOX' }, { path: 'Sent', name: 'Sent', specialUse: '\\Sent' }, { path: 'Trash', name: 'Trash', specialUse: '\\Trash' }, { path: 'Archivio', name: 'Archivio' }];
    return {
        log,
        client: {
            on() {}, async connect() {}, async logout() { log.loggedOut = true; },
            async list() { return boxes; },
            async getMailboxLock(folder, opts) { log.locks.push({ folder, readOnly: !!(opts && opts.readOnly) }); return { release() {} }; },
            async messageFlagsAdd(uid, flags, o) { log.flagsAdd.push([uid, flags, o]); },
            async messageFlagsRemove(uid, flags, o) { log.flagsRemove.push([uid, flags, o]); },
            async messageMove(uid, dest, o) { log.moved.push([uid, dest, o]); },
            async messageDelete(uid, o) { log.deleted.push([uid, o]); },
            async fetchOne() { return { source: Buffer.from(['From: a@x.it', 'Subject: x', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b"', '', '--b', 'Content-Type: text/plain', '', 'ciao', '--b', 'Content-Type: application/pdf; name="a/../fattura.pdf"', 'Content-Disposition: attachment; filename="a/../fattura.pdf"', 'Content-Transfer-Encoding: base64', '', 'JVBERi0xLjQK', '--b--', ''].join('\r\n')) }; },
        },
    };
}
const CFG = inbox.config(ENV);

test('segnare letta o non letta: un solo messaggio, per numero', async () => {
    const { client, log } = fakeBox();
    assert.deepStrictEqual(await actions.setSeen(CFG, 'INBOX', 42, true, () => client), { uid: 42, seen: true });
    assert.deepStrictEqual(log.flagsAdd, [['42', ['\\Seen'], { uid: true }]]);
    await actions.setSeen(CFG, 'INBOX', 42, false, () => client);
    assert.deepStrictEqual(log.flagsRemove, [['42', ['\\Seen'], { uid: true }]]);
    assert.strictEqual(log.locks[0].readOnly, false);
    assert.strictEqual(log.loggedOut, true);
});

test('eliminare: dal normale va nel Cestino, dal Cestino è per sempre', async () => {
    const a = fakeBox();
    assert.deepStrictEqual(await actions.deleteMessage(CFG, 'INBOX', 7, () => a.client), { uid: 7, deleted: 'trash' });
    assert.deepStrictEqual(a.log.moved, [['7', 'Trash', { uid: true }]]);
    assert.strictEqual(a.log.deleted.length, 0, 'niente cancellazione definitiva dalla posta normale');
    const b = fakeBox();
    assert.deepStrictEqual(await actions.deleteMessage(CFG, 'Trash', 7, () => b.client), { uid: 7, deleted: 'forever' });
    assert.deepStrictEqual(b.log.deleted, [['7', { uid: true }]]);
    const c = fakeBox({ folders: [{ path: 'INBOX', name: 'INBOX' }] });
    await assert.rejects(actions.deleteMessage(CFG, 'INBOX', 7, () => c.client), e => e.status === 404 && /Cestino/.test(e.message));
    assert.strictEqual(c.log.moved.length + c.log.deleted.length, 0, 'senza Cestino non si cancella niente');
});

test('spostare: la destinazione deve esistere e deve essere un\'altra cartella', async () => {
    const a = fakeBox();
    assert.deepStrictEqual(await actions.moveMessage(CFG, 'INBOX', 9, 'Archivio', () => a.client), { uid: 9, moved: true, to: 'Archivio' });
    assert.deepStrictEqual(a.log.moved, [['9', 'Archivio', { uid: true }]]);
    const b = fakeBox();
    await assert.rejects(actions.moveMessage(CFG, 'INBOX', 9, 'Inventata', () => b.client), e => e.status === 404);
    await assert.rejects(actions.moveMessage(CFG, 'INBOX', 9, 'INBOX', () => b.client), e => e.status === 400);
    assert.strictEqual(b.log.moved.length, 0);
});

test('allegato: si scarica per posizione, con un nome pulito', async () => {
    const { client, log } = fakeBox();
    const f = await actions.getAttachment(CFG, 'INBOX', 5, 0, () => client);
    assert.strictEqual(f.contentType, 'application/pdf');
    assert.ok(f.content.length > 0);
    assert.strictEqual(log.locks[0].readOnly, true, 'scaricare non cambia niente nella casella');
    assert.strictEqual(actions.safeDownloadName(f.filename), 'fattura.pdf', 'niente percorsi');
    assert.strictEqual(actions.safeDownloadName('a"b\r\nc.pdf'), 'a b c.pdf');
    await assert.rejects(actions.getAttachment(CFG, 'INBOX', 5, 3, () => client), e => e.status === 404);
    assert.strictEqual(actions.cleanIndex('0'), 0);
    assert.strictEqual(actions.cleanIndex('-1'), null);
    assert.strictEqual(actions.cleanIndex('abc'), null);
    assert.strictEqual(actions.cleanIndex('99'), null);
});
