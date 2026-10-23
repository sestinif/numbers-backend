// Numbers — la casella email di UNA azienda, in SOLA LETTURA (IMAP).
//
// Serve a leggere la posta dell'azienda dentro Numbers, senza aprire la webmail. Non scrive niente:
// la casella si apre in lettura (EXAMINE), i messaggi si scaricano senza segnarli come letti, e qui
// non esiste nessuna chiamata che sposti, cancelli, segni o invii. Per rispondere o scrivere si usa
// la webmail, come sempre.
//
// Variabili su Render (tutte obbligatorie, tranne le ultime due):
//   IMAP_COMPANY_ID   l'id dell'azienda di Numbers che vede la sezione (solo quella)
//   IMAP_HOST         es. mailserver.businessidentity.llc
//   IMAP_USER         l'indirizzo della casella
//   IMAP_PASS         la password della casella (la mette Federico su Render: non passa mai dalla chat)
//   IMAP_PORT         facoltativa, di base 993 (connessione cifrata)
//   IMAP_TLS_STRICT   facoltativa: "false" accetta un certificato non riconosciuto (di base: controllo attivo)
// Per staccare tutto: togliere IMAP_PASS (o la variabile IMAP_COMPANY_ID) da Render.

const sanitizeHtml = require('sanitize-html');

const PAGE_SIZE = 25;
const MAX_FOLDER_LENGTH = 120;
const MAX_UNREAD_UIDS = 200;
const CONNECT_TIMEOUT_MS = 15000;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

class InboxError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'InboxError';
        this.status = status || 400; // mai 401/403: la pagina esce dall'accesso su quei codici
    }
}

// ===== Funzioni pure =====

function config(env) {
    const get = k => (env && typeof env[k] === 'string' ? env[k].trim() : '');
    const companyId = parseInt(get('IMAP_COMPANY_ID'), 10);
    const host = get('IMAP_HOST').toLowerCase();
    const user = get('IMAP_USER');
    const pass = typeof env.IMAP_PASS === 'string' ? env.IMAP_PASS : '';
    if (!(companyId > 0) || !HOST_RE.test(host) || !user || !pass) return null;
    const port = parseInt(get('IMAP_PORT'), 10);
    return {
        companyId,
        host,
        user,
        pass,
        port: port > 0 && port < 65536 ? port : 993,
        strict: get('IMAP_TLS_STRICT').toLowerCase() !== 'false',
    };
}

function isEnabledFor(env, companyId) {
    const cfg = config(env);
    return !!cfg && String(cfg.companyId) === String(companyId);
}

// Il nome di una cartella arriva dalla pagina: solo testo normale, corto, senza caratteri di controllo.
function cleanFolder(value) {
    const v = String(value == null || value === '' ? 'INBOX' : value);
    if (v.length > MAX_FOLDER_LENGTH || /[\u0000-\u001f\u007f]/.test(v)) return null;
    return v;
}

function cleanUid(value) {
    const n = Number(value);
    return Number.isInteger(n) && n > 0 && n < 4294967296 ? n : null;
}

function cleanPage(value) {
    const n = parseInt(value, 10);
    return Number.isInteger(n) && n >= 0 && n < 10000 ? n : 0;
}

// Pagina 0 = i più recenti. Ritorna l'intervallo di numeri d'ordine da chiedere al server, o null se vuoto.
function pageRange(total, page, size = PAGE_SIZE) {
    const last = total - page * size;
    if (last < 1) return null;
    return { from: Math.max(1, last - size + 1), to: last };
}

// L'HTML di una email non è fidato: niente script, niente stili (potrebbero caricare cose), niente
// moduli, link solo https/mailto/tel e sempre in scheda nuova. Le immagini remote sono bloccate finché
// non si chiede di mostrarle (sono il modo in cui i mittenti sanno che hai aperto l'email).
function sanitizeEmailHtml(html, { showImages = false } = {}) {
    return sanitizeHtml(String(html || ''), {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2', 'span', 'div', 'center', 'font', 'u', 'hr']),
        allowedAttributes: {
            a: ['href', 'name', 'target', 'rel'],
            img: ['src', 'alt', 'width', 'height'],
            td: ['colspan', 'rowspan', 'align'],
            th: ['colspan', 'rowspan', 'align'],
            table: ['width', 'border', 'cellpadding', 'cellspacing'],
        },
        allowedSchemes: ['https', 'mailto', 'tel'],
        allowedSchemesByTag: { img: ['https', 'data'] },
        allowProtocolRelative: false,
        transformTags: {
            a: (tagName, attribs) => ({ tagName: 'a', attribs: { ...attribs, target: '_blank', rel: 'noopener noreferrer nofollow' } }),
            img: (tagName, attribs) => {
                const src = String(attribs.src || '');
                if (!showImages && !/^data:/i.test(src)) {
                    return { tagName: 'span', attribs: {}, text: attribs.alt ? `[immagine: ${attribs.alt}]` : '[immagine bloccata]' };
                }
                return { tagName: 'img', attribs: { src, alt: attribs.alt || '' } };
            },
        },
        // Lo stile e gli script spariscono con il loro contenuto.
        nonTextTags: ['style', 'script', 'textarea', 'option', 'noscript'],
    });
}

function hasRemoteImages(html) {
    return /<img\b[^>]*\bsrc\s*=\s*["']?\s*(https?:)?\/\//i.test(String(html || ''));
}

function formatAddress(a) {
    if (!a) return '';
    return a.name ? `${a.name} <${a.address || ''}>` : (a.address || '');
}

function formatAddressList(list) {
    return (Array.isArray(list) ? list : []).map(formatAddress).filter(Boolean);
}

// Un errore del server di posta, in italiano e dicendo cosa fare. Mai 401/403.
function describeError(error) {
    if (error instanceof InboxError) return error;
    const code = error && (error.code || error.responseStatus || '');
    const text = String((error && (error.responseText || error.message)) || '');
    if (error && error.authenticationFailed) return new InboxError('La casella ha rifiutato utente o password: controlla IMAP_USER e IMAP_PASS su Render.', 502);
    if (/AUTHENTICATIONFAILED|Invalid credentials|authentication failed|LOGIN failed/i.test(text)) {
        return new InboxError('La casella ha rifiutato utente o password: controlla IMAP_USER e IMAP_PASS su Render.', 502);
    }
    if (/certificate|self.signed|SELF_SIGNED|CERT_|ERR_TLS/i.test(`${code} ${text}`)) {
        return new InboxError('Il certificato del server di posta non è riconosciuto. Se il server è quello giusto, metti IMAP_TLS_STRICT=false su Render.', 502);
    }
    if (/ENOTFOUND|EAI_AGAIN/i.test(`${code} ${text}`)) return new InboxError('Il server di posta non esiste: controlla IMAP_HOST su Render.', 502);
    if (/ETIMEDOUT|ECONNREFUSED|ECONNRESET|timeout|timed out/i.test(`${code} ${text}`)) {
        return new InboxError('Il server di posta non risponde. Riprova tra un minuto.', 502);
    }
    if (/Mailbox doesn't exist|NONEXISTENT|Unknown Mailbox|does not exist/i.test(text)) return new InboxError('Cartella non trovata.', 404);
    return new InboxError('Non riesco a leggere la casella in questo momento.', 502);
}

// ===== Collegamento al server (ImapFlow) =====
// `connect` si può sostituire nei test con una finta casella.

function realConnect(cfg) {
    const { ImapFlow } = require('imapflow');
    return new ImapFlow({
        host: cfg.host,
        port: cfg.port,
        secure: true,
        auth: { user: cfg.user, pass: cfg.pass },
        logger: false,
        emitLogs: false,
        connectionTimeout: CONNECT_TIMEOUT_MS,
        greetingTimeout: CONNECT_TIMEOUT_MS,
        socketTimeout: 60000,
        tls: { rejectUnauthorized: cfg.strict },
    });
}

async function withClient(cfg, work, connect = realConnect) {
    const client = connect(cfg);
    // Un errore a connessione aperta non deve far cadere il processo.
    if (typeof client.on === 'function') client.on('error', () => {});
    try {
        await client.connect();
        return await work(client);
    } catch (e) {
        throw describeError(e);
    } finally {
        try { await client.logout(); } catch (e) { /* già chiusa */ }
    }
}

async function listFolders(cfg, connect) {
    return withClient(cfg, async client => {
        const boxes = await client.list();
        return boxes
            .filter(b => !(b.flags && (b.flags.has ? b.flags.has('\\Noselect') : b.flags.includes && b.flags.includes('\\Noselect'))))
            .map(b => ({ path: b.path, name: b.name, special: b.specialUse || null }))
            .sort((a, b) => (a.path === 'INBOX' ? -1 : b.path === 'INBOX' ? 1 : a.path.localeCompare(b.path, 'it')));
    }, connect);
}

// I messaggi di una pagina, dal più recente. Sola lettura: la cartella si apre con readOnly.
async function listMessages(cfg, folder, page, connect) {
    return withClient(cfg, async client => {
        const lock = await client.getMailboxLock(folder, { readOnly: true });
        try {
            const total = (client.mailbox && client.mailbox.exists) || 0;
            const range = pageRange(total, page);
            if (!range) return { folder, page, total, messages: [], hasMore: false };
            const messages = [];
            for await (const msg of client.fetch(`${range.from}:${range.to}`, { uid: true, envelope: true, flags: true, internalDate: true, size: true })) {
                const env = msg.envelope || {};
                const flags = msg.flags instanceof Set ? msg.flags : new Set(msg.flags || []);
                messages.push({
                    uid: msg.uid,
                    subject: env.subject || '(senza oggetto)',
                    from: formatAddress((env.from || [])[0]),
                    date: (env.date || msg.internalDate) ? new Date(env.date || msg.internalDate).toISOString() : null,
                    seen: flags.has('\\Seen'),
                    size: msg.size || 0,
                });
            }
            messages.sort((a, b) => String(b.date).localeCompare(String(a.date)) || b.uid - a.uid);
            return { folder, page, total, messages, hasMore: range.from > 1 };
        } finally {
            lock.release();
        }
    }, connect);
}

// Le email non lette nella casella: serve al pallino di «nuova email» che si vede in tutta l'app.
// Una sola ricerca, in sola lettura. Ritorna i numeri dei messaggi (i più recenti per primi, al massimo 200).
async function unreadUids(cfg, connect) {
    return withClient(cfg, async client => {
        const lock = await client.getMailboxLock('INBOX', { readOnly: true });
        try {
            const found = await client.search({ seen: false }, { uid: true });
            const uids = (Array.isArray(found) ? found : []).slice().sort((a, b) => b - a);
            return { count: uids.length, uids: uids.slice(0, MAX_UNREAD_UIDS) };
        } finally {
            lock.release();
        }
    }, connect);
}

// Un messaggio intero, già pulito. Si scarica con BODY.PEEK e la cartella è in sola lettura: resta «non letto».
async function getMessage(cfg, folder, uid, { showImages = false } = {}, connect) {
    return withClient(cfg, async client => {
        const lock = await client.getMailboxLock(folder, { readOnly: true });
        try {
            const found = await client.fetchOne(String(uid), { source: true, flags: true }, { uid: true });
            if (!found || !found.source) throw new InboxError('Messaggio non trovato.', 404);
            const { simpleParser } = require('mailparser');
            const mail = await simpleParser(found.source);
            const rawHtml = typeof mail.html === 'string' ? mail.html : '';
            return {
                uid,
                folder,
                subject: mail.subject || '(senza oggetto)',
                from: formatAddressList(mail.from && mail.from.value),
                to: formatAddressList(mail.to && mail.to.value),
                cc: formatAddressList(mail.cc && mail.cc.value),
                date: mail.date ? mail.date.toISOString() : null,
                html: rawHtml ? sanitizeEmailHtml(rawHtml, { showImages }) : '',
                text: mail.text || '',
                imagesBlocked: !!rawHtml && !showImages && hasRemoteImages(rawHtml),
                attachments: (mail.attachments || []).map(a => ({ filename: a.filename || '(senza nome)', size: a.size || 0, contentType: a.contentType || '' })),
            };
        } finally {
            lock.release();
        }
    }, connect);
}

module.exports = {
    PAGE_SIZE, InboxError,
    config, isEnabledFor, cleanFolder, cleanUid, cleanPage, pageRange,
    sanitizeEmailHtml, hasRemoteImages, formatAddress, formatAddressList, describeError,
    listFolders, listMessages, unreadUids, getMessage,
};
