// Numbers — invio di email dalla casella dell'azienda (Gmail, SOLO invio)
//
// Il permesso chiesto a Google è uno solo, gmail.send: con quello si può mandare un'email
// e nient'altro. Numbers non può leggere la posta, né le risposte: arrivano nella casella,
// come sempre. In questo file esiste una sola chiamata verso Gmail, quella che invia.
//
// Variabili su Render (le produce tools/gmail-collega.py, lanciato una volta da Federico):
//   GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN, GMAIL_FROM
// Facoltative:
//   GMAIL_FROM_NAME  nome che vede chi riceve (se manca: solo l'indirizzo)
//   GMAIL_BCC        indirizzi che ricevono in copia nascosta OGNI email partita da Numbers
//   GMAIL_MAX_PER_DAY quante email al giorno, al massimo (se manca: 50)
// Per staccare tutto: togliere le variabili, o revocare l'accesso da myaccount.google.com/permissions.

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SEND_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';
const TIMEOUT_MS = 20000;
const MAX_ATTACHMENTS = 5;
const MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024; // in tutto, dopo la decodifica
const REQUIRED = ['GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN', 'GMAIL_FROM'];

class MailError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'MailError';
        this.status = status || 400;
    }
}

function isConfigured(env) {
    return REQUIRED.every(k => env && typeof env[k] === 'string' && env[k].trim());
}

// ===== Funzioni pure =====

const ADDRESS_RE = /^[^\s@<>(),;:"\\]+@[^\s@<>(),;:"\\]+\.[^\s@<>(),;:"\\]{2,}$/;

// Accetta una stringa («a@b.it, c@d.it») o una lista. Niente a capo: un indirizzo non può
// portarsi dietro un'intestazione in più.
function parseAddresses(value) {
    const raw = Array.isArray(value) ? value.join(',') : String(value == null ? '' : value);
    if (/[\r\n]/.test(raw)) throw new MailError('Indirizzo non valido.');
    const out = [];
    for (const piece of raw.split(/[,;]/)) {
        const addr = piece.trim().toLowerCase();
        if (!addr) continue;
        if (!ADDRESS_RE.test(addr)) throw new MailError(`Indirizzo non valido: ${addr}`);
        if (!out.includes(addr)) out.push(addr);
    }
    return out;
}

// Intestazioni: gli a capo spariscono sempre; se c'è qualcosa fuori dall'ASCII si codifica (RFC 2047).
function encodeHeader(value) {
    const clean = String(value == null ? '' : value).replace(/[\r\n]+/g, ' ').trim();
    return /^[\x20-\x7E]*$/.test(clean) ? clean : `=?UTF-8?B?${Buffer.from(clean, 'utf8').toString('base64')}?=`;
}

function safeFilename(name) {
    const base = String(name == null ? '' : name).split(/[\\/]/).pop().replace(/[\r\n]+/g, ' ').replace(/[:"<>|?*\x00-\x1f]/g, '').replace(/\s+/g, ' ').trim();
    return base || 'allegato';
}

function wrap76(b64) {
    return b64.replace(/.{1,76}/g, '$&\r\n').trimEnd();
}

// Allegati in arrivo dalla pagina: [{ filename, mimeType, base64 }] (anche come data: URL).
function readAttachments(list) {
    const items = Array.isArray(list) ? list : [];
    if (items.length > MAX_ATTACHMENTS) throw new MailError(`Troppi allegati: al massimo ${MAX_ATTACHMENTS}.`);
    let total = 0;
    return items.map(item => {
        const b64 = String((item && item.base64) || '').replace(/^data:[^;,]*;base64,/, '');
        const content = Buffer.from(b64, 'base64');
        total += content.length;
        if (total > MAX_ATTACHMENT_BYTES) throw new MailError('Allegati troppo grandi: al massimo 8 MB in tutto.');
        const mimeType = /^[\w.+-]+\/[\w.+-]+$/.test(String(item && item.mimeType)) ? item.mimeType : 'application/octet-stream';
        return { filename: safeFilename(item && item.filename), mimeType, content };
    });
}

function buildMime({ from, fromName, to, bcc, subject, text, attachments }) {
    const headers = [
        `From: ${fromName ? `${encodeHeader(fromName)} <${from}>` : from}`,
        `To: ${to.join(', ')}`,
    ];
    if (bcc && bcc.length) headers.push(`Bcc: ${bcc.join(', ')}`);
    headers.push(`Subject: ${encodeHeader(subject)}`, 'MIME-Version: 1.0');

    const body = wrap76(Buffer.from(String(text).replace(/\r?\n/g, '\r\n'), 'utf8').toString('base64'));
    const textPart = ['Content-Type: text/plain; charset="UTF-8"', 'Content-Transfer-Encoding: base64', '', body];
    const files = attachments || [];
    if (files.length === 0) return headers.concat(textPart).join('\r\n');

    const boundary = 'numbers_' + require('node:crypto').randomBytes(12).toString('hex');
    const lines = headers.concat([`Content-Type: multipart/mixed; boundary="${boundary}"`, '', `--${boundary}`], textPart);
    for (const file of files) {
        lines.push(
            `--${boundary}`,
            `Content-Type: ${file.mimeType}`,
            'Content-Transfer-Encoding: base64',
            `Content-Disposition: attachment; filename*=UTF-8''${encodeURIComponent(file.filename)}`,
            '',
            wrap76(file.content.toString('base64'))
        );
    }
    lines.push(`--${boundary}--`);
    return lines.join('\r\n');
}

// ===== Cliente =====

function createClient({ env, fetchImpl } = {}) {
    const doFetch = fetchImpl || fetch;
    let cached = null; // { token, until }

    async function call(url, opts) {
        let res;
        try {
            res = await doFetch(url, { ...opts, signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(TIMEOUT_MS) : undefined });
        } catch (e) {
            throw new MailError('Google non risponde. Riprova tra poco.', 502);
        }
        const textBody = await res.text();
        let data = null;
        try { data = textBody ? JSON.parse(textBody) : null; } catch (e) { data = null; }
        return { res, data };
    }

    async function accessToken() {
        if (cached && cached.until > Date.now() + 60000) return cached.token;
        const { res, data } = await call(TOKEN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: env.GMAIL_CLIENT_ID.trim(),
                client_secret: env.GMAIL_CLIENT_SECRET.trim(),
                refresh_token: env.GMAIL_REFRESH_TOKEN.trim(),
                grant_type: 'refresh_token',
            }).toString(),
        });
        if (!res.ok || !data || !data.access_token) {
            throw new MailError('Google non riconosce più il collegamento della casella: va ricollegata (tools/gmail-collega.py).', 502);
        }
        cached = { token: data.access_token, until: Date.now() + (Number(data.expires_in) || 3000) * 1000 };
        return cached.token;
    }

    async function send({ to, subject, text, attachments } = {}) {
        const recipients = parseAddresses(to);
        if (recipients.length === 0) throw new MailError('Scrivi almeno un destinatario.');
        if (!String(subject == null ? '' : subject).trim()) throw new MailError('Scrivi l\'oggetto.');
        if (!String(text == null ? '' : text).trim()) throw new MailError('Scrivi il testo dell\'email.');
        const from = env.GMAIL_FROM.trim().toLowerCase();
        const bcc = parseAddresses(env.GMAIL_BCC || '').filter(a => !recipients.includes(a));
        const raw = buildMime({ from, fromName: (env.GMAIL_FROM_NAME || '').trim(), to: recipients, bcc, subject, text, attachments });
        const token = await accessToken();
        const { res, data } = await call(SEND_URL, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw: Buffer.from(raw, 'utf8').toString('base64url') }),
        });
        if (!res.ok) {
            const why = data && data.error && data.error.message ? String(data.error.message) : `errore ${res.status}`;
            throw new MailError(`Gmail non ha inviato l'email: ${why}`, 502);
        }
        return { id: data && data.id };
    }

    return { send };
}

module.exports = { MailError, isConfigured, createClient, parseAddresses, encodeHeader, safeFilename, readAttachments, buildMime, MAX_ATTACHMENTS, MAX_ATTACHMENT_BYTES };
