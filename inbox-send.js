// Numbers — invio di email dalla casella di UNA azienda (SMTP), quella di inbox.js.
//
// Parte solo quando Federico preme «Invia» (nessun invio automatico). Usa gli stessi accessi della
// lettura: stesso utente e stessa password (IMAP_USER / IMAP_PASS), server di invio sul server di posta.
// Variabili facoltative su Render:
//   SMTP_HOST            di base lo stesso di IMAP_HOST
//   SMTP_PORT            di base 465 (connessione cifrata)
//   IMAP_FROM_NAME       nome che vede chi riceve (se manca: solo l'indirizzo)
//   INBOX_MAX_PER_DAY    quante email al giorno, al massimo (se manca: 50)
// Dopo l'invio la copia si salva in «Inviata» (se si riesce: l'invio non dipende da questo).
// Questo è l'unico file che scrive nella casella; inbox.js resta in sola lettura.

const gmail = require('./gmail');
const inbox = require('./inbox');

const MAX_RECIPIENTS = 20;
const MAX_SUBJECT = 300;
const MAX_TEXT = 100000;
const MESSAGE_ID_RE = /^<[^<>\s]{1,300}>$/;

function sendConfig(env) {
    const cfg = inbox.config(env);
    if (!cfg) return null;
    const host = String((env && env.SMTP_HOST) || cfg.host).trim().toLowerCase();
    const port = parseInt(env && env.SMTP_PORT, 10);
    return {
        ...cfg,
        smtpHost: host,
        smtpPort: port > 0 && port < 65536 ? port : 465,
        fromName: String((env && env.IMAP_FROM_NAME) || '').replace(/[\r\n"<>]+/g, ' ').trim().slice(0, 100),
    };
}

function dailyLimit(env) {
    const n = parseInt(env && env.INBOX_MAX_PER_DAY, 10);
    return Number.isFinite(n) && n > 0 ? n : 50;
}

// Quello che arriva dalla pagina, controllato. Lancia MailError (400) se qualcosa non va.
function validateOutgoing(body) {
    const b = body || {};
    const to = gmail.parseAddresses(b.to);
    const cc = gmail.parseAddresses(b.cc);
    if (to.length === 0) throw new gmail.MailError('Scrivi almeno un destinatario.');
    if (to.length + cc.length > MAX_RECIPIENTS) throw new gmail.MailError(`Troppi destinatari: al massimo ${MAX_RECIPIENTS}.`);
    const subject = String(b.subject == null ? '' : b.subject).replace(/[\r\n]+/g, ' ').trim();
    if (!subject) throw new gmail.MailError('Scrivi l\'oggetto.');
    if (subject.length > MAX_SUBJECT) throw new gmail.MailError(`L'oggetto è troppo lungo (massimo ${MAX_SUBJECT} caratteri).`);
    const text = String(b.text == null ? '' : b.text);
    if (!text.trim()) throw new gmail.MailError('Scrivi il testo dell\'email.');
    if (text.length > MAX_TEXT) throw new gmail.MailError('Il testo è troppo lungo.');
    const inReplyTo = MESSAGE_ID_RE.test(String(b.inReplyTo || '')) ? String(b.inReplyTo) : null;
    const references = (Array.isArray(b.references) ? b.references : []).map(String).filter(r => MESSAGE_ID_RE.test(r)).slice(-20);
    const attachments = gmail.readAttachments(b.attachments);
    return { to, cc, subject, text, inReplyTo, references: inReplyTo && !references.includes(inReplyTo) ? references.concat(inReplyTo) : references, attachments };
}

// Le opzioni per nodemailer. «From» è sempre la casella: la pagina non può scegliere un altro mittente.
function buildMessage(cfg, out) {
    const message = {
        from: cfg.fromName ? { name: cfg.fromName, address: cfg.user } : cfg.user,
        to: out.to,
        subject: out.subject,
        text: out.text,
        attachments: out.attachments.map(a => ({ filename: a.filename, content: a.content, contentType: a.mimeType })),
    };
    if (out.cc.length) message.cc = out.cc;
    if (out.inReplyTo) message.inReplyTo = out.inReplyTo;
    if (out.references.length) message.references = out.references;
    return message;
}

function describeSendError(error) {
    if (error instanceof gmail.MailError) return error;
    const code = String((error && error.code) || '');
    const text = String((error && (error.response || error.message)) || '');
    if (code === 'EAUTH' || /Invalid login|authentication failed|535/i.test(text)) return new gmail.MailError('La casella ha rifiutato utente o password per l\'invio: controlla IMAP_USER e IMAP_PASS su Render.', 502);
    if (/certificate|self.signed|CERT_|ERR_TLS/i.test(`${code} ${text}`)) return new gmail.MailError('Il certificato del server di posta non è riconosciuto. Se il server è quello giusto, metti IMAP_TLS_STRICT=false su Render.', 502);
    if (code === 'EENVELOPE' || /^5(5\d|0\d)/.test(String(error && error.responseCode)) || /recipient|mailbox unavailable|user unknown/i.test(text)) {
        return new gmail.MailError('Il server ha rifiutato un indirizzo: controlla i destinatari.', 502);
    }
    if (/ETIMEDOUT|ECONNREFUSED|ECONNECTION|ESOCKET|ENOTFOUND|EAI_AGAIN|timeout/i.test(`${code} ${text}`)) return new gmail.MailError('Il server di posta non risponde per l\'invio. Riprova tra un minuto.', 502);
    return new gmail.MailError('Non riesco a inviare l\'email in questo momento.', 502);
}

function realTransport(cfg) {
    return require('nodemailer').createTransport({
        host: cfg.smtpHost,
        port: cfg.smtpPort,
        secure: cfg.smtpPort === 465,
        auth: { user: cfg.user, pass: cfg.pass },
        tls: { rejectUnauthorized: cfg.strict },
        connectionTimeout: 15000,
        greetingTimeout: 15000,
        socketTimeout: 60000,
    });
}

// La copia in «Inviata», se la cartella c'è. Mai un errore verso chi invia: la mail è già partita.
async function saveToSent(cfg, raw, connect) {
    try {
        return await inbox.withClient(cfg, async client => {
            const boxes = await client.list();
            const sent = boxes.find(b => b.specialUse === '\\Sent') || boxes.find(b => /^(inviata|sent|posta inviata|sent items|inviati)$/i.test(b.name));
            if (!sent) return false;
            await client.append(sent.path, raw, ['\\Seen']);
            return true;
        }, connect);
    } catch (e) {
        console.error('Posta: copia in Inviata non salvata:', e && e.message);
        return false;
    }
}

// Manda l'email. `deps` serve ai test (trasporto finto, connessione finta).
async function send(cfg, out, deps = {}) {
    const message = buildMessage(cfg, out);
    const transport = (deps.transport || realTransport)(cfg);
    let info;
    try {
        info = await transport.sendMail(message);
    } catch (e) {
        throw describeSendError(e);
    }
    let savedToSent = false;
    try {
        const MailComposer = require('nodemailer/lib/mail-composer');
        const raw = await new MailComposer({ ...message, messageId: info && info.messageId }).compile().build();
        savedToSent = await saveToSent(cfg, raw, deps.connect);
    } catch (e) {
        console.error('Posta: copia non preparata:', e && e.message);
    }
    return { messageId: (info && info.messageId) || null, savedToSent };
}

module.exports = { MAX_RECIPIENTS, sendConfig, dailyLimit, validateOutgoing, buildMessage, describeSendError, send };
