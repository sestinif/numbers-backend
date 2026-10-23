// Numbers — le azioni sulla casella di UNA azienda: segnare letta/non letta, spostare, eliminare, scaricare un allegato.
//
// Ogni azione parte da un clic di Federico su UN messaggio (niente azioni di massa, niente automatismi).
// «Elimina» sposta nel Cestino; solo dal Cestino un messaggio si cancella per sempre.
// La lettura (elenchi, messaggi) sta in inbox.js e non scrive mai; l'invio sta in inbox-send.js.

const inbox = require('./inbox');

const TRASH_NAMES = /^(trash|cestino|deleted items|deleted messages|posta eliminata|eliminati)$/i;

function findTrash(boxes) {
    return boxes.find(b => b.specialUse === '\\Trash') || boxes.find(b => TRASH_NAMES.test(b.name)) || null;
}

function isTrashPath(boxes, path) {
    const trash = findTrash(boxes);
    return !!trash && trash.path === path;
}

// Segna un messaggio come letto o non letto.
async function setSeen(cfg, folder, uid, seen, connect) {
    return inbox.withClient(cfg, async client => {
        const lock = await client.getMailboxLock(folder);
        try {
            if (seen) await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
            else await client.messageFlagsRemove(String(uid), ['\\Seen'], { uid: true });
            return { uid, seen: !!seen };
        } finally { lock.release(); }
    }, connect);
}

// Sposta un messaggio in un'altra cartella (che deve esistere).
async function moveMessage(cfg, folder, uid, destination, connect) {
    return inbox.withClient(cfg, async client => {
        const boxes = await client.list();
        if (!boxes.some(b => b.path === destination)) throw new inbox.InboxError('Cartella di destinazione non trovata.', 404);
        if (destination === folder) throw new inbox.InboxError('Il messaggio è già in quella cartella.', 400);
        const lock = await client.getMailboxLock(folder);
        try {
            await client.messageMove(String(uid), destination, { uid: true });
            return { uid, moved: true, to: destination };
        } finally { lock.release(); }
    }, connect);
}

// Elimina: dal Cestino è definitivo, da qualsiasi altra cartella è uno spostamento nel Cestino.
async function deleteMessage(cfg, folder, uid, connect) {
    return inbox.withClient(cfg, async client => {
        const boxes = await client.list();
        const trash = findTrash(boxes);
        const lock = await client.getMailboxLock(folder);
        try {
            if (trash && trash.path === folder) {
                await client.messageDelete(String(uid), { uid: true });
                return { uid, deleted: 'forever' };
            }
            if (!trash) throw new inbox.InboxError('Non trovo la cartella Cestino: sposta il messaggio a mano.', 404);
            await client.messageMove(String(uid), trash.path, { uid: true });
            return { uid, deleted: 'trash' };
        } finally { lock.release(); }
    }, connect);
}

// Un allegato, scaricato da un messaggio. Ritorna { filename, contentType, content }.
async function getAttachment(cfg, folder, uid, index, connect) {
    return inbox.withClient(cfg, async client => {
        const lock = await client.getMailboxLock(folder, { readOnly: true });
        try {
            const found = await client.fetchOne(String(uid), { source: true }, { uid: true });
            if (!found || !found.source) throw new inbox.InboxError('Messaggio non trovato.', 404);
            const { simpleParser } = require('mailparser');
            const mail = await simpleParser(found.source);
            const list = (mail.attachments || []).filter(a => a.content);
            const a = list[index];
            if (!a) throw new inbox.InboxError('Allegato non trovato.', 404);
            return { filename: a.filename || 'allegato', contentType: a.contentType || 'application/octet-stream', content: a.content };
        } finally { lock.release(); }
    }, connect);
}

// Il nome del file per l'intestazione di scarico: niente percorsi, niente a capo, niente virgolette.
function safeDownloadName(name) {
    const base = String(name == null ? '' : name).split(/[\\/]/).pop().replace(/[\r\n"\\]+/g, ' ').replace(/[\u0000-\u001f\u007f]/g, '').trim();
    return base.slice(0, 150) || 'allegato';
}

function cleanIndex(value) {
    const n = Number(value);
    return Number.isInteger(n) && n >= 0 && n < 50 ? n : null;
}

module.exports = { findTrash, isTrashPath, setSeen, moveMessage, deleteMessage, getAttachment, safeDownloadName, cleanIndex };
