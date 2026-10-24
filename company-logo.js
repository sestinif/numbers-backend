// Numbers — il logo di un'azienda.
// Ogni azienda ha due loghi facoltativi: `logo` (quello dell'app, di solito chiaro su scuro)
// e `logo_invoice` (la versione per le fatture, scura su bianco; se manca la fattura
// inverte quello dell'app). Si caricano SVG o PNG fino a MAX_BYTES e si salvano nel DB
// come data URL, così arrivano al frontend insieme all'azienda.
// Un SVG può contenere codice: qui passa solo da un elenco chiuso di tag e attributi
// di disegno. Niente script, niente handler on*, niente link esterni, niente <style>.
const sanitizeHtml = require('sanitize-html');

const MAX_BYTES = 512 * 1024;
const KINDS = { app: 'logo', invoice: 'logo_invoice' };
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const SVG_TAGS = [
    'svg', 'g', 'path', 'circle', 'ellipse', 'rect', 'line', 'polyline', 'polygon',
    'defs', 'linearGradient', 'radialGradient', 'stop', 'clipPath', 'mask', 'use',
    'symbol', 'title', 'desc', 'text', 'tspan'
];
const SVG_ATTRS = [
    'xmlns', 'viewBox', 'width', 'height', 'x', 'y', 'x1', 'y1', 'x2', 'y2', 'cx', 'cy', 'r', 'rx', 'ry',
    'd', 'points', 'transform', 'fill', 'fill-rule', 'fill-opacity', 'clip-rule', 'clip-path', 'mask',
    'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit', 'stroke-dasharray',
    'stroke-dashoffset', 'stroke-opacity', 'opacity', 'offset', 'stop-color', 'stop-opacity',
    'gradientUnits', 'gradientTransform', 'spreadMethod', 'fx', 'fy', 'fr', 'clipPathUnits', 'maskUnits',
    'maskContentUnits', 'preserveAspectRatio', 'id', 'class', 'href', 'xlink:href', 'xmlns:xlink',
    'font-family', 'font-size', 'font-weight', 'letter-spacing', 'text-anchor', 'dominant-baseline',
    'dx', 'dy', 'style', 'version', 'vector-effect', 'shape-rendering', 'display', 'visibility'
];

// Un valore che punta fuori dal file (url(http…), javascript:, expression(), @import) non passa.
// Restano solo i riferimenti interni: url(#id) e href="#id".
function safeValue(name, value) {
    const v = String(value).replace(/[\u0000- ]+/g, ' ').trim();
    if (/javascript:|vbscript:|data:|expression\s*\(|@import|behavior\s*:/i.test(v)) return false;
    if (name === 'href' || name === 'xlink:href') return /^#[\w.:-]+$/.test(v);
    const urls = v.match(/url\s*\(([^)]*)\)/gi) || [];
    return urls.every(u => /^url\s*\(\s*['"]?#[\w.:-]+['"]?\s*\)$/i.test(u));
}

function sanitizeSvg(input) {
    let text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
    text = text.replace(/^﻿/, '');
    // Le entità del DTD possono gonfiare o far leggere file: un logo non ne ha bisogno.
    if (/<!ENTITY/i.test(text)) throw new Error('SVG non valido: contiene entità.');
    text = text.replace(/<\?xml[\s\S]*?\?>/gi, '').replace(/<!DOCTYPE[\s\S]*?>/gi, '').replace(/<!--[\s\S]*?-->/g, '');
    const clean = sanitizeHtml(text, {
        allowedTags: SVG_TAGS,
        allowedAttributes: { '*': SVG_ATTRS },
        allowedSchemes: [],
        allowVulnerableTags: false,
        disallowedTagsMode: 'discard',
        nonTextTags: ['script', 'style', 'foreignObject', 'iframe', 'object', 'embed', 'noscript'],
        parser: { xmlMode: true, lowerCaseTags: false, lowerCaseAttributeNames: false, recognizeSelfClosing: true },
        exclusiveFilter: () => false,
        transformTags: {
            '*': (tagName, attribs) => {
                const kept = {};
                for (const [k, v] of Object.entries(attribs)) {
                    if (/^on/i.test(k)) continue;
                    if (safeValue(k, v)) kept[k] = v;
                }
                return { tagName, attribs: kept };
            }
        }
    }).trim();
    if (!/^<svg[\s>]/.test(clean) || !/<\/svg>$/.test(clean)) throw new Error('SVG non valido: non trovo il disegno.');
    if (!/xmlns=/.test(clean.slice(0, clean.indexOf('>')))) {
        return clean.replace(/^<svg/, '<svg xmlns="http://www.w3.org/2000/svg"');
    }
    return clean;
}

function isPng(buffer) {
    return Buffer.isBuffer(buffer) && buffer.length > PNG_MAGIC.length && buffer.subarray(0, 8).equals(PNG_MAGIC);
}

function looksLikeSvg(buffer, name, mimetype) {
    if (/^image\/svg\+xml$/i.test(mimetype || '') || /\.svg$/i.test(name || '')) return true;
    const head = buffer.subarray(0, 512).toString('utf8');
    return /<svg[\s>]/i.test(head);
}

// Dal file caricato al data URL da salvare. Lancia un errore leggibile se il file non va.
function prepareLogo(file) {
    if (!file || !Buffer.isBuffer(file.buffer) || file.buffer.length === 0) throw new Error('Nessun file caricato.');
    if (file.buffer.length > MAX_BYTES) throw new Error('Il logo pesa troppo: massimo 512 KB.');
    if (isPng(file.buffer)) {
        return 'data:image/png;base64,' + file.buffer.toString('base64');
    }
    if (looksLikeSvg(file.buffer, file.originalname, file.mimetype)) {
        const svg = sanitizeSvg(file.buffer);
        return 'data:image/svg+xml;base64,' + Buffer.from(svg, 'utf8').toString('base64');
    }
    throw new Error('Formato non supportato: carica un SVG o un PNG.');
}

// «app» o «invoice» → la colonna del DB. Qualsiasi altra cosa: null.
function columnFor(kind) {
    return Object.prototype.hasOwnProperty.call(KINDS, kind || 'app') ? KINDS[kind || 'app'] : null;
}

async function ensureColumns(pool) {
    await pool.query('ALTER TABLE companies ADD COLUMN IF NOT EXISTS logo TEXT');
    await pool.query('ALTER TABLE companies ADD COLUMN IF NOT EXISTS logo_invoice TEXT');
}

module.exports = { MAX_BYTES, sanitizeSvg, prepareLogo, columnFor, isPng, ensureColumns };
