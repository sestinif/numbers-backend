const test = require('node:test');
const assert = require('node:assert');
const L = require('../company-logo');

const svgFile = (text, name = 'logo.svg') => ({ buffer: Buffer.from(text, 'utf8'), originalname: name, mimetype: 'image/svg+xml' });
const decode = dataUrl => Buffer.from(dataUrl.split(',')[1], 'base64').toString('utf8');
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32, 1)]);

test('un SVG pulito passa com\'è, viewBox e attributi di disegno compresi', () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="#fff" fill-rule="evenodd" d="M0 0L10 10Z"/><circle cx="5" cy="5" r="2" stroke-width="1"/></svg>';
    const out = L.sanitizeSvg(svg);
    assert.match(out, /^<svg xmlns="http:\/\/www.w3.org\/2000\/svg" viewBox="0 0 20 20">/);
    assert.match(out, /fill-rule="evenodd"/);
    assert.match(out, /<circle cx="5" cy="5" r="2" stroke-width="1">/);
});

test('via gli script, gli handler on* e gli stili', () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script><style>rect{fill:red}</style><rect width="5" height="5" onclick="x()" onMouseOver="y()"/></svg>';
    const out = L.sanitizeSvg(svg);
    assert.doesNotMatch(out, /script|alert|onload|onclick|onmouseover|<style/i);
    assert.match(out, /<rect width="5" height="5">/);
});

test('via i link esterni: href, url() fuori dal file, javascript:, data:, foreignObject, image', () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect fill="url(http://evil/x)"/></a>'
        + '<use href="https://evil/x.svg#a"/><use href="#ok"/><image href="http://x/a.png"/><image href="data:image/png;base64,AAA"/>'
        + '<path style="fill:url(https://e/p)" d="M0 0"/><path fill="url(#grad)" d="M1 1"/><foreignObject><div>hi</div></foreignObject></svg>';
    const out = L.sanitizeSvg(svg);
    assert.doesNotMatch(out, /http(?!:\/\/www\.w3\.org)|javascript|data:|<a[\s>]|<image|foreignObject|<div/i);
    assert.match(out, /<use href="#ok">/);
    assert.match(out, /fill="url\(#grad\)"/);
});

test('niente entità del DTD, e un file che non è un disegno viene rifiutato', () => {
    assert.throws(() => L.sanitizeSvg('<!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>'), /entità/);
    assert.throws(() => L.sanitizeSvg('<html><body>ciao</body></html>'), /non trovo il disegno/);
    assert.throws(() => L.sanitizeSvg(''), /non trovo il disegno/);
});

test('se manca xmlns lo aggiunge, se no un <img> non lo disegna', () => {
    assert.match(L.sanitizeSvg('<svg viewBox="0 0 1 1"><rect width="1" height="1"/></svg>'), /^<svg xmlns="http:\/\/www.w3.org\/2000\/svg" viewBox/);
});

test('il caricamento: SVG ripulito e PNG diventano data URL', () => {
    const svgUrl = L.prepareLogo(svgFile('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><script>x</script><rect width="1" height="1"/></svg>'));
    assert.match(svgUrl, /^data:image\/svg\+xml;base64,/);
    assert.doesNotMatch(decode(svgUrl), /script|<\?xml/);
    const pngUrl = L.prepareLogo({ buffer: PNG, originalname: 'logo.png', mimetype: 'image/png' });
    assert.strictEqual(pngUrl, 'data:image/png;base64,' + PNG.toString('base64'));
});

test('il caricamento rifiuta file vuoti, troppo pesanti e formati diversi', () => {
    assert.throws(() => L.prepareLogo(null), /Nessun file/);
    assert.throws(() => L.prepareLogo({ buffer: Buffer.alloc(0) }), /Nessun file/);
    assert.throws(() => L.prepareLogo({ buffer: Buffer.alloc(L.MAX_BYTES + 1, 32), originalname: 'x.svg' }), /pesa troppo/);
    assert.throws(() => L.prepareLogo({ buffer: Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]), originalname: 'foto.jpg', mimetype: 'image/jpeg' }), /SVG o un PNG/);
    // Un PNG finto (nome .png, dentro testo) non passa per PNG.
    assert.throws(() => L.prepareLogo({ buffer: Buffer.from('ciao'), originalname: 'logo.png', mimetype: 'image/png' }), /SVG o un PNG/);
});

test('il tipo di logo: app o fatture, nient\'altro (il nome finisce in una query)', () => {
    assert.strictEqual(L.columnFor('app'), 'logo');
    assert.strictEqual(L.columnFor(undefined), 'logo');
    assert.strictEqual(L.columnFor('invoice'), 'logo_invoice');
    assert.strictEqual(L.columnFor('logo; DROP TABLE companies'), null);
    assert.strictEqual(L.columnFor('toString'), null);
    assert.strictEqual(L.columnFor('__proto__'), null);
});
