// Numbers — collegamento a Wise (conto business della LLC)
//
// Cosa fa: legge saldi e beneficiari, chiede un preventivo, PREPARA un bonifico e, su richiesta,
// lo FA PARTIRE (fundTransfer: paga dal saldo Wise). Preparare e pagare sono due chiamate
// separate: un bonifico preparato resta su Wise «in attesa di pagamento» finché qualcuno non
// lo paga, dall'app di Wise o da Numbers.
// fundTransfer è l'unica chiamata che muove soldi. Dal 19/10/2026, per scelta di Federico, la
// usa solo la rotta protetta dal PIN (vedi pay-pin.js e server.js): senza PIN configurato su
// Render nessuno può chiamarla. Non va mai chiamata da altre parti.
//
// Token: variabile d'ambiente WISE_API_TOKEN (token personale «full access» creato su Wise:
// Your Account → Connect and manage apps → API tokens). Viaggia solo nell'intestazione
// Authorization e non finisce mai in un messaggio d'errore o in un log.
// Facoltative: WISE_PROFILE_ID (se i profili business sono più d'uno), WISE_API_BASE.
//
// Nota di Wise: se sul conto sono attive le «Payment approvals», preparare bonifici da API
// viene rifiutato («missing approval»). Le due cose non convivono.

const DEFAULT_BASE = 'https://api.wise.com';
const TIMEOUT_MS = 15000;
const MAX_RECIPIENT_PAGES = 10;

class WiseError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'WiseError';
        this.status = status || 0;
    }
}

function isConfigured(env) {
    return !!(env && typeof env.WISE_API_TOKEN === 'string' && env.WISE_API_TOKEN.trim());
}

// ===== Funzioni pure =====

const STATUS = {
    incoming_payment_waiting: { state: 'waiting', label: 'Da confermare su Wise', final: false },
    // Numbers sta pagando adesso il bonifico (vedi wise-payments.js): blocca un secondo invio in parallelo.
    sending: { state: 'paid', label: 'In invio', final: false },
    incoming_payment_initiated: { state: 'paid', label: 'In lavorazione', final: false },
    processing: { state: 'paid', label: 'In lavorazione', final: false },
    funds_converted: { state: 'paid', label: 'In lavorazione', final: false },
    outgoing_payment_sent: { state: 'paid', label: 'Inviato', final: true },
    cancelled: { state: 'cancelled', label: 'Annullato', final: true },
    funds_refunded: { state: 'returned', label: 'Tornato indietro', final: true },
    bounced_back: { state: 'returned', label: 'Tornato indietro', final: false },
    charged_back: { state: 'returned', label: 'Tornato indietro', final: true },
};

// Uno stato che non conosciamo resta «in attesa» e si mostra com'è: meglio di un'etichetta inventata.
function statusInfo(status) {
    const known = STATUS[status];
    return known ? { ...known } : { state: 'waiting', label: String(status || 'sconosciuto'), final: false };
}

// La spesa si segna una volta sola, e solo quando i soldi sono usciti davvero dal conto.
function shouldTrackExpense(payment) {
    if (!payment || !payment.track_expense || payment.expense_id) return false;
    return statusInfo(payment.status).state === 'paid';
}

function cleanIban(value) {
    return String(value == null ? '' : value).replace(/\s+/g, '').toUpperCase();
}

// Controllo di forma (paese, cifre di controllo, lunghezza) più il resto 97: ferma i refusi
// prima di chiamare Wise. Che il conto esista lo dice Wise.
function validIban(value) {
    const iban = cleanIban(value);
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
    const moved = iban.slice(4) + iban.slice(0, 4);
    let rest = 0;
    for (const ch of moved) {
        const n = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
        for (const d of n) rest = (rest * 10 + Number(d)) % 97;
    }
    return rest === 1;
}

function maskAccount(details) {
    const d = details || {};
    const iban = d.IBAN || d.iban;
    if (iban) { const c = cleanIban(iban); return `${c.slice(0, 4)} •••• ${c.slice(-4)}`; }
    if (d.accountNumber) return `•••• ${String(d.accountNumber).slice(-4)}`;
    if (d.email) return String(d.email);
    return '';
}

// Wise restituisce il beneficiario in due forme (lista v2 e creazione v1): qui diventa una sola.
function summarizeRecipient(raw) {
    const name = (raw.name && raw.name.fullName) || raw.accountHolderName || '';
    return {
        id: raw.id,
        name: String(name).trim(),
        currency: raw.currency || '',
        country: raw.country || '',
        type: raw.type || '',
        account: maskAccount(raw.details),
    };
}

// Perché Wise ha rifiutato un pagamento, in parole di Federico. Un codice nuovo cade sul messaggio generico.
const FUND_REJECTIONS = {
    'balance.insufficient-funds': 'Il saldo Wise non basta per questo bonifico.',
    'balance.no-balance-for-currency': 'Non c\'è un saldo Wise in questa valuta da cui pagare.',
    'balance.currency-unsupported': 'Questa valuta non si può pagare dal saldo Wise.',
    'balance.account-inactive': 'Il saldo Wise da cui pagare non è attivo.',
    'balance.account-not-found': 'Il saldo Wise da cui pagare non c\'è.',
    'balance.payment-option-unavailable': 'Dal saldo Wise questo bonifico adesso non si può pagare.',
    'payment.option-unavailable': 'Dal saldo Wise questo bonifico adesso non si può pagare.',
    'transfer.invalid-state': 'Il bonifico non è più in attesa: è già partito o è stato annullato.',
    'transfer.not-found': 'Wise non trova questo bonifico.',
};

// «TRANSFER-1234567» → 1234567. Le righe dell'estratto che non sono bonifici danno null.
function transferIdFromReference(ref) {
    const m = /^TRANSFER-(\d+)$/.exec(String(ref == null ? '' : ref));
    return m ? Number(m[1]) : null;
}

function positiveAmount(value) {
    const n = typeof value === 'number' ? value : parseFloat(value);
    return Number.isFinite(n) && n > 0 ? Math.round(n * 100) / 100 : null;
}

function errorMessage(status, body) {
    if (status === 401) return 'Wise non riconosce il token: è sbagliato, scaduto o cancellato.';
    if (status === 403) return 'Il token di Wise non ha il permesso per questa operazione (serve «full access»).';
    const first = body && Array.isArray(body.errors) && body.errors[0];
    const text = (first && (first.message || first.code)) || (body && (body.message || body.error_description || body.error));
    return text ? String(text) : `Wise ha risposto con un errore (${status}).`;
}

// ===== Cliente =====

function createClient({ token, baseUrl, profileId, fetchImpl } = {}) {
    const doFetch = fetchImpl || fetch;
    const base = (baseUrl || DEFAULT_BASE).replace(/\/+$/, '');
    let knownProfile = profileId ? Number(profileId) : null;

    async function request(method, path, body) {
        let res;
        try {
            res = await doFetch(base + path, {
                method,
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: body === undefined ? undefined : JSON.stringify(body),
                signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(TIMEOUT_MS) : undefined,
            });
        } catch (e) {
            throw new WiseError('Wise non risponde. Riprova tra poco.', 0);
        }
        const text = await res.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (!res.ok) throw new WiseError(errorMessage(res.status, data), res.status);
        return data;
    }

    async function getProfileId() {
        if (knownProfile) return knownProfile;
        const profiles = await request('GET', '/v2/profiles');
        const business = (profiles || []).find(p => String(p.type).toUpperCase() === 'BUSINESS');
        if (!business) throw new WiseError('Su questo accesso Wise non c\'è un profilo business.', 0);
        knownProfile = business.id;
        return knownProfile;
    }

    async function balances() {
        const id = await getProfileId();
        const rows = await request('GET', `/v4/profiles/${id}/balances?types=STANDARD`);
        return (rows || [])
            .map(b => ({ id: b.id, currency: b.currency, amount: Number((b.amount && b.amount.value) || 0) }))
            .sort((a, b) => (b.amount > 0) - (a.amount > 0) || b.amount - a.amount);
    }

    // L'estratto di un saldo, ridotto ai soli bonifici in uscita: [{ date, transferId, amount, currency }].
    // Sola lettura. Fuori da USA, Canada, Australia, Nuova Zelanda, Singapore e Malesia Wise chiede
    // l'autenticazione forte, che un token personale non sa dare: in quel caso errore chiaro (403).
    async function statement(balanceId, currency, intervalStart, intervalEnd) {
        const profile = await getProfileId();
        const qs = new URLSearchParams({ currency, intervalStart, intervalEnd, type: 'COMPACT' }).toString();
        let data;
        try {
            data = await request('GET', `/v1/profiles/${profile}/balance-statements/${Number(balanceId)}/statement.json?${qs}`);
        } catch (e) {
            if (e instanceof WiseError && e.status === 403) {
                throw new WiseError('Wise non lascia leggere l\'estratto del conto da Numbers (per questo conto serve l\'autenticazione forte, che un token personale non può dare).', 502);
            }
            throw e;
        }
        return ((data && data.transactions) || [])
            .filter(t => t.type === 'DEBIT' && t.details && t.details.type === 'TRANSFER')
            .map(t => ({
                date: t.date,
                transferId: transferIdFromReference(t.referenceNumber),
                amount: Math.abs(Number(t.amount && t.amount.value) || 0),
                currency: t.amount && t.amount.currency,
            }))
            .filter(t => t.transferId);
    }

    async function recipients() {
        const id = await getProfileId();
        const out = [];
        let seek = null;
        for (let page = 0; page < MAX_RECIPIENT_PAGES; page++) {
            const data = await request('GET', `/v2/accounts?profileId=${id}&active=true&size=20${seek ? `&seekPosition=${seek}` : ''}`);
            for (const raw of (data && data.content) || []) {
                if (raw.active !== false) out.push(summarizeRecipient(raw));
            }
            seek = data && data.seekPositionForNext;
            if (!seek) break;
        }
        return out;
    }

    async function createIbanRecipient({ name, iban, legalType } = {}) {
        const holder = String(name == null ? '' : name).trim();
        if (!holder) throw new WiseError('Scrivi il nome del beneficiario.', 400);
        if (!validIban(iban)) throw new WiseError('L\'IBAN non è valido: controlla che sia scritto giusto.', 400);
        const profile = await getProfileId();
        const made = await request('POST', '/v1/accounts', {
            currency: 'EUR',
            type: 'iban',
            profile,
            accountHolderName: holder,
            details: { legalType: legalType === 'BUSINESS' ? 'BUSINESS' : 'PRIVATE', IBAN: cleanIban(iban) },
        });
        return summarizeRecipient(made);
    }

    // amount è la cifra che deve ARRIVARE al beneficiario, nella sua valuta.
    async function quote({ recipientId, amount, targetCurrency, sourceCurrency } = {}) {
        const value = positiveAmount(amount);
        if (value == null) throw new WiseError('L\'importo deve essere un numero maggiore di zero.', 400);
        const id = await getProfileId();
        const q = await request('POST', `/v3/profiles/${id}/quotes`, {
            sourceCurrency,
            targetCurrency,
            targetAmount: value,
            targetAccount: Number(recipientId),
            payOut: 'BANK_TRANSFER',
        });
        const fromBalance = ((q && q.paymentOptions) || []).find(o => o.payIn === 'BALANCE');
        if (!fromBalance) throw new WiseError('Questo bonifico non si può pagare dal saldo Wise.', 422);
        if (fromBalance.disabled) {
            const why = fromBalance.disabledReason && fromBalance.disabledReason.message;
            throw new WiseError(why || 'Dal saldo Wise questo bonifico adesso non si può pagare.', 422);
        }
        return {
            id: q.id,
            sourceCurrency: q.sourceCurrency,
            sourceAmount: fromBalance.sourceAmount,
            targetCurrency: q.targetCurrency,
            targetAmount: fromBalance.targetAmount,
            fee: Number((fromBalance.fee && fromBalance.fee.total) || 0),
            rate: q.rate,
            delivery: fromBalance.estimatedDelivery || fromBalance.formattedEstimatedDelivery || null,
        };
    }

    // key: chiave anti-doppione. Riprovare con la stessa chiave non crea un secondo bonifico.
    async function createTransfer({ recipientId, quoteId, reference, key } = {}) {
        return request('POST', '/v1/transfers', {
            targetAccount: Number(recipientId),
            quoteUuid: quoteId,
            customerTransactionId: key,
            details: { reference: String(reference == null ? '' : reference).trim() },
        });
    }

    function getTransfer(transferId) {
        return request('GET', `/v1/transfers/${Number(transferId)}`);
    }

    // FA PARTIRE I SOLDI: paga il bonifico dal saldo. Da chiamare solo dalla rotta protetta dal PIN.
    // Un bonifico già pagato non è un errore (already: true): si risincronizza e basta.
    // Se il conto non permette di pagare da API il bonifico resta preparato, e lo si conferma dall'app.
    async function fundTransfer(transferId) {
        const profile = await getProfileId();
        let data;
        try {
            data = await request('POST', `/v3/profiles/${profile}/transfers/${Number(transferId)}/payments`, { type: 'BALANCE' });
        } catch (e) {
            if (e instanceof WiseError && e.status === 403) {
                throw new WiseError('Wise non lascia far partire il bonifico da Numbers (serve un token «full access» su un conto che lo permetta). Il bonifico resta preparato: confermalo dall\'app di Wise.', 502);
            }
            throw e;
        }
        if (data && data.status === 'REJECTED') {
            if (data.errorCode === 'payment.exists') return { status: 'COMPLETED', already: true };
            throw new WiseError(FUND_REJECTIONS[data.errorCode] || 'Wise ha rifiutato il pagamento del bonifico.', 422);
        }
        if (!data || (data.status !== 'COMPLETED' && data.status !== 'CREATED')) {
            throw new WiseError('Wise ha risposto in un modo che non riconosco: controlla lo stato del bonifico nell\'app di Wise prima di riprovare.', 502);
        }
        return { status: data.status, already: false };
    }

    // Wise lo permette solo finché il bonifico è in attesa di pagamento.
    function cancelTransfer(transferId) {
        return request('PUT', `/v1/transfers/${Number(transferId)}/cancel`);
    }

    return { profileId: getProfileId, balances, statement, recipients, createIbanRecipient, quote, createTransfer, fundTransfer, getTransfer, cancelTransfer };
}

// Il collegamento Wise di UNA azienda. Ogni azienda può avere il suo token (WISE_API_TOKEN_<id>, e se serve
// WISE_PROFILE_ID_<id>), cioè i suoi conti; il token «generale» (WISE_API_TOKEN) vale solo per l'azienda a cui
// appartiene (`usesDefault`). Ritorna le variabili da dare a clientFromEnv, envForCompany, o null se l'azienda non ha Wise.
function envForCompany(env, companyId, usesDefault) {
    const id = String(companyId).replace(/\D/g, '');
    const own = env && typeof env[`WISE_API_TOKEN_${id}`] === 'string' ? env[`WISE_API_TOKEN_${id}`].trim() : '';
    if (own) {
        return { WISE_API_TOKEN: own, WISE_API_BASE: env.WISE_API_BASE, WISE_PROFILE_ID: env[`WISE_PROFILE_ID_${id}`] };
    }
    if (usesDefault && isConfigured(env)) {
        return { WISE_API_TOKEN: env.WISE_API_TOKEN.trim(), WISE_API_BASE: env.WISE_API_BASE, WISE_PROFILE_ID: env.WISE_PROFILE_ID };
    }
    return null;
}

function clientFromEnv(env) {
    return createClient({
        token: env.WISE_API_TOKEN.trim(),
        baseUrl: env.WISE_API_BASE,
        profileId: env.WISE_PROFILE_ID,
    });
}

module.exports = {
    WiseError, isConfigured, createClient, clientFromEnv, envForCompany,
    statusInfo, shouldTrackExpense, transferIdFromReference, validIban, cleanIban, maskAccount, summarizeRecipient, positiveAmount,
};
