#!/usr/bin/env python3
"""Numbers — collega la casella da cui partono le email (solo invio).

Si lancia UNA volta, a mano, sul Mac di Federico:

    python3 tools/gmail-collega.py

Cosa fa:
1. legge il file scaricato da Google Cloud (client OAuth di tipo «Desktop app»);
2. apre il browser sulla pagina di Google: lì si entra con la casella da cui devono partire
   le email e si accetta l'unico permesso chiesto, «inviare email per tuo conto»
   (gmail.send: Numbers NON può leggere la posta);
3. scrive i tre valori da mettere su Render in fondo a Internal/App/CREDENZIALI.md.

A schermo non stampa nessun segreto. Usa solo la libreria standard di Python.
"""
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request
import webbrowser

SCOPE = 'https://www.googleapis.com/auth/gmail.send'
HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.abspath(os.path.join(HERE, '..', '..', '..'))          # Internal/App
DEFAULT_CLIENT_FILE = os.path.join(APP_DIR, 'Numbers', 'gmail-credentials.json')
CREDENTIALS_MD = os.path.join(APP_DIR, 'CREDENZIALI.md')
SENDER_HINT = 'info@scalingcatalyst.com'


def fail(message):
    print('\nNon collegato: ' + message)
    sys.exit(1)


def load_client(path):
    if not os.path.exists(path):
        fail(f'non trovo il file di Google in\n  {path}\nScaricalo da Google Cloud (client «Desktop app») e salvalo lì con quel nome.')
    data = json.load(open(path, encoding='utf-8'))
    block = data.get('installed') or data.get('web')
    if not block or not block.get('client_id') or not block.get('client_secret'):
        fail('il file non è un client OAuth di tipo «Desktop app».')
    return block['client_id'], block['client_secret']


def wait_for_code(server, state):
    """Aspetta che Google rimandi il browser qui con il codice."""
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if query.get('state', [''])[0] != state:
                self.send_response(400); self.end_headers(); return
            result['code'] = query.get('code', [''])[0]
            result['error'] = query.get('error', [''])[0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            text = 'Fatto. Puoi chiudere questa scheda e tornare al terminale.' if result['code'] else 'Collegamento annullato. Puoi chiudere questa scheda.'
            self.wfile.write(f'<body style="font-family:sans-serif;padding:40px">{text}</body>'.encode('utf-8'))

        def log_message(self, *args):
            pass

    server.RequestHandlerClass = Handler
    while 'code' not in result:
        server.handle_request()
    return result


def main():
    client_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CLIENT_FILE
    client_id, client_secret = load_client(client_file)

    server = http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
    redirect_uri = f'http://127.0.0.1:{server.server_port}'
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode({
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': SCOPE,
        'access_type': 'offline',
        'prompt': 'consent',
        'login_hint': SENDER_HINT,
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    })
    print('Apro il browser sulla pagina di Google.')
    print(f'Entra con {SENDER_HINT} e accetta il permesso di invio.')
    if not webbrowser.open(url):
        print('\nIl browser non si è aperto. Copia questo indirizzo e aprilo a mano:\n' + url)

    got = wait_for_code(server, state)
    if not got.get('code'):
        fail('Google non ha dato il permesso (' + (got.get('error') or 'annullato') + ').')

    body = urllib.parse.urlencode({
        'code': got['code'],
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
        'code_verifier': verifier,
    }).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request('https://oauth2.googleapis.com/token', data=body), timeout=30) as res:
            token = json.load(res)
    except Exception as exc:  # noqa: BLE001 - qualunque errore di rete va detto in chiaro
        fail(f'Google ha rifiutato lo scambio del codice ({exc}).')
    refresh = token.get('refresh_token')
    if not refresh:
        fail('Google non ha dato il gettone di lunga durata. Riprova: se la casella aveva già dato il permesso, toglilo da myaccount.google.com/permissions e rilancia.')
    if SCOPE not in (token.get('scope') or ''):
        fail('il permesso di invio non è stato accettato.')

    section = (
        '\n## Numbers — Gmail, solo invio (collegato con tools/gmail-collega.py)\n'
        'Tre variabili da mettere su Render, servizio `numbers-backend`. Permesso: solo inviare email (gmail.send).\n'
        'Per staccare tutto: togli le variabili da Render, o revoca l\'accesso da myaccount.google.com/permissions.\n\n'
        '```\n'
        f'GMAIL_CLIENT_ID={client_id}\n'
        f'GMAIL_CLIENT_SECRET={client_secret}\n'
        f'GMAIL_REFRESH_TOKEN={refresh}\n'
        f'GMAIL_FROM={SENDER_HINT}\n'
        '```\n'
    )
    with open(CREDENTIALS_MD, 'a', encoding='utf-8') as out:
        out.write(section)
    print('\nCollegato. I valori da mettere su Render sono in fondo a:')
    print('  ' + CREDENTIALS_MD)
    print('Qui non li stampo.')


if __name__ == '__main__':
    main()
