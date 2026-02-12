# Numbers Backend API 🚀

Backend API per l'applicazione di gestione fatture **Numbers**.

## 📋 Configurazione per Render.com

### Build Command
```
npm install
```

### Start Command
```
npm start
```

### Environment Variables Required

```
DATABASE_URL=postgresql://user:password@host/database
JWT_SECRET=numbers_jwt_secret_super_sicuro_2024
PORT=10000
NODE_ENV=production
```

### Optional (per email reset password)
```
SENDGRID_API_KEY=SG.xxxxxxx
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
APP_URL=https://your-app.onrender.com
```

## 🗄️ Setup Database

Dopo il primo deploy, esegui nella Shell di Render:

```bash
psql $DATABASE_URL < database/schema.sql
```

Questo crea tutte le tabelle necessarie.

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` - Registrazione nuovo utente
- `POST /api/auth/login` - Login utente
- `POST /api/auth/forgot-password` - Richiesta reset password
- `POST /api/auth/reset-password` - Reset password con token

### Companies
- `GET /api/companies` - Lista aziende utente
- `POST /api/companies` - Crea nuova azienda
- `PUT /api/companies/:id` - Aggiorna azienda
- `DELETE /api/companies/:id` - Elimina azienda

### Customers
- `GET /api/customers` - Lista clienti utente
- `POST /api/customers` - Crea nuovo cliente
- `PUT /api/customers/:id` - Aggiorna cliente
- `DELETE /api/customers/:id` - Elimina cliente

### Invoices
- `GET /api/invoices` - Lista fatture utente
- `POST /api/invoices` - Crea nuova fattura
- `PUT /api/invoices/:id` - Aggiorna fattura
- `DELETE /api/invoices/:id` - Elimina fattura

### Expenses
- `GET /api/expenses` - Lista spese utente
- `POST /api/expenses` - Crea nuova spesa
- `PUT /api/expenses/:id` - Aggiorna spesa
- `DELETE /api/expenses/:id` - Elimina spesa

### Reminders
- `GET /api/reminders` - Lista promemoria utente
- `POST /api/reminders` - Crea nuovo promemoria
- `PUT /api/reminders/:id` - Aggiorna promemoria
- `DELETE /api/reminders/:id` - Elimina promemoria

## 🔒 Authentication

Tutte le API (eccetto `/api/auth/*`) richiedono header di autenticazione:

```
Authorization: Bearer <JWT_TOKEN>
```

Il token JWT viene restituito al login e ha validità 30 giorni.

## 🏗️ Database Schema

- **users** - Utenti registrati
- **companies** - Aziende (multi-company support)
- **customers** - Clienti
- **invoices** - Fatture
- **expenses** - Spese
- **reminders** - Promemoria
- **password_reset_tokens** - Token per reset password

Ogni tabella (eccetto users e password_reset_tokens) ha campo `user_id` per isolamento dati tra utenti.

## 🔐 Security

- Password hashate con **bcrypt** (10 rounds)
- JWT tokens con secret sicuro
- Validazione input con **express-validator**
- CORS configurato
- Headers sicuri
- Rate limiting (TODO)

## 📦 Dependencies

- **express** - Web framework
- **pg** - PostgreSQL client
- **bcrypt** - Password hashing
- **jsonwebtoken** - JWT authentication
- **cors** - CORS middleware
- **dotenv** - Environment variables
- **express-validator** - Input validation
- **@sendgrid/mail** - Email sending

## 🚀 Deploy su Render

1. Crea database PostgreSQL su Render
2. Crea Web Service collegato a questo repository
3. Configura variabili d'ambiente
4. Deploy automatico
5. Esegui `psql $DATABASE_URL < database/schema.sql` nella Shell

## ✅ Health Check

```
GET /api/health
```

Ritorna:
```json
{
  "status": "OK",
  "timestamp": "2024-02-12T21:00:00.000Z"
}
```

## 📝 Notes

- Il server ascolta su porta definita da `process.env.PORT` (default: 5000)
- Render assegna automaticamente la porta via variabile PORT
- Database connection pool configurato per Render
- Auto-disconnect on SIGTERM per graceful shutdown
