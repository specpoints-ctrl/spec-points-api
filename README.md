# 🚀 SpecPoints API

Backend do sistema de fidelidade SpecPoints - Express + TypeScript + Firebase + PostgreSQL

## 📋 Stack

- **Runtime:** Node.js 20+
- **Framework:** Express.js
- **Language:** TypeScript
- **Database:** PostgreSQL (Railway)
- **Auth:** Firebase Admin SDK
- **ORM:** pg-promise
- **Deploy:** Railway

## 🚀 Deploy no Railway

### 1. Criar Service

1. Acesse Railway: https://railway.app
2. New Project → Deploy from GitHub Repo
3. Selecione: `spec-points-api`
4. Railway detecta automaticamente Node.js

### 2. Configurar Variáveis de Ambiente

No Railway, adicione as seguintes variáveis:

```bash
DATABASE_URL=${{Postgres.DATABASE_URL}}  # Referência ao PostgreSQL
FIREBASE_PROJECT_ID=spec-points-prod
FIREBASE_PRIVATE_KEY="{sua-private-key-com-newlines}"
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-fbsvc@spec-points-prod.iam.gserviceaccount.com
JWT_SECRET=your-secret-key
NODE_ENV=production
API_PORT=3000
LOG_LEVEL=info
CORS_ORIGIN=https://spec-points-web.railway.app
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_ATTEMPTS=5
```

### 3. Rodar Migrações

Após o primeiro deploy:

```bash
# Via Railway CLI
railway run npm run migrate

# Ou conecte diretamente no banco e execute os SQLs
```

### 4. Verificar Deploy

Acesse: `https://seu-projeto.railway.app/health`

Deve retornar:
```json
{
  "status": "healthy",
  "timestamp": "2026-03-02T...",
  "uptime": 123.45
}
```

## 🛠️ Desenvolvimento Local

### Instalação

```bash
npm install
```

### Configurar Environment

Copie `.env.example` para `.env.local` e preencha:

```bash
cp .env.example .env.local
```

### Rodar Migrações

```bash
npm run migrate
```

### Iniciar Servidor

```bash
npm run dev
```

Servidor rodando em: `http://localhost:3000`

## 📡 Endpoints

### Public
- `GET /health` - Health check
- `POST /api/auth/register` - Registrar usuário
- `POST /api/auth/login` - Login

### Protected (require Bearer token)
- `GET /api/auth/me` - Info do usuário
- `GET /api/architects` - Listar arquitetos
- `GET /api/stores` - Listar lojas
- `POST /api/sales` - Criar venda
- ... (outros endpoints)

## 🗄️ Database

### Schema

12 tabelas principais:
- `users` - Usuários (Firebase UID)
- `user_roles` - Papéis (admin, architect, lojista)
- `architects` - Arquitetos cadastrados
- `stores` - Lojas parceiras
- `sales` - Vendas registradas
- `prizes` - Prêmios disponíveis
- `redemptions` - Resgates de prêmios
- `login_attempts` - Rate limiting
- `security_audit_log` - Auditoria
- ... (e mais)

### Migrações

Arquivos SQL em: `src/db/migrations/`
- `0001_initial_schema.sql` - Criar tabelas
- `0002_seed_data.sql` - Dados iniciais

## 🔐 Segurança

- ✅ Rate limiting (5 tentativas/15 min)
- ✅ Helmet.js security headers
- ✅ CORS configurado
- ✅ Firebase token verification
- ✅ SQL injection prevention (parameterized queries)
- ✅ Audit logging

## 📦 Scripts

- `npm run dev` - Desenvolvimento com hot reload
- `npm run build` - Build para produção
- `npm start` - Rodar produção
- `npm run migrate` - Rodar migrações
- `npm run lint` - Lint código
- `npm test` - Rodar testes

## 📞 Suporte

Issues: https://github.com/specpoints-ctrl/spec-points-api/issues

## 📄 Licença

MIT © 2026 SpecPoints
