# Backend File Scanner

## Email Verification

Variables de entorno requeridas para verificación por correo:

```
DATABASE_URL=postgres://user:pass@host:port/db
JWT_SECRET=alguna_clave_segura
APP_BASE_URL=http://localhost:5173
SMTP_HOST=smtp.tu-proveedor.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=tu_usuario
SMTP_PASS=tu_password
MAIL_FROM="File Scanner <no-reply@tudominio.com>"
```

Flujo:

1. POST /api/register crea usuario (email_verified=false) y envía email con enlace: `${APP_BASE_URL}/verify-email?token=...`.
2. GET /api/users/verify-email?token=... valida token (24h), marca email verificado y consume token.
3. POST /api/users/resend-verification { email } invalida tokens previos y envía uno nuevo.
4. POST /api/login rechaza si email_verified=false (HTTP 403).

Tabla utilizada: `email_verification` (ver `schema.sql`). El token se almacena con hash SHA-256.

## Scripts

Instalar dependencias:

```
npm install
```

Desarrollar con recarga:

```
npm run dev
```

Producción:

```
npm start
```
