# Rotacion de Credenciales (URGENTE)

Si un secreto estuvo en `env.txt` y ese archivo se subio o compartio, se considera comprometido.
Rotar = generar un secreto nuevo, actualizarlo en el backend y revocar/eliminar el secreto viejo.

## 1) Que debes rotar ya

1. `CRON_SECRET`
2. `EMAIL_PASSWORD` (o App Password SMTP)
3. Llave de Firebase Service Account (si estuvo expuesta)
4. Cualquier secreto heredado que no uses (`CLIENT_SECRET`, `REFRESH_TOKEN`, `NEXTAUTH_SECRET`, etc.)

## 2) Como generar nuevos secretos

### CRON_SECRET nuevo (recomendado 64+ chars)

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Pega ese valor en `CRON_SECRET`.

## 3) Rotar Firebase Service Account

1. Ve a Google Cloud Console > IAM & Admin > Service Accounts.
2. Abre la cuenta de servicio del proyecto.
3. Crea una nueva Key (JSON).
4. Actualiza backend con la nueva key (opcion A, B o C):

### Opcion A (JSON en variable)
`FIREBASE_SERVICE_ACCOUNT_KEY={...json...}`

### Opcion B (Base64)
Convierte JSON a base64:

```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content .\serviceAccountKey.json -Raw)))
```

Guarda resultado en:
`FIREBASE_SERVICE_ACCOUNT_KEY_B64=...`

### Opcion C (archivo)
Guarda JSON y define:
`FIREBASE_SERVICE_ACCOUNT_FILE=./serviceAccountKey.json`

5. Elimina/revoca la key vieja en GCP.

## 4) Rotar SMTP (correo)

- Si usas Outlook/Office365, genera un nuevo App Password o cambia credencial SMTP.
- Actualiza:
  - `EMAIL_USER`
  - `EMAIL_PASSWORD`

## 5) Variables minimas que usa este backend

- `PORT`
- `APP_URL` o `NEXT_PUBLIC_APP_URL`
- `CORS_ORIGIN` (opcional pero recomendado)
- `CRON_SECRET`
- `EMAIL_USER`
- `EMAIL_PASSWORD`
- `FIREBASE_DATABASE_URL` (o `NEXT_PUBLIC_FIREBASE_DATABASE_URL`)
- Service account por una de estas rutas:
  - `FIREBASE_SERVICE_ACCOUNT_KEY`
  - `FIREBASE_SERVICE_ACCOUNT_KEY_B64`
  - `FIREBASE_SERVICE_ACCOUNT_FILE`
  - o archivo `serviceAccountKey.b64`

## 6) Limpieza recomendada

Quita del `env.txt` variables que ya no se usan en este backend:
- `CLIENT_ID`
- `CLIENT_SECRET`
- `TENANT_ID`
- `REFRESH_TOKEN`
- `NEXTAUTH_SECRET`

## 7) Despues de rotar

1. Reinicia backend.
2. Prueba:
   - `GET /health`
   - login admin OTP
   - crear prestamo
   - cron con `Authorization: Bearer <CRON_SECRET>`