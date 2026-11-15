# Vamos Pa' Arriba

App de salud y bienestar: comida (plan familiar y compras), ejercicio sin gimnasio,
calma (respiración, meditación, oración, sueño) y registro médico.

Node 20 + Express + PostgreSQL. Frontend en `public/index.html`.
El esquema (`schema.sql`) se aplica solo al arrancar.

## Variables de entorno
| Variable | Obligatoria | Para qué |
|---|---|---|
| `DATABASE_URL` | sí | Conexión a Postgres |
| `JWT_SECRET` | sí | Firma de las sesiones (frase larga y secreta) |
| `REGISTRO_CODIGO` | no | Si está, se pide para registrarse. Vacía = registro abierto |
| `ADMIN_EMAIL` | no | Email del dueño: ve el panel de estadísticas en Ajustes |
| `RESEND_API_KEY` | no | Para "Olvidé mi contraseña" |
| `MAIL_FROM` | no | Remitente, ej.: `Vamos Pa' Arriba <no-reply@i8aproject.com>` |
| `SOPORTE_EMAIL` | no | Contacto que se muestra en la app y en la privacidad |
| `APP_URL` | no | URL pública, ej.: `https://vamospaarriba.i8aproject.com` |
| `PORT` | no | Por defecto 3000 |
