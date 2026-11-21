// Vamos Pa' Arriba — servidor
// Node 20 + Express + PostgreSQL. Variables de entorno (en Easypanel):
//   DATABASE_URL     conexión a Postgres
//   JWT_SECRET       cadena larga y secreta
//   REGISTRO_CODIGO  opcional: si está, se pide para crear cuenta. Vacío = registro abierto
//   ADMIN_EMAIL      email del dueño: ve el panel de estadísticas
//   RESEND_API_KEY   para enviar el mail de "olvidé mi contraseña"
//   MAIL_FROM        remitente, ej.: Vamos Pa' Arriba <no-reply@i8aproject.com>
//   SOPORTE_EMAIL    email de contacto que se muestra en la app y en la privacidad
//   APP_URL          opcional, ej.: https://vamospaarriba.i8aproject.com
//   OPENAI_API_KEY   opcional: activa "Completar con IA" (leer PDF o foto de un estudio)
//   OPENAI_MODEL     opcional, modelo a usar (por defecto gpt-5-mini)
//   IA_LIMITE_MES    opcional, lecturas con IA por usuario por mes (por defecto 10)
//   TTS_MODEL        opcional, modelo de voz de OpenAI (por defecto gpt-4o-mini-tts)
//   TTS_VOZ          opcional, voz de OpenAI (por defecto sage)
//   PORT             opcional, por defecto 3000

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool, types } = require('pg');

// Las columnas DATE vuelven como texto 'YYYY-MM-DD' (sin corrimientos de zona horaria)
types.setTypeParser(1082, (v) => v);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cambiar-esta-clave';
const REGISTRO_CODIGO = (process.env.REGISTRO_CODIGO || '').trim();
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || "Vamos Pa' Arriba <no-reply@i8aproject.com>";
const SOPORTE_EMAIL = process.env.SOPORTE_EMAIL || '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-5-mini';
const OPENAI_URL = (process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, '');
const IA_LIMITE_MES = parseInt(process.env.IA_LIMITE_MES, 10) || 10;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

const TIPOS = ['ejercicio', 'meditacion', 'oracion', 'consulta', 'estudio',
  'psicologo', 'sueno', 'peso', 'episodio'];
const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/;

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY' });
  next();
});
// Los adjuntos viajan en base64: esa ruta acepta cuerpos más grandes
const jsonNormal = express.json({ limit: '2mb' });
const jsonGrande = express.json({ limit: '15mb' });
const RUTAS_GRANDES = ['/api/archivos', '/api/ia/leer'];
app.use((req, res, next) => (req.method === 'POST' && RUTAS_GRANDES.includes(req.path) ? jsonGrande : jsonNormal)(req, res, next));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ---------- helpers ----------
// token_ver: al cambiar o restablecer la contraseña sube y se cierran las demás sesiones
const firmar = (u) => jwt.sign({ id: u.id, v: u.token_ver || 0 }, JWT_SECRET, { expiresIn: '180d' });
const usuarioPublico = (u) => ({
  id: u.id, nombre: u.nombre, email: u.email, perfil: u.perfil || {},
  admin: !!ADMIN_EMAIL && u.email === ADMIN_EMAIL,
  acepto: !!u.acepto_terminos,
  plan: u.plan || 'gratis',
});
const emailValido = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Sesión vencida' });
  let datos;
  try { datos = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Sesión vencida' }); }
  try {
    const r = await pool.query('SELECT token_ver, email, suspendido FROM usuarios WHERE id=$1', [datos.id]);
    if (!r.rowCount || (r.rows[0].token_ver || 0) !== (datos.v || 0)) return res.status(401).json({ error: 'Sesión vencida' });
    if (r.rows[0].suspendido) return res.status(403).json({ error: MSJ_SUSPENDIDA, suspendida: true });
    req.uid = datos.id; req.email = r.rows[0].email;
    pool.query('UPDATE usuarios SET ultimo_acceso = now() WHERE id=$1 AND (ultimo_acceso IS NULL OR ultimo_acceso < now() - interval \'1 hour\')', [datos.id]).catch(() => {});
    next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
}

const MSJ_SUSPENDIDA = 'Tu cuenta está suspendida. Escribe a soporte para más información.';
const esAdmin = (req) => !!ADMIN_EMAIL && req.email === ADMIN_EMAIL;
function soloAdmin(req, res, next) {
  if (!esAdmin(req)) return res.status(403).json({ error: 'Solo para el administrador' });
  next();
}

// Límite simple de intentos por IP (login, registro, recuperar)
const intentos = new Map();
function limite(max, minutos) {
  return (req, res, next) => {
    const k = req.path + '|' + req.ip;
    const ahora = Date.now();
    const lista = (intentos.get(k) || []).filter((t) => ahora - t < minutos * 60000);
    if (lista.length >= max) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos y vuelve a probar.' });
    lista.push(ahora); intentos.set(k, lista);
    next();
  };
}
setInterval(() => { const ahora = Date.now(); for (const [k, l] of intentos) if (!l.some((t) => ahora - t < 3600000)) intentos.delete(k); }, 600000).unref();

async function enviarMail(para, asunto, html) {
  if (!RESEND_API_KEY) return false;
  if (process.env.DEBUG_MAIL === 'true') console.log('MAIL a', para, html.match(/href="([^"]+)"/)?.[1]);
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: MAIL_FROM, to: [para], subject: asunto, html }),
    });
    if (!r.ok) console.error('Resend', r.status, await r.text());
    return r.ok;
  } catch (e) { console.error('Resend', e.message); return false; }
}

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  });

// ---------- configuración pública ----------
app.get('/api/config', (req, res) => res.json({
  registroConCodigo: !!REGISTRO_CODIGO,
  recuperar: !!RESEND_API_KEY,
  soporte: SOPORTE_EMAIL,
  ia: !!OPENAI_API_KEY,
  vozNatural: !!OPENAI_API_KEY,
  iaLimite: IA_LIMITE_MES,
}));

// ---------- auth ----------
app.post('/api/registro', limite(10, 60), wrap(async (req, res) => {
  const { nombre, email, password, codigo, acepta } = req.body || {};
  if (acepta !== true) return res.status(400).json({ error: 'Para crear la cuenta tienes que aceptar la política de privacidad y los términos' });
  if (REGISTRO_CODIGO && (codigo || '').trim() !== REGISTRO_CODIGO)
    return res.status(403).json({ error: 'Código de invitación incorrecto' });
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Completa todos los campos' });
  if (String(password).length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  const mail = String(email).trim().toLowerCase();
  if (!emailValido(mail)) return res.status(400).json({ error: 'El email no parece válido' });
  const existe = await pool.query('SELECT 1 FROM usuarios WHERE email=$1', [mail]);
  if (existe.rowCount) return res.status(409).json({ error: 'Ese email ya tiene cuenta' });
  const hash = await bcrypt.hash(String(password), 10);
  const r = await pool.query(
    'INSERT INTO usuarios (nombre, email, password_hash, acepto_terminos) VALUES ($1,$2,$3, now()) RETURNING *',
    [String(nombre).trim().slice(0, 60), mail, hash]);
  res.json({ token: firmar(r.rows[0]), usuario: usuarioPublico(r.rows[0]) });
}));

app.post('/api/login', limite(15, 15), wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const r = await pool.query('SELECT * FROM usuarios WHERE email=$1', [String(email || '').trim().toLowerCase()]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(password || ''), u.password_hash)))
    return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  if (u.suspendido) return res.status(403).json({ error: MSJ_SUSPENDIDA });
  res.json({ token: firmar(u), usuario: usuarioPublico(u) });
}));

app.get('/api/yo', auth, wrap(async (req, res) => {
  const r = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.uid]);
  if (!r.rowCount) return res.status(401).json({ error: 'Sesión vencida' });
  res.json(usuarioPublico(r.rows[0]));
}));

// Mezcla superficial: solo se pisan las claves que vienen
app.patch('/api/perfil', auth, wrap(async (req, res) => {
  const cambios = req.body && typeof req.body === 'object' ? { ...req.body } : {};
  const nombre = String(cambios.nombre_cuenta || '').trim().slice(0, 60);
  delete cambios.nombre_cuenta;
  const r = await pool.query(
    'UPDATE usuarios SET perfil = perfil || $2::jsonb, nombre = COALESCE(NULLIF($3, \'\'), nombre) WHERE id=$1 RETURNING *',
    [req.uid, JSON.stringify(cambios), nombre]);
  res.json(usuarioPublico(r.rows[0]));
}));

app.patch('/api/password', auth, wrap(async (req, res) => {
  const { actual, nueva } = req.body || {};
  const r = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.uid]);
  if (!(await bcrypt.compare(String(actual || ''), r.rows[0].password_hash)))
    return res.status(400).json({ error: 'La contraseña actual no coincide' });
  if (String(nueva || '').length < 6) return res.status(400).json({ error: 'Mínimo 6 caracteres' });
  const u = await pool.query('UPDATE usuarios SET password_hash=$2, token_ver = token_ver + 1 WHERE id=$1 RETURNING *',
    [req.uid, await bcrypt.hash(String(nueva), 10)]);
  res.json({ ok: true, token: firmar(u.rows[0]) });
}));

// Usuarios creados antes de que existieran los términos
app.post('/api/aceptar', auth, wrap(async (req, res) => {
  const r = await pool.query('UPDATE usuarios SET acepto_terminos = now() WHERE id=$1 RETURNING *', [req.uid]);
  res.json(usuarioPublico(r.rows[0]));
}));

// ---------- olvidé mi contraseña ----------
const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

app.post('/api/recuperar', limite(5, 30), wrap(async (req, res) => {
  const mail = String((req.body && req.body.email) || '').trim().toLowerCase();
  const respuesta = { ok: true, mensaje: 'Si ese email tiene cuenta, te enviamos un link para crear una contraseña nueva. Revisa también el spam.' };
  if (!RESEND_API_KEY) return res.status(503).json({ error: 'La recuperación por email no está configurada. Escribe a soporte.' });
  const r = await pool.query('SELECT id, nombre, email FROM usuarios WHERE email=$1', [mail]);
  if (!r.rowCount) return res.json(respuesta);
  await enviarReset(r.rows[0], req, 1);
  res.json(respuesta);
}));

async function enviarReset(u, req, horas) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('DELETE FROM reseteos WHERE usuario_id=$1', [u.id]);
  await pool.query(`INSERT INTO reseteos (usuario_id, token_hash, expira) VALUES ($1,$2, now() + interval '${Number(horas)} hours')`, [u.id, hashToken(token)]);
  const base = (process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
  const link = `${base}/#reset=${token}`;
  return enviarMail(u.email, "Crea tu nueva contraseña · Vamos Pa' Arriba", `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#1e2a27">
      <h2 style="color:#1f6f5c">Hola, ${String(u.nombre).replace(/[<>&]/g, '')} 🌱</h2>
      <p>Recibimos un pedido para cambiar la contraseña de tu cuenta de Vamos Pa' Arriba.</p>
      <p><a href="${link}" style="display:inline-block;background:#1f6f5c;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:bold">Crear contraseña nueva</a></p>
      <p style="color:#6b7774;font-size:13px">El link vence en ${horas === 1 ? '1 hora' : horas + ' horas'}. Si no lo pediste, ignora este mensaje: tu contraseña sigue igual.</p>
    </div>`);
}

app.post('/api/restablecer', limite(10, 30), wrap(async (req, res) => {
  const { token, password } = req.body || {};
  if (String(password || '').length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  const r = await pool.query('SELECT usuario_id FROM reseteos WHERE token_hash=$1 AND expira > now()', [hashToken(String(token || ''))]);
  if (!r.rowCount) return res.status(400).json({ error: 'El link venció o ya se usó. Pide uno nuevo.' });
  const u = await pool.query('UPDATE usuarios SET password_hash=$2, token_ver = token_ver + 1 WHERE id=$1 RETURNING *',
    [r.rows[0].usuario_id, await bcrypt.hash(String(password), 10)]);
  await pool.query('DELETE FROM reseteos WHERE usuario_id=$1', [r.rows[0].usuario_id]);
  res.json({ token: firmar(u.rows[0]), usuario: usuarioPublico(u.rows[0]) });
}));

// ---------- mis datos: descargar y borrar cuenta ----------
app.get('/api/exportar', auth, wrap(async (req, res) => {
  const [u, d, r, a] = await Promise.all([
    pool.query('SELECT nombre, email, perfil, creado, acepto_terminos FROM usuarios WHERE id=$1', [req.uid]),
    pool.query('SELECT fecha, datos FROM dias WHERE usuario_id=$1 ORDER BY fecha', [req.uid]),
    pool.query('SELECT id, tipo, fecha, datos FROM registros WHERE usuario_id=$1 ORDER BY tipo, fecha', [req.uid]),
    pool.query("SELECT registro_id, ambito, nombre, tipo, encode(datos, 'base64') AS base64 FROM archivos WHERE usuario_id=$1 ORDER BY id", [req.uid]),
  ]);
  res.set('Content-Disposition', 'attachment; filename="mis-datos-vamos-pa-arriba.json"');
  res.json({ exportado: new Date().toISOString(), cuenta: u.rows[0], dias: d.rows, registros: r.rows, archivos: a.rows });
}));

app.delete('/api/cuenta', auth, wrap(async (req, res) => {
  const r = await pool.query('SELECT password_hash, familia_id FROM usuarios WHERE id=$1', [req.uid]);
  if (!(await bcrypt.compare(String((req.body && req.body.password) || ''), r.rows[0].password_hash)))
    return res.status(400).json({ error: 'La contraseña no coincide' });
  await pool.query('DELETE FROM usuarios WHERE id=$1', [req.uid]); // borra días y registros en cascada
  const fid = r.rows[0].familia_id;
  if (fid) await pool.query('DELETE FROM familias f WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM usuarios WHERE familia_id=f.id)', [fid]);
  res.json({ ok: true });
}));

// ---------- panel del dueño ----------
app.get('/api/admin/estadisticas', auth, soloAdmin, wrap(async (req, res) => {
  const q = async (sql) => Number((await pool.query(sql)).rows[0].n);
  res.json({
    usuarios: await q('SELECT count(*) n FROM usuarios'),
    nuevos7: await q("SELECT count(*) n FROM usuarios WHERE creado > now() - interval '7 days'"),
    nuevos30: await q("SELECT count(*) n FROM usuarios WHERE creado > now() - interval '30 days'"),
    activos7: await q("SELECT count(*) n FROM usuarios WHERE ultimo_acceso > now() - interval '7 days'"),
    activos30: await q("SELECT count(*) n FROM usuarios WHERE ultimo_acceso > now() - interval '30 days'"),
    familias: await q('SELECT count(*) n FROM familias'),
    registros30: await q("SELECT count(*) n FROM registros WHERE creado > now() - interval '30 days'"),
    ia30: await q("SELECT count(*) n FROM ia_usos WHERE creado > now() - interval '30 days'"),
    suspendidos: await q('SELECT count(*) n FROM usuarios WHERE suspendido'),
    pro: await q("SELECT count(*) n FROM usuarios WHERE plan <> 'gratis'"),
  });
}));

// ---------- familia ----------
const nuevoCodigo = () => Array.from({ length: 6 }, () => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[Math.floor(Math.random() * 32)]).join('');

async function datosFamilia(uid) {
  const u = await pool.query('SELECT familia_id FROM usuarios WHERE id=$1', [uid]);
  const fid = u.rows[0] && u.rows[0].familia_id;
  if (!fid) return { familia: null, miembros: [] };
  const f = await pool.query('SELECT id, nombre, codigo, datos FROM familias WHERE id=$1', [fid]);
  const m = await pool.query(
    `SELECT id, nombre, perfil->'excluye' AS excluye, perfil->>'excluyeTxt' AS "excluyeTxt",
            CASE WHEN perfil->>'compartirFocos' = 'true' THEN perfil->'focos' END AS focos
     FROM usuarios WHERE familia_id=$1 ORDER BY id`, [fid]);
  return { familia: f.rows[0] || null, miembros: m.rows.map((r) => ({ ...r, excluye: r.excluye || [] })) };
}

app.get('/api/familia', auth, wrap(async (req, res) => res.json(await datosFamilia(req.uid))));

app.post('/api/familia', auth, wrap(async (req, res) => {
  const nombre = String((req.body && req.body.nombre) || 'Mi familia').trim().slice(0, 60);
  const yo = await pool.query('SELECT perfil FROM usuarios WHERE id=$1', [req.uid]);
  const p = yo.rows[0].perfil || {};
  // El plan que ya tenía pasa a ser el de la familia
  const datos = { personas: 3, ...(p.plan ? { plan: p.plan, comprado: p.comprado || [] } : {}) };
  let f;
  for (let i = 0; i < 5 && !f; i++) {
    try {
      f = (await pool.query('INSERT INTO familias (nombre, codigo, datos) VALUES ($1,$2,$3::jsonb) RETURNING id',
        [nombre, nuevoCodigo(), JSON.stringify(datos)])).rows[0];
    } catch (e) { if (e.code !== '23505') throw e; }
  }
  await pool.query('UPDATE usuarios SET familia_id=$2 WHERE id=$1', [req.uid, f.id]);
  res.json(await datosFamilia(req.uid));
}));

app.post('/api/familia/unirse', auth, wrap(async (req, res) => {
  const codigo = String((req.body && req.body.codigo) || '').trim().toUpperCase();
  const f = await pool.query('SELECT id FROM familias WHERE codigo=$1', [codigo]);
  if (!f.rowCount) return res.status(404).json({ error: 'No existe una familia con ese código' });
  await pool.query('UPDATE usuarios SET familia_id=$2 WHERE id=$1', [req.uid, f.rows[0].id]);
  res.json(await datosFamilia(req.uid));
}));

app.post('/api/familia/salir', auth, wrap(async (req, res) => {
  await pool.query('UPDATE usuarios SET familia_id=NULL WHERE id=$1', [req.uid]);
  res.json({ familia: null, miembros: [] });
}));

// Mezcla superficial sobre los datos de la familia (plan, comprado, personas, excluyeExtra, noReceta)
app.patch('/api/familia', auth, wrap(async (req, res) => {
  const cambios = req.body && typeof req.body === 'object' ? req.body : {};
  const r = await pool.query(
    `UPDATE familias SET datos = datos || $2::jsonb
     WHERE id = (SELECT familia_id FROM usuarios WHERE id=$1) RETURNING id`,
    [req.uid, JSON.stringify(cambios)]);
  if (!r.rowCount) return res.status(400).json({ error: 'No perteneces a una familia' });
  res.json(await datosFamilia(req.uid));
}));

// ---------- días (checklist diario) ----------
app.get('/api/dias', auth, wrap(async (req, res) => {
  const { desde, hasta } = req.query;
  if (!FECHA_RE.test(desde || '') || !FECHA_RE.test(hasta || ''))
    return res.status(400).json({ error: 'Fechas inválidas' });
  const r = await pool.query(
    'SELECT fecha, datos FROM dias WHERE usuario_id=$1 AND fecha BETWEEN $2 AND $3 ORDER BY fecha',
    [req.uid, desde, hasta]);
  res.json(r.rows);
}));

app.put('/api/dias/:fecha', auth, wrap(async (req, res) => {
  const { fecha } = req.params;
  if (!FECHA_RE.test(fecha)) return res.status(400).json({ error: 'Fecha inválida' });
  const r = await pool.query(
    `INSERT INTO dias (usuario_id, fecha, datos) VALUES ($1,$2,$3::jsonb)
     ON CONFLICT (usuario_id, fecha) DO UPDATE SET datos = dias.datos || EXCLUDED.datos, actualizado = now()
     RETURNING fecha, datos`,
    [req.uid, fecha, JSON.stringify(req.body || {})]);
  res.json(r.rows[0]);
}));

// ---------- registros ----------
app.get('/api/registros', auth, wrap(async (req, res) => {
  const { tipo } = req.query;
  if (!TIPOS.includes(tipo)) return res.status(400).json({ error: 'Tipo inválido' });
  const limite = Math.min(parseInt(req.query.limite, 10) || 200, 1000);
  const r = await pool.query(
    `SELECT r.id, r.tipo, r.fecha, r.datos, (SELECT count(*)::int FROM archivos a WHERE a.registro_id = r.id) AS adjuntos
     FROM registros r WHERE r.usuario_id=$1 AND r.tipo=$2 ORDER BY r.fecha DESC, r.id DESC LIMIT $3`,
    [req.uid, tipo, limite]);
  res.json(r.rows);
}));

app.post('/api/registros', auth, wrap(async (req, res) => {
  const { tipo, fecha, datos } = req.body || {};
  if (!TIPOS.includes(tipo)) return res.status(400).json({ error: 'Tipo inválido' });
  if (fecha && !FECHA_RE.test(fecha)) return res.status(400).json({ error: 'Fecha inválida' });
  const r = await pool.query(
    'INSERT INTO registros (usuario_id, tipo, fecha, datos) VALUES ($1,$2,COALESCE($3::date, CURRENT_DATE),$4::jsonb) RETURNING id, tipo, fecha, datos',
    [req.uid, tipo, fecha || null, JSON.stringify(datos || {})]);
  res.json(r.rows[0]);
}));

app.put('/api/registros/:id', auth, wrap(async (req, res) => {
  const { fecha, datos } = req.body || {};
  if (fecha && !FECHA_RE.test(fecha)) return res.status(400).json({ error: 'Fecha inválida' });
  const r = await pool.query(
    `UPDATE registros SET fecha = COALESCE($3::date, fecha), datos = $4::jsonb, actualizado = now()
     WHERE id=$1 AND usuario_id=$2 RETURNING id, tipo, fecha, datos`,
    [req.params.id, req.uid, fecha || null, JSON.stringify(datos || {})]);
  if (!r.rowCount) return res.status(404).json({ error: 'No encontrado' });
  res.json(r.rows[0]);
}));

app.delete('/api/registros/:id', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM registros WHERE id=$1 AND usuario_id=$2', [req.params.id, req.uid]);
  res.json({ ok: true });
}));

// ---------- administración de cuentas ----------
// El administrador ve solo datos de la cuenta (nunca datos de salud, notas ni archivos)
const SQL_USUARIOS_ADMIN = `
  SELECT u.id, u.nombre, u.email, u.creado, u.ultimo_acceso, u.suspendido, u.plan, u.plan_vence, u.ia_limite, u.nota_admin,
         u.acepto_terminos IS NOT NULL AS acepto, f.nombre AS familia,
         (SELECT count(*)::int FROM ia_usos i WHERE i.usuario_id = u.id AND i.ok AND i.creado > date_trunc('month', now())) AS ia_mes
  FROM usuarios u LEFT JOIN familias f ON f.id = u.familia_id`;

app.get('/api/admin/usuarios', auth, soloAdmin, wrap(async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const r = await pool.query(`${SQL_USUARIOS_ADMIN}
    WHERE ($1 = '' OR lower(u.nombre) LIKE '%' || $1 || '%' OR lower(u.email) LIKE '%' || $1 || '%')
    ORDER BY u.creado DESC LIMIT 500`, [q]);
  res.json(r.rows.map((u) => ({ ...u, admin: u.email === ADMIN_EMAIL, ia_limite_efectivo: u.ia_limite ?? IA_LIMITE_MES })));
}));

app.get('/api/admin/usuarios.csv', auth, soloAdmin, wrap(async (req, res) => {
  const r = await pool.query(`${SQL_USUARIOS_ADMIN} ORDER BY u.creado`);
  const c = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const f = (d) => (d ? new Date(d).toISOString().slice(0, 10) : '');
  const filas = [['Nombre', 'Email', 'Alta', 'Último acceso', 'Plan', 'Vence', 'Estado', 'Familia', 'Lecturas IA este mes'].map(c).join(',')]
    .concat(r.rows.map((u) => [u.nombre, u.email, f(u.creado), f(u.ultimo_acceso), u.plan, f(u.plan_vence), u.suspendido ? 'Suspendida' : 'Activa', u.familia, u.ia_mes].map(c).join(',')));
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="usuarios-vamos-pa-arriba.csv"' });
  res.send('\uFEFF' + filas.join('\n'));
}));

async function usuarioObjetivo(req, res) {
  const r = await pool.query('SELECT id, nombre, email, familia_id FROM usuarios WHERE id=$1', [req.params.id]);
  if (!r.rowCount) { res.status(404).json({ error: 'Usuario no encontrado' }); return null; }
  if (r.rows[0].email === ADMIN_EMAIL && req.method !== 'PATCH') { res.status(400).json({ error: 'No puedes hacer eso con tu propia cuenta de administrador' }); return null; }
  return r.rows[0];
}

app.patch('/api/admin/usuarios/:id', auth, soloAdmin, wrap(async (req, res) => {
  const u = await usuarioObjetivo(req, res); if (!u) return;
  const b = req.body || {};
  if ('suspendido' in b && u.email === ADMIN_EMAIL) return res.status(400).json({ error: 'No puedes suspender tu propia cuenta' });
  const sets = [], vals = [u.id];
  const poner = (col, v) => { vals.push(v); sets.push(`${col} = $${vals.length}`); };
  if ('suspendido' in b) { poner('suspendido', !!b.suspendido); if (b.suspendido) sets.push('token_ver = token_ver + 1'); }
  if ('plan' in b) { if (!['gratis', 'pro', 'cortesia'].includes(b.plan)) return res.status(400).json({ error: 'Plan inválido' }); poner('plan', b.plan); }
  if ('plan_vence' in b) { if (b.plan_vence && !FECHA_RE.test(b.plan_vence)) return res.status(400).json({ error: 'Fecha inválida' }); poner('plan_vence', b.plan_vence || null); }
  if ('ia_limite' in b) { const n = b.ia_limite === null || b.ia_limite === '' ? null : parseInt(b.ia_limite, 10); if (n !== null && (isNaN(n) || n < 0 || n > 1000)) return res.status(400).json({ error: 'Límite inválido' }); poner('ia_limite', n); }
  if ('nota_admin' in b) poner('nota_admin', String(b.nota_admin || '').slice(0, 1000));
  if (!sets.length) return res.status(400).json({ error: 'Nada para cambiar' });
  await pool.query(`UPDATE usuarios SET ${sets.join(', ')} WHERE id = $1`, vals);
  const r = await pool.query(`${SQL_USUARIOS_ADMIN} WHERE u.id = $1`, [u.id]);
  res.json({ ...r.rows[0], admin: r.rows[0].email === ADMIN_EMAIL, ia_limite_efectivo: r.rows[0].ia_limite ?? IA_LIMITE_MES });
}));

// Contraseña temporal: se muestra una sola vez al administrador para que se la pase al usuario
app.post('/api/admin/usuarios/:id/clave-temporal', auth, soloAdmin, wrap(async (req, res) => {
  const u = await usuarioObjetivo(req, res); if (!u) return;
  const clave = Array.from(crypto.randomBytes(10), (x) => 'abcdefghjkmnpqrstuvwxyz23456789'[x % 31]).join('');
  await pool.query('UPDATE usuarios SET password_hash=$2, token_ver = token_ver + 1 WHERE id=$1', [u.id, await bcrypt.hash(clave, 10)]);
  res.json({ clave });
}));

app.post('/api/admin/usuarios/:id/enviar-reset', auth, soloAdmin, wrap(async (req, res) => {
  const u = await usuarioObjetivo(req, res); if (!u) return;
  if (!RESEND_API_KEY) return res.status(503).json({ error: 'El envío de emails no está configurado (falta RESEND_API_KEY). Usa la contraseña temporal.' });
  const ok = await enviarReset(u, req, 24);
  if (!ok) return res.status(502).json({ error: 'No se pudo enviar el email. Revisa la configuración de Resend.' });
  res.json({ ok: true });
}));

app.post('/api/admin/usuarios/:id/cerrar-sesiones', auth, soloAdmin, wrap(async (req, res) => {
  const u = await usuarioObjetivo(req, res); if (!u) return;
  await pool.query('UPDATE usuarios SET token_ver = token_ver + 1 WHERE id=$1', [u.id]);
  res.json({ ok: true });
}));

app.delete('/api/admin/usuarios/:id', auth, soloAdmin, wrap(async (req, res) => {
  const u = await usuarioObjetivo(req, res); if (!u) return;
  if (String((req.body && req.body.confirmar) || '').trim().toLowerCase() !== u.email) return res.status(400).json({ error: 'Para confirmar, escribe el email exacto de la cuenta' });
  await pool.query('DELETE FROM usuarios WHERE id=$1', [u.id]);
  if (u.familia_id) await pool.query('DELETE FROM familias f WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM usuarios WHERE familia_id=f.id)', [u.familia_id]);
  res.json({ ok: true });
}));

// ---------- archivos adjuntos ----------
const TIPOS_ARCHIVO = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];
const MAX_ARCHIVO = 10 * 1024 * 1024;
const AMBITOS = ['nutricion'];

app.get('/api/archivos', auth, wrap(async (req, res) => {
  const { registro_id, ambito } = req.query;
  let r;
  if (registro_id) r = await pool.query('SELECT id, nombre, tipo, tamano, creado FROM archivos WHERE usuario_id=$1 AND registro_id=$2 ORDER BY id', [req.uid, registro_id]);
  else if (AMBITOS.includes(ambito)) r = await pool.query('SELECT id, nombre, tipo, tamano, creado FROM archivos WHERE usuario_id=$1 AND ambito=$2 ORDER BY id DESC', [req.uid, ambito]);
  else return res.status(400).json({ error: 'Falta registro o ámbito' });
  res.json(r.rows);
}));

app.post('/api/archivos', auth, wrap(async (req, res) => {
  const { nombre, tipo, base64, registro_id, ambito } = req.body || {};
  if (!TIPOS_ARCHIVO.includes(tipo)) return res.status(400).json({ error: 'Solo se aceptan PDF o fotos (JPG, PNG)' });
  const buf = Buffer.from(String(base64 || ''), 'base64');
  if (!buf.length) return res.status(400).json({ error: 'El archivo está vacío' });
  if (buf.length > MAX_ARCHIVO) return res.status(400).json({ error: 'El archivo supera los 10 MB' });
  if (registro_id) {
    const ok = await pool.query('SELECT 1 FROM registros WHERE id=$1 AND usuario_id=$2', [registro_id, req.uid]);
    if (!ok.rowCount) return res.status(404).json({ error: 'Registro no encontrado' });
  } else if (!AMBITOS.includes(ambito)) return res.status(400).json({ error: 'Falta registro o ámbito' });
  const total = await pool.query('SELECT COALESCE(sum(tamano),0)::bigint AS t FROM archivos WHERE usuario_id=$1', [req.uid]);
  if (Number(total.rows[0].t) + buf.length > 300 * 1024 * 1024) return res.status(400).json({ error: 'Llegaste al límite de 300 MB de archivos' });
  const r = await pool.query(
    'INSERT INTO archivos (usuario_id, registro_id, ambito, nombre, tipo, tamano, datos) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, nombre, tipo, tamano, creado',
    [req.uid, registro_id || null, registro_id ? null : ambito, String(nombre || 'archivo').slice(0, 120), tipo, buf.length, buf]);
  res.json(r.rows[0]);
}));

app.get('/api/archivos/:id', auth, wrap(async (req, res) => {
  const r = await pool.query('SELECT nombre, tipo, datos FROM archivos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.uid]);
  if (!r.rowCount) return res.status(404).json({ error: 'No encontrado' });
  res.set({ 'Content-Type': r.rows[0].tipo, 'Content-Disposition': `inline; filename="${encodeURIComponent(r.rows[0].nombre)}"`, 'Cache-Control': 'private, no-store' });
  res.send(r.rows[0].datos);
}));

app.delete('/api/archivos/:id', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM archivos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.uid]);
  res.json({ ok: true });
}));

// ---------- leer un estudio con IA (OpenAI) ----------
// Solo extrae números de un InBody o un análisis de sangre. El usuario revisa todo antes de guardar.
const CAMPOS_IA = {
  gr: 'Hematíes en millones por mm³ (ej.: 5.780.000 por mm³ = 5.78)',
  hto: 'Hematocrito (%)',
  hb: 'Hemoglobina (g/dL; gr/100 ml es lo mismo)',
  vcm: 'Volumen corpuscular medio (fL)',
  hcm: 'Hemoglobina corpuscular media (pg)',
  chcm: 'Concentración de hemoglobina corpuscular media (g/dL)',
  ade: 'Anisocitosis, ADE o RDW (%)',
  gb: 'Glóbulos blancos o leucocitos por mm³ (ej.: 6.600 = 6600)',
  neu: 'Neutrófilos segmentados, porcentaje',
  linf: 'Linfocitos, porcentaje',
  mono: 'Monocitos, porcentaje',
  eos: 'Eosinófilos, porcentaje',
  baso: 'Basófilos, porcentaje',
  plaq: 'Plaquetas por mm³ (ej.: 250.000 = 250000)',
  vsg: 'Eritrosedimentación o VSG, primera hora (mm)',
  glu: 'Glucemia o glucosa en ayunas en mg/dL (1,01 g/l = 101)',
  hba1c: 'Hemoglobina glicosilada HbA1c (%)',
  urea: 'Urea o uremia en mg/dL (0,28 g/l = 28)',
  crea: 'Creatinina sérica (mg/dL; mg/100 ml es lo mismo)',
  au: 'Ácido úrico o uricemia en mg/dL',
  na: 'Sodio (mEq/L)',
  k: 'Potasio (mEq/L)',
  cl: 'Cloro (mEq/L)',
  ct: 'Colesterol total (mg/dL)',
  hdl: 'Colesterol HDL (mg/dL)',
  ldl: 'Colesterol LDL (mg/dL)',
  tg: 'Triglicéridos (mg/dL)',
  ct_hdl: 'Relación o índice colesterol total / HDL',
  bt: 'Bilirrubina total (mg/dL)',
  bd: 'Bilirrubina directa (mg/dL)',
  bi: 'Bilirrubina indirecta (mg/dL)',
  got: 'Transaminasa glutámico oxalacética, GOT o AST (U/L; mU/ml es lo mismo)',
  gpt: 'Transaminasa glutámico pirúvica, GPT o ALT (U/L; mU/ml es lo mismo)',
  fal: 'Fosfatasa alcalina (U/L; mU/ml es lo mismo)',
  ggt: 'Gamma glutamil transpeptidasa GGT (U/L)',
  tsh: 'TSH o tirotrofina (µUI/mL; uU/ml es lo mismo)',
  t4: 'T4 total o tiroxina total (µg/dL; ug/100 ml es lo mismo)',
  t4l: 'T4 libre (ng/dL)',
  pcr: 'Proteína C reactiva (mg/dL; mg % es lo mismo)',
  vitd: 'Vitamina D 25-hidroxi (ng/mL)',
  ferritina: 'Ferritina (ng/mL)',
  psa: 'Antígeno prostático específico PSA total (ng/mL)',
  ib_peso: 'InBody: peso (kg)', ib_musculo: 'InBody: masa muscular esquelética (kg)', ib_grasa_kg: 'InBody: masa grasa corporal (kg)', ib_grasa_pct: 'InBody: porcentaje de grasa corporal (%)',
  ib_visceral: 'InBody: nivel de grasa visceral', ib_agua: 'InBody: agua corporal total (L)', ib_imc: 'InBody: IMC', ib_metab: 'InBody: metabolismo basal (kcal)', ib_puntaje: 'InBody: puntaje InBody',
};
const TIPOS_ESTUDIO = ['Análisis de sangre', 'Análisis de orina', 'Composición corporal (InBody)', 'Ecografía', 'Ecocardiograma', 'Electrocardiograma', 'Ergometría / prueba de esfuerzo', 'Holter / MAPA (presión 24 h)', 'Imagen (RX, TAC, RMN)', 'Endoscopía / colonoscopía', 'Densitometría ósea', 'Espirometría', 'Estudio del sueño', 'Biopsia / anatomía patológica', 'Control oftalmológico', 'Otro'];
const ESQUEMA_IA = {
  type: 'object', additionalProperties: false,
  required: ['tipo', 'estudio', 'titulo', 'resumen', 'fecha', 'lugar', 'valores', 'referencias', 'otros_valores', 'orina', 'notas'],
  properties: {
    tipo: { type: 'string', enum: ['inbody', 'analisis', 'otro'] },
    estudio: { type: 'string', enum: TIPOS_ESTUDIO, description: 'Categoría del estudio' },
    titulo: { type: ['string', 'null'], description: 'Nombre del estudio tal como figura en el informe, corto (ej.: "Ecografía testicular y prostática-vesical"), o null' },
    resumen: { type: ['string', 'null'], description: 'Solo para estudios que NO son análisis de sangre ni InBody: los hallazgos y conclusiones del informe transcriptos fielmente, una línea por hallazgo empezando con "• ", con sus medidas. Para análisis o InBody: null' },
    fecha: { type: ['string', 'null'], description: 'Fecha del estudio en formato YYYY-MM-DD, o null' },
    lugar: { type: ['string', 'null'], description: 'Laboratorio o centro, o null' },
    valores: {
      type: 'object', additionalProperties: false, required: Object.keys(CAMPOS_IA),
      properties: Object.fromEntries(Object.entries(CAMPOS_IA).map(([k, d]) => [k, { type: ['number', 'null'], description: d }])),
    },
    referencias: {
      type: 'array', description: 'Valor de referencia que imprime el laboratorio para cada valor encontrado',
      items: { type: 'object', additionalProperties: false, required: ['clave', 'texto'],
        properties: { clave: { type: 'string', enum: Object.keys(CAMPOS_IA) }, texto: { type: 'string', description: 'Ej.: "hasta 200", "70 a 110", "0,80 a 1,40"' } } },
    },
    otros_valores: {
      type: 'array', description: 'Todos los demás valores medidos del informe que NO tienen un campo en "valores" (por ejemplo hormonas, vitaminas, marcadores, valores de orina, medidas de una ecografía, presión arterial de un MAPA)',
      items: { type: 'object', additionalProperties: false, required: ['nombre', 'valor', 'unidad', 'referencia'],
        properties: {
          nombre: { type: 'string' },
          valor: { type: 'string', description: 'Tal como figura, con coma o punto decimal (ej.: "4,2", "negativo", "1.020")' },
          unidad: { type: ['string', 'null'] },
          referencia: { type: ['string', 'null'], description: 'Valor de referencia del laboratorio, si figura' },
        } },
    },
    orina: { type: ['string', 'null'], description: 'Si hay examen de orina, resumen corto de lo que dice (ej.: "Densidad 1.010, pH 6, sin proteínas ni glucosa, sedimento sin particularidades"), o null' },
    notas: { type: ['string', 'null'], description: 'Otros valores numéricos del informe que no están en la lista, en una línea corta, o null' },
  },
};
const PROMPT_IA = `Eres un asistente que transcribe datos de informes de salud. Lee el documento adjunto (un análisis de sangre, un informe InBody u otro estudio) y devuelve SOLO los valores que aparecen escritos en él.
Reglas:
- No inventes ni estimes nada. Si un valor no aparece o no se lee con claridad, devuelve null.
- En los informes argentinos el punto separa miles y la coma decimales: "5.780.000" = 5780000, "1,32" = 1.32. Devuelve los números con punto decimal.
- Convierte a la unidad indicada en cada campo cuando la conversión es directa:
  · g/l o g/L → mg/dL multiplicando por 100 (glucemia 1,01 g/l = 101; uremia 0,28 g/l = 28).
  · mg/100 ml, mg/dl y mg % son lo mismo que mg/dL. gr/100 ml = g/dL. ug/100 ml = µg/dL.
  · mU/ml, UI/L y U/L son lo mismo. uU/ml = µUI/mL. meq/l = mEq/L.
  · Hematíes por mm³ → millones/mm³ (5.780.000 → 5.78).
  · En la fórmula leucocitaria usa los porcentajes, no los valores absolutos.
- Si la unidad es otra y no hay conversión directa (por ejemplo mmol/L), devuelve null.
- "Glucemia" es la glucosa en ayunas. "Uremia" es la urea. "Segmentados" son los neutrófilos.
- En referencias, copia el valor de referencia que el laboratorio imprime al lado de cada valor que encontraste (adultos), tal como está.
- tipo: "inbody" si es un informe de composición corporal (InBody u otro bioimpedanciómetro), "analisis" si es un análisis de sangre, "otro" en cualquier otro caso.
- Si el estudio no encaja en ninguna categoría, usa "Otro" y pon su nombre real en "titulo". Nunca lo clasifiques como análisis de sangre si no lo es.
- En "otros_valores" incluye cada valor medido que no tenga campo propio en "valores", con su unidad y referencia. No repitas los que ya pusiste en "valores".
- estudio: la categoría que mejor corresponda (una ecografía de cualquier zona es "Ecografía"; un ecocardiograma o eco doppler cardíaco es "Ecocardiograma"; radiografías, tomografías y resonancias son "Imagen (RX, TAC, RMN)").
- Si es otro estudio (ecografía, ecocardiograma, electrocardiograma, imagen, estudio del sueño, etc.), en "resumen" copia los hallazgos y la conclusión tal como los escribió el profesional, una línea por hallazgo, con sus medidas. No agregues opiniones, explicaciones ni diagnósticos propios. No incluyas nombres, documentos ni datos personales del paciente.
- No interpretes ni des recomendaciones médicas: solo transcribe.`;

app.post('/api/ia/leer', auth, wrap(async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(503).json({ error: 'La lectura con IA no está activada' });
  const u = await pool.query("SELECT perfil->>'consentIA' AS c, ia_limite FROM usuarios WHERE id=$1", [req.uid]);
  if (u.rows[0].c !== 'true') return res.status(403).json({ error: 'Primero tienes que aceptar el uso de la IA' });
  const limiteIA = u.rows[0].ia_limite ?? IA_LIMITE_MES;
  const usos = await pool.query("SELECT count(*)::int n FROM ia_usos WHERE usuario_id=$1 AND ok AND creado > date_trunc('month', now())", [req.uid]);
  if (usos.rows[0].n >= limiteIA) return res.status(429).json({ error: limiteIA ? `Llegaste al límite de ${limiteIA} lecturas con IA de este mes` : 'La lectura con IA no está habilitada en tu cuenta' });

  // El archivo puede venir de un adjunto ya guardado o directo (registro nuevo todavía sin guardar)
  let tipo, nombre, base64;
  const { archivo_id } = req.body || {};
  if (archivo_id) {
    const a = await pool.query('SELECT nombre, tipo, datos FROM archivos WHERE id=$1 AND usuario_id=$2', [archivo_id, req.uid]);
    if (!a.rowCount) return res.status(404).json({ error: 'Archivo no encontrado' });
    ({ nombre, tipo } = a.rows[0]); base64 = a.rows[0].datos.toString('base64');
  } else {
    ({ nombre, tipo, base64 } = req.body || {});
    if (!TIPOS_ARCHIVO.includes(tipo) || !base64) return res.status(400).json({ error: 'Archivo inválido' });
    if (Buffer.byteLength(base64, 'base64') > MAX_ARCHIVO) return res.status(400).json({ error: 'El archivo supera los 10 MB' });
  }
  const dataUrl = `data:${tipo};base64,${base64}`;
  const parteArchivo = tipo === 'application/pdf'
    ? { type: 'input_file', filename: nombre || 'estudio.pdf', file_data: dataUrl }
    : { type: 'input_image', image_url: dataUrl };

  let r, cuerpo;
  try {
    r = await fetch(OPENAI_URL + '/responses', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + OPENAI_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: OPENAI_MODEL,
        input: [{ role: 'user', content: [parteArchivo, { type: 'input_text', text: PROMPT_IA }] }],
        text: { format: { type: 'json_schema', name: 'estudio', strict: true, schema: ESQUEMA_IA } },
        store: false,
      }),
    });
    cuerpo = await r.json();
  } catch (e) {
    console.error('OpenAI', e.message);
    return res.status(502).json({ error: 'No se pudo conectar con la IA. Prueba de nuevo en un rato.' });
  }
  if (!r.ok) {
    console.error('OpenAI', r.status, JSON.stringify(cuerpo).slice(0, 500));
    await pool.query('INSERT INTO ia_usos (usuario_id, ok) VALUES ($1, false)', [req.uid]);
    return res.status(502).json({ error: r.status === 429 ? 'La IA está ocupada o sin crédito. Avisa a soporte.' : 'La IA no pudo leer el archivo.' });
  }
  const texto = (cuerpo.output || []).flatMap((o) => o.content || []).find((c) => c.type === 'output_text');
  let datos;
  try { datos = JSON.parse(texto.text); } catch { return res.status(502).json({ error: 'La IA no devolvió datos legibles. Prueba con otra foto o el PDF.' }); }
  await pool.query('INSERT INTO ia_usos (usuario_id) VALUES ($1)', [req.uid]);
  // Limpieza: solo números válidos y fecha con formato correcto
  const valores = {};
  for (const k of Object.keys(CAMPOS_IA)) {
    const v = datos.valores && datos.valores[k];
    if (typeof v === 'number' && isFinite(v)) valores[k] = v;
  }
  const refs = {};
  (datos.referencias || []).forEach((x) => { if (x && CAMPOS_IA[x.clave] && x.texto) refs[x.clave] = String(x.texto).slice(0, 60); });
  res.json({
    tipo: datos.tipo, valores, refs,
    estudio: TIPOS_ESTUDIO.includes(datos.estudio) ? datos.estudio : null,
    titulo: datos.titulo ? String(datos.titulo).slice(0, 100) : null,
    otros: (Array.isArray(datos.otros_valores) ? datos.otros_valores : []).slice(0, 80)
      .filter((x) => x && x.nombre && x.valor !== undefined && x.valor !== null && String(x.valor).trim() !== '')
      .map((x) => ({ n: String(x.nombre).slice(0, 80), v: String(x.valor).slice(0, 40), u: x.unidad ? String(x.unidad).slice(0, 20) : '', ref: x.referencia ? String(x.referencia).slice(0, 60) : '' })),
    resumen: datos.resumen ? String(datos.resumen).slice(0, 2000) : null,
    orina: datos.orina ? String(datos.orina).slice(0, 400) : null,
    fecha: FECHA_RE.test(datos.fecha || '') ? datos.fecha : null,
    lugar: datos.lugar ? String(datos.lugar).slice(0, 80) : null,
    notas: datos.notas ? String(datos.notas).slice(0, 400) : null,
    restantes: limiteIA - usos.rows[0].n - 1,
  });
}));

const ING_NOMBRES = {
  avena: 'Avena',
  leche: 'Leche descremada',
  yogur: 'Yogur natural sin azúcar',
  queso: 'Queso fresco / blanco',
  huevo: 'Huevos',
  pan_integral: 'Pan integral',
  harina_maiz: 'Harina de maíz precocida (arepa)',
  harina_integral: 'Harina integral',
  pan_rallado: 'Pan rallado',
  galletas_arroz: 'Galletas de arroz',
  arroz_integral: 'Arroz integral',
  fideos_integrales: 'Fideos integrales',
  lentejas: 'Lentejas',
  garbanzos: 'Garbanzos',
  porotos: 'Porotos / caraotas negras',
  atun: 'Atún al natural (lata)',
  sardinas: 'Sardinas (lata)',
  mani: 'Maní sin sal',
  semillas: 'Semillas (lino, chía o girasol)',
  aceite: 'Aceite de oliva o canola',
  pollo: 'Pollo (pechuga o pata-muslo sin piel)',
  carne: 'Carne magra (nalga, peceto, cuadril)',
  cerdo: 'Cerdo magro (solomillo, carré)',
  pescado: 'Pescado (merluza u otro)',
  banana: 'Banana',
  manzana: 'Manzana',
  fruta: 'Fruta de estación',
  papa: 'Papa',
  batata: 'Batata',
  zapallo: 'Zapallo / calabaza',
  zanahoria: 'Zanahoria',
  tomate: 'Tomate',
  lechuga: 'Lechuga / hojas verdes',
  cebolla: 'Cebolla',
  morron: 'Morrón',
  zapallito: 'Zapallito',
  acelga: 'Acelga o espinaca',
  brocoli: 'Brócoli',
  berenjena: 'Berenjena',
  repollo: 'Repollo',
  chauchas: 'Chauchas',
  pepino: 'Pepino',
  choclo: 'Choclo (fresco o en lata)',
  arvejas: 'Arvejas',
  palta: 'Palta',
  champinones: 'Champiñones',
  remolacha: 'Remolacha',
  ricota: 'Ricota descremada',
};

// ---------- recetas nuevas con IA ----------
// La IA solo propone recetas caseras con ingredientes de la lista permitida. No arma dietas ni da indicaciones médicas.
const FOCOS_TXT = {
  trigliceridos: 'triglicéridos altos: priorizar pescado y legumbres, pocas harinas blancas, nada de azúcar',
  colesterol: 'colesterol alto: más fibra (avena, legumbres, verduras), grasas buenas, nada frito ni fiambres',
  glucemia: 'glucemia elevada: pocas harinas y almidones, porciones chicas de pan/arroz/fideos, fruta entera y no licuados',
  acido_urico: 'ácido úrico alto: poca carne roja, evitar sardinas, preferir lácteos descremados',
  peso: 'bajar de peso: preparaciones livianas, pocas harinas, mucha verdura',
};
// Segunda barrera: descarta recetas cuyo texto menciona algo excluido aunque no lo haya listado en "ing"
const GENERICAS = ['harina', 'pan', 'arroz', 'fideos', 'queso', 'yogur', 'aceite', 'fruta', 'carne', 'semillas', 'galletas', 'leche'];
const sinTildes = (t) => t.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
const RAICES = { leche: 'leche', yogur: 'yogur', queso: 'queso', carne: 'carne', semillas: 'semilla', galletas_arroz: 'galletas de arroz', fideos_integrales: 'fideo', harina_maiz: 'harina de maiz', arroz_integral: 'arroz integral', aceite: 'aceite' };
function raiz(nombre) {
  const w = sinTildes(nombre).replace(/[()]/g, '').split(/\s+/);
  const r = GENERICAS.includes(w[0]) && w[1] && w[1] !== 'de' ? w[0] + ' ' + w[1] : w[0];
  return r.replace(/s$/, '');
}
function mencionaExcluido(texto, excluye) {
  const t = sinTildes(texto);
  return [...excluye].some((k) => { const r = RAICES[k] || raiz(ING_NOMBRES[k]); return r.length > 3 && t.includes(r); });
}
const MOMENTOS_IA = { d: 'desayuno', k: 'colación de media mañana', a: 'almuerzo', m: 'merienda', c: 'cena (liviana)' };

app.post('/api/ia/recetas', auth, wrap(async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(503).json({ error: 'La IA no está activada' });
  const u = await pool.query("SELECT perfil, ia_limite FROM usuarios WHERE id=$1", [req.uid]);
  const perfil = u.rows[0].perfil || {};
  if (perfil.consentIA !== true) return res.status(403).json({ error: 'Primero tienes que aceptar el uso de la IA' });
  const limiteIA = u.rows[0].ia_limite ?? IA_LIMITE_MES;
  const usos = await pool.query("SELECT count(*)::int n FROM ia_usos WHERE usuario_id=$1 AND ok AND creado > date_trunc('month', now())", [req.uid]);
  if (usos.rows[0].n >= limiteIA) return res.status(429).json({ error: `Llegaste al límite de ${limiteIA} usos de IA de este mes` });

  const b = req.body || {};
  const excluye = new Set((Array.isArray(b.excluye) ? b.excluye : []).filter((k) => ING_NOMBRES[k]));
  const permitidos = Object.keys(ING_NOMBRES).filter((k) => !excluye.has(k));
  const focos = (Array.isArray(b.focos) ? b.focos : []).filter((k) => FOCOS_TXT[k]);
  const momento = MOMENTOS_IA[b.momento] ? b.momento : null;
  const idea = String(b.idea || '').slice(0, 200);
  const evitar = (Array.isArray(b.evitar) ? b.evitar : []).slice(0, 160).map((x) => String(x).slice(0, 70));
  // Para que no repita siempre lo mismo: cada pedido lleva un estilo de cocina y dos ingredientes protagonistas al azar
  const ESTILOS = ['criolla argentina casera', 'venezolana liviana', 'mediterránea', 'salteados estilo oriental casero', 'al horno en una sola fuente', 'a la olla, de cocción lenta', 'ensaladas completas y tibias', 'peruana casera', 'mexicana casera sin picante fuerte', 'italiana casera liviana', 'de aprovechamiento (con lo que sobra)', 'rápida, de 15 minutos'];
  const azar = (a) => a[Math.floor(Math.random() * a.length)];
  const estilo = azar(ESTILOS);
  const protagonistas = [...permitidos].sort(() => Math.random() - 0.5).slice(0, 2).map((k) => ING_NOMBRES[k]);
  const pautas = perfil.nutri && perfil.nutri.pautas ? String(perfil.nutri.pautas).slice(0, 1500) : '';

  const prompt = `Eres un cocinero de comida casera, simple y económica, en Argentina. Propón 5 recetas nuevas y distintas entre sí (distinta proteína y distinta forma de cocción en cada una).
Inspiración para esta tanda: cocina ${estilo}. Intenta que al menos dos recetas usen ${protagonistas.join(' y ')}.
Momento del día: ${momento ? MOMENTOS_IA[momento] : 'variado (mezcla desayunos, almuerzos, cenas livianas y meriendas o colaciones)'}.
${idea ? `Pedido del usuario: "${idea}".` : ''}
Ingredientes principales disponibles (usa SOLO estos; sal, especias, ajo, limón, vinagre y agua se pueden usar siempre): ${permitidos.map((k) => ING_NOMBRES[k]).join(', ')}.
${excluye.size ? `NUNCA uses: ${[...excluye].map((k) => ING_NOMBRES[k]).join(', ')}.` : ''}
${focos.length ? `Enfoque de alimentación saludable general: ${focos.map((k) => FOCOS_TXT[k]).join('; ')}.` : 'Enfoque: alimentación saludable general.'}
${pautas ? `Pautas de su nutricionista (respétalas siempre, tienen prioridad): ${pautas}` : ''}
${evitar.length ? `Ya tiene estas recetas: NO repitas ninguna ni hagas variantes casi iguales (mismo plato con otro nombre): ${evitar.join('; ')}.` : ''}
Reglas: preparación de hasta 30 minutos cuando se pueda; nada frito; sin azúcar agregada; sin alcohol; porción para 1 persona con medidas caseras (taza, cucharada, puñado); no menciones calorías, suplementos, medicamentos ni promesas de salud; español claro usando "tú".
En "ing" pon solo las claves de la lista de ingredientes que usa la receta. En "porque" explica en una frase simple por qué encaja con el enfoque.`;

  const ESQ = {
    type: 'object', additionalProperties: false, required: ['recetas'],
    properties: { recetas: { type: 'array', items: {
      type: 'object', additionalProperties: false, required: ['n', 'momentos', 'ing', 'tag', 'p', 'porque'],
      properties: {
        n: { type: 'string', description: 'Nombre corto de la receta' },
        momentos: { type: 'array', items: { type: 'string', enum: Object.keys(MOMENTOS_IA) }, description: 'd=desayuno, k=colación, a=almuerzo, m=merienda, c=cena' },
        ing: { type: 'array', items: { type: 'string', enum: permitidos } },
        tag: { type: 'string', enum: ['pescado', 'legumbre', 'ninguno'] },
        p: { type: 'string', description: 'Preparación en 2 a 4 frases con cantidades caseras' },
        porque: { type: 'string' },
      } } } },
  };
  let r, cuerpo;
  try {
    r = await fetch(OPENAI_URL + '/responses', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + OPENAI_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: OPENAI_MODEL, input: [{ role: 'user', content: [{ type: 'input_text', text: prompt }] }],
        text: { format: { type: 'json_schema', name: 'recetas', strict: true, schema: ESQ } }, store: false }),
    });
    cuerpo = await r.json();
  } catch (e) { console.error('OpenAI', e.message); return res.status(502).json({ error: 'No se pudo conectar con la IA. Prueba de nuevo en un rato.' }); }
  if (!r.ok) {
    console.error('OpenAI', r.status, JSON.stringify(cuerpo).slice(0, 500));
    await pool.query('INSERT INTO ia_usos (usuario_id, ok) VALUES ($1, false)', [req.uid]);
    return res.status(502).json({ error: 'La IA no pudo generar recetas en este momento.' });
  }
  const texto = (cuerpo.output || []).flatMap((o) => o.content || []).find((c) => c.type === 'output_text');
  let datos;
  try { datos = JSON.parse(texto.text); } catch { return res.status(502).json({ error: 'La IA devolvió una respuesta que no se pudo leer. Prueba de nuevo.' }); }
  await pool.query('INSERT INTO ia_usos (usuario_id) VALUES ($1)', [req.uid]);
  // Validación: solo ingredientes permitidos y momentos válidos
  const propuestas = (datos.recetas || []).length;
  const recetas = (datos.recetas || []).map((x) => ({
    id: 'ia_' + crypto.randomBytes(5).toString('hex'),
    n: String(x.n || '').slice(0, 80),
    m: [...new Set((x.momentos || []).filter((k) => MOMENTOS_IA[k]))].join(''),
    ing: [...new Set((x.ing || []).filter((k) => ING_NOMBRES[k] && !excluye.has(k)))],
    tag: x.tag === 'pescado' || x.tag === 'legumbre' ? x.tag : undefined,
    p: String(x.p || '').slice(0, 700),
    porque: String(x.porque || '').slice(0, 200),
    ia: true, creada: new Date().toISOString().slice(0, 10),
  })).filter((x) => x.n && x.m && x.ing.length && x.p && !mencionaExcluido(x.n + ' ' + x.p, excluye));
  res.json({ recetas, descartadas: propuestas - recetas.length, restantes: limiteIA - usos.rows[0].n - 1 });
}));

// ---------- voz guía natural (texto a voz de OpenAI, con caché) ----------
// Cada frase se genera una sola vez y queda guardada: la próxima vez (para cualquier usuario) sale de la base.
const TTS_MODEL = process.env.TTS_MODEL || 'gpt-4o-mini-tts';
const TTS_VOZ = process.env.TTS_VOZ || 'sage';
const ESTILOS_VOZ = {
  calma: 'Habla en español latinoamericano neutro, con voz cálida, suave y muy tranquila, despacio y con pausas, como una guía de meditación.',
  ejercicio: 'Habla en español latinoamericano neutro, con voz clara, amable y con energía, como un entrenador que motiva sin gritar.',
};
const generacionesVoz = new Map(); // usuario → [timestamps] para limitar abusos
app.post('/api/voz', auth, wrap(async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(503).json({ error: 'Voz natural no disponible' });
  const texto = String((req.body && req.body.texto) || '').replace(/\s+/g, ' ').trim().slice(0, 700);
  const estilo = ESTILOS_VOZ[req.body && req.body.estilo] ? req.body.estilo : 'calma';
  if (!texto) return res.status(400).json({ error: 'Falta el texto' });
  const clave = crypto.createHash('sha256').update([TTS_MODEL, TTS_VOZ, estilo, texto].join('|')).digest('hex');
  const c = await pool.query('SELECT audio FROM voz_cache WHERE clave=$1', [clave]);
  const enviar = (buf) => res.set({ 'Content-Type': 'audio/mpeg', 'Cache-Control': 'private, max-age=86400' }).send(buf);
  if (c.rowCount) return enviar(c.rows[0].audio);
  const ahora = Date.now();
  const lista = (generacionesVoz.get(req.uid) || []).filter((t) => ahora - t < 86400000);
  if (lista.length >= 500) return res.status(429).json({ error: 'Límite diario de voz alcanzado' });
  lista.push(ahora); generacionesVoz.set(req.uid, lista);
  const pedir = (cuerpo) => fetch(OPENAI_URL + '/audio/speech', {
    method: 'POST', headers: { Authorization: 'Bearer ' + OPENAI_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(cuerpo),
  });
  let r;
  try {
    r = await pedir({ model: TTS_MODEL, voice: TTS_VOZ, input: texto, instructions: ESTILOS_VOZ[estilo], response_format: 'mp3' });
    if (!r.ok && TTS_MODEL !== 'tts-1') { console.error('TTS', r.status, (await r.text()).slice(0, 200)); r = await pedir({ model: 'tts-1', voice: 'nova', input: texto, response_format: 'mp3', speed: estilo === 'calma' ? 0.9 : 1 }); }
  } catch (e) { console.error('TTS', e.message); return res.status(502).json({ error: 'No se pudo generar la voz' }); }
  if (!r.ok) { console.error('TTS', r.status, (await r.text()).slice(0, 200)); return res.status(502).json({ error: 'No se pudo generar la voz' }); }
  const buf = Buffer.from(await r.arrayBuffer());
  await pool.query('INSERT INTO voz_cache (clave, audio) VALUES ($1,$2) ON CONFLICT (clave) DO NOTHING', [clave, buf]);
  enviar(buf);
}));

// ---------- SPA ----------
// index.html se sirve con la URL pública completa en las etiquetas de vista previa (og:image necesita URL absoluta)
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'No existe' });
  const base = (process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
  res.set('Cache-Control', 'no-cache').type('html').send(INDEX_HTML.split('__URL__').join(base));
});

// ---------- arranque ----------
(async () => {
  try {
    await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
    console.log('Esquema OK');
  } catch (e) {
    console.error('Error aplicando schema.sql:', e.message);
  }
  if (!process.env.JWT_SECRET) console.warn('⚠️  Falta JWT_SECRET: configúralo en Easypanel');
  app.listen(PORT, () => console.log(`Vamos Pa' Arriba escuchando en :${PORT}`));
})();
