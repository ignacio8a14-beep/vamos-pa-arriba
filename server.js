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
});
const emailValido = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Sesión vencida' });
  let datos;
  try { datos = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Sesión vencida' }); }
  try {
    const r = await pool.query('SELECT token_ver, email FROM usuarios WHERE id=$1', [datos.id]);
    if (!r.rowCount || (r.rows[0].token_ver || 0) !== (datos.v || 0)) return res.status(401).json({ error: 'Sesión vencida' });
    req.uid = datos.id; req.email = r.rows[0].email;
    pool.query('UPDATE usuarios SET ultimo_acceso = now() WHERE id=$1 AND (ultimo_acceso IS NULL OR ultimo_acceso < now() - interval \'1 hour\')', [datos.id]).catch(() => {});
    next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
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
  const r = await pool.query('SELECT id, nombre FROM usuarios WHERE email=$1', [mail]);
  if (!r.rowCount) return res.json(respuesta);
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('DELETE FROM reseteos WHERE usuario_id=$1', [r.rows[0].id]);
  await pool.query("INSERT INTO reseteos (usuario_id, token_hash, expira) VALUES ($1,$2, now() + interval '1 hour')", [r.rows[0].id, hashToken(token)]);
  const base = (process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
  const link = `${base}/#reset=${token}`;
  await enviarMail(mail, "Crea tu nueva contraseña · Vamos Pa' Arriba", `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#1e2a27">
      <h2 style="color:#1f6f5c">Hola, ${String(r.rows[0].nombre).replace(/[<>&]/g, '')} 🌱</h2>
      <p>Recibimos un pedido para cambiar la contraseña de tu cuenta de Vamos Pa' Arriba.</p>
      <p><a href="${link}" style="display:inline-block;background:#1f6f5c;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:bold">Crear contraseña nueva</a></p>
      <p style="color:#6b7774;font-size:13px">El link vence en 1 hora. Si no lo pediste, ignora este mensaje: tu contraseña sigue igual.</p>
    </div>`);
  res.json(respuesta);
}));

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
app.get('/api/admin/estadisticas', auth, wrap(async (req, res) => {
  if (!ADMIN_EMAIL || req.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'Solo para el administrador' });
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
    `SELECT id, nombre, perfil->'excluye' AS excluye, perfil->>'excluyeTxt' AS "excluyeTxt"
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
  ct: 'Colesterol total (mg/dL)', hdl: 'Colesterol HDL (mg/dL)', ldl: 'Colesterol LDL (mg/dL)', tg: 'Triglicéridos (mg/dL)',
  glu: 'Glucosa en ayunas (mg/dL)', hba1c: 'Hemoglobina glicosilada (%)', crea: 'Creatinina (mg/dL)', tsh: 'TSH (µUI/mL)', au: 'Ácido úrico (mg/dL)',
  ib_peso: 'Peso (kg)', ib_musculo: 'Masa muscular esquelética (kg)', ib_grasa_kg: 'Masa grasa corporal (kg)', ib_grasa_pct: 'Porcentaje de grasa corporal (%)',
  ib_visceral: 'Nivel de grasa visceral', ib_agua: 'Agua corporal total (L)', ib_imc: 'IMC', ib_metab: 'Metabolismo basal / tasa metabólica basal (kcal)', ib_puntaje: 'Puntaje InBody',
};
const ESQUEMA_IA = {
  type: 'object', additionalProperties: false,
  required: ['tipo', 'fecha', 'lugar', 'valores', 'notas'],
  properties: {
    tipo: { type: 'string', enum: ['inbody', 'analisis', 'otro'] },
    fecha: { type: ['string', 'null'], description: 'Fecha del estudio en formato YYYY-MM-DD, o null' },
    lugar: { type: ['string', 'null'], description: 'Laboratorio o centro, o null' },
    valores: {
      type: 'object', additionalProperties: false, required: Object.keys(CAMPOS_IA),
      properties: Object.fromEntries(Object.entries(CAMPOS_IA).map(([k, d]) => [k, { type: ['number', 'null'], description: d }])),
    },
    notas: { type: ['string', 'null'], description: 'Otros valores del informe que no están en la lista, en una línea corta, o null' },
  },
};
const PROMPT_IA = `Eres un asistente que transcribe datos de informes de salud. Lee el documento adjunto (un análisis de sangre, un informe InBody u otro estudio) y devuelve SOLO los valores que aparecen escritos en él.
Reglas:
- No inventes ni estimes nada. Si un valor no aparece o no se lee con claridad, devuelve null.
- Usa punto como separador decimal.
- Si un valor aparece en una unidad distinta a la indicada (por ejemplo mmol/L en vez de mg/dL), devuelve null para ese valor.
- tipo: "inbody" si es un informe de composición corporal (InBody u otro bioimpedanciómetro), "analisis" si es un análisis de sangre, "otro" en cualquier otro caso.
- No interpretes ni des recomendaciones médicas: solo transcribe.`;

app.post('/api/ia/leer', auth, wrap(async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(503).json({ error: 'La lectura con IA no está activada' });
  const u = await pool.query("SELECT perfil->>'consentIA' AS c FROM usuarios WHERE id=$1", [req.uid]);
  if (u.rows[0].c !== 'true') return res.status(403).json({ error: 'Primero tienes que aceptar el uso de la IA' });
  const usos = await pool.query("SELECT count(*)::int n FROM ia_usos WHERE usuario_id=$1 AND ok AND creado > date_trunc('month', now())", [req.uid]);
  if (usos.rows[0].n >= IA_LIMITE_MES) return res.status(429).json({ error: `Llegaste al límite de ${IA_LIMITE_MES} lecturas con IA de este mes` });

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
  res.json({
    tipo: datos.tipo, valores,
    fecha: FECHA_RE.test(datos.fecha || '') ? datos.fecha : null,
    lugar: datos.lugar ? String(datos.lugar).slice(0, 80) : null,
    notas: datos.notas ? String(datos.notas).slice(0, 400) : null,
    restantes: IA_LIMITE_MES - usos.rows[0].n - 1,
  });
}));

// ---------- SPA ----------
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'No existe' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
