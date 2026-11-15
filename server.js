// Vamos Pa' Arriba — servidor
// Node 20 + Express + PostgreSQL. Variables de entorno (en Easypanel):
//   DATABASE_URL     conexión a Postgres
//   JWT_SECRET       cadena larga y secreta
//   REGISTRO_CODIGO  código que se pide para crear cuenta (evita registros de extraños)
//   PORT             opcional, por defecto 3000

const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool, types } = require('pg');

// Las columnas DATE vuelven como texto 'YYYY-MM-DD' (sin corrimientos de zona horaria)
types.setTypeParser(1082, (v) => v);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cambiar-esta-clave';
const REGISTRO_CODIGO = (process.env.REGISTRO_CODIGO || '').trim();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

const TIPOS = ['ejercicio', 'meditacion', 'oracion', 'consulta', 'estudio',
  'psicologo', 'sueno', 'peso', 'episodio'];
const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/;

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ---------- helpers ----------
const firmar = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '180d' });
const usuarioPublico = (u) => ({ id: u.id, nombre: u.nombre, email: u.email, perfil: u.perfil || {} });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Sesión vencida' });
  try {
    req.uid = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: 'Sesión vencida' });
  }
}

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  });

// ---------- auth ----------
app.post('/api/registro', wrap(async (req, res) => {
  const { nombre, email, password, codigo } = req.body || {};
  if (REGISTRO_CODIGO && (codigo || '').trim() !== REGISTRO_CODIGO)
    return res.status(403).json({ error: 'Código de invitación incorrecto' });
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Completa todos los campos' });
  if (String(password).length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  const mail = String(email).trim().toLowerCase();
  const existe = await pool.query('SELECT 1 FROM usuarios WHERE email=$1', [mail]);
  if (existe.rowCount) return res.status(409).json({ error: 'Ese email ya tiene cuenta' });
  const hash = await bcrypt.hash(String(password), 10);
  const r = await pool.query(
    'INSERT INTO usuarios (nombre, email, password_hash) VALUES ($1,$2,$3) RETURNING *',
    [String(nombre).trim(), mail, hash]);
  res.json({ token: firmar(r.rows[0]), usuario: usuarioPublico(r.rows[0]) });
}));

app.post('/api/login', wrap(async (req, res) => {
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
  const cambios = req.body && typeof req.body === 'object' ? req.body : {};
  const r = await pool.query(
    'UPDATE usuarios SET perfil = perfil || $2::jsonb WHERE id=$1 RETURNING *',
    [req.uid, JSON.stringify(cambios)]);
  res.json(usuarioPublico(r.rows[0]));
}));

app.patch('/api/password', auth, wrap(async (req, res) => {
  const { actual, nueva } = req.body || {};
  const r = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.uid]);
  if (!(await bcrypt.compare(String(actual || ''), r.rows[0].password_hash)))
    return res.status(400).json({ error: 'La contraseña actual no coincide' });
  if (String(nueva || '').length < 6) return res.status(400).json({ error: 'Mínimo 6 caracteres' });
  await pool.query('UPDATE usuarios SET password_hash=$2 WHERE id=$1', [req.uid, await bcrypt.hash(String(nueva), 10)]);
  res.json({ ok: true });
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
    'SELECT id, tipo, fecha, datos FROM registros WHERE usuario_id=$1 AND tipo=$2 ORDER BY fecha DESC, id DESC LIMIT $3',
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
