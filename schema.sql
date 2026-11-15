-- Vamos Pa' Arriba — esquema
-- Se aplica solo al arrancar el servidor (todo es IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS usuarios (
  id            SERIAL PRIMARY KEY,
  nombre        TEXT NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  perfil        JSONB NOT NULL DEFAULT '{}'::jsonb,
  creado        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Grupo familiar: comparten plan de comidas y lista de compras
CREATE TABLE IF NOT EXISTS familias (
  id      SERIAL PRIMARY KEY,
  nombre  TEXT NOT NULL,
  codigo  TEXT UNIQUE NOT NULL,
  datos   JSONB NOT NULL DEFAULT '{}'::jsonb,
  creado  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS familia_id INT REFERENCES familias(id) ON DELETE SET NULL;

-- Un registro por día con el checklist (hábitos, agua, ánimo, comidas hechas)
CREATE TABLE IF NOT EXISTS dias (
  usuario_id  INT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  fecha       DATE NOT NULL,
  datos       JSONB NOT NULL DEFAULT '{}'::jsonb,
  actualizado TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (usuario_id, fecha)
);

-- Registros genéricos: ejercicio, meditacion, oracion, consulta, estudio,
-- psicologo, sueno, peso, episodio
CREATE TABLE IF NOT EXISTS registros (
  id          SERIAL PRIMARY KEY,
  usuario_id  INT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  tipo        TEXT NOT NULL,
  fecha       DATE NOT NULL DEFAULT CURRENT_DATE,
  datos       JSONB NOT NULL DEFAULT '{}'::jsonb,
  creado      TIMESTAMPTZ NOT NULL DEFAULT now(),
  actualizado TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_registros_usuario_tipo_fecha
  ON registros (usuario_id, tipo, fecha DESC);
