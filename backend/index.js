require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Email transporter (usar variables de entorno para seguridad)
// Variables esperadas: SMTP_HOST, SMTP_PORT, SMTP_SECURE (true/false), SMTP_USER, SMTP_PASS, MAIL_FROM, APP_BASE_URL
let transporter;
function getTransporter() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
    });
  }
  return transporter;
}

async function sendVerificationEmail(email, token) {
  const baseUrl = process.env.APP_BASE_URL || 'http://localhost:5173';
  const verifyUrl = `${baseUrl}/verify-email?token=${encodeURIComponent(token)}`;
  const mailOptions = {
    from: process.env.MAIL_FROM || 'no-reply@example.com',
    to: email,
    subject: 'Verifica tu correo electrónico',
    html: `<p>Gracias por registrarte. Haz clic en el siguiente enlace para verificar tu correo:</p>
           <p><a href="${verifyUrl}" target="_blank">Verificar correo</a></p>
           <p>Si no creaste esta cuenta, ignora este correo.</p>`
  };
  try {
    await getTransporter().sendMail(mailOptions);
  } catch (e) {
    console.error('Error enviando email:', e.message);
  }
}

async function createAndStoreVerificationToken(user_id) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expires_at = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24h
  await pool.query(
    'INSERT INTO email_verification (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [user_id, tokenHash, expires_at]
  );
  return rawToken; // devolvemos token crudo para enviar por email
}

// Registro de usuario con generación de token de verificación
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING user_id, name, email, created_at, email_verified',
      [name, email, hashedPassword]
    );
    const user = result.rows[0];
    // Crear token y enviar email (no bloquear la respuesta si falla el email)
    try {
      const token = await createAndStoreVerificationToken(user.user_id);
      await sendVerificationEmail(user.email, token);
    } catch (e) {
      console.error('No se pudo enviar email de verificación:', e.message);
    }
    res.status(201).json({
      user_id: user.user_id,
      name: user.name,
      email: user.email,
      created_at: user.created_at,
      email_verified: user.email_verified,
      message: 'Usuario registrado. Se envió email de verificación.'
    });
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ error: 'El email ya está registrado.' });
    } else {
      console.error('Error /api/register:', err.message);
      res.status(500).json({ error: 'Error al registrar usuario.' });
    }
  }
});

// Login de usuario
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Usuario no encontrado.' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Contraseña incorrecta.' });
    if (!user.email_verified) {
      return res.status(403).json({ error: 'Email no verificado. Revisa tu correo o solicita reenvío.' });
    }
    const token = jwt.sign({ user_id: user.user_id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { user_id: user.user_id, name: user.name, email: user.email, email_verified: user.email_verified } });
  } catch (err) {
    console.error('Error /api/login:', err.message);
    res.status(500).json({ error: 'Error al iniciar sesión.' });
  }
});

// Endpoint de verificación de email
app.get('/api/users/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token requerido' });
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const result = await pool.query(
      'SELECT ev.verification_id, ev.user_id, ev.expires_at, ev.used, u.email_verified FROM email_verification ev JOIN users u ON u.user_id = ev.user_id WHERE ev.token_hash = $1',
      [tokenHash]
    );
    const row = result.rows[0];
    if (!row) return res.status(400).json({ error: 'Token inválido' });
    if (row.used) return res.json({ success: true, alreadyVerified: true });
    if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'Token expirado' });
    // Marcar verificado
    await pool.query('UPDATE users SET email_verified = true WHERE user_id = $1', [row.user_id]);
    await pool.query('UPDATE email_verification SET used = true WHERE verification_id = $1', [row.verification_id]);
    res.json({ success: true });
  } catch (e) {
    console.error('Error /api/users/verify-email:', e.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Reenvío de verificación
app.post('/api/users/resend-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido' });
  try {
    const result = await pool.query('SELECT user_id, email_verified FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });
    if (user.email_verified) return res.status(400).json({ error: 'El email ya está verificado' });
    // Opcional: invalidar tokens previos (marcar usados)
    await pool.query('UPDATE email_verification SET used = true WHERE user_id = $1 AND used = false', [user.user_id]);
    const token = await createAndStoreVerificationToken(user.user_id);
    await sendVerificationEmail(email, token);
    res.json({ success: true, message: 'Correo de verificación reenviado' });
  } catch (e) {
    console.error('Error /api/users/resend-verification:', e.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Subir archivo escaneado
app.post('/api/files', async (req, res) => {
  const { user_id, file_hash, file_name, file_type } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO file (user_id, file_hash, file_name, file_type) VALUES ($1, $2, $3, $4) RETURNING *',
      [user_id, file_hash, file_name, file_type]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar archivo.' });
  }
});

// Guardar resultado de escaneo
app.post('/api/scan', async (req, res) => {
  const { file_id, scan_report, vt_score, total_analyzers } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO scan (file_id, scan_report, vt_score, total_analyzers) VALUES ($1, $2, $3, $4) RETURNING *',
      [file_id, scan_report, vt_score, total_analyzers]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar escaneo.' });
  }
});

// Guardar advertencias de proveedores
app.post('/api/warnings', async (req, res) => {
  const { file_id, scan_id, warnings } = req.body; // warnings: [{vendor_name, warning_message}]
  try {
    for (const w of warnings) {
      await pool.query(
        'INSERT INTO vendor_warning (file_id, scan_id, vendor_name, warning_message) VALUES ($1, $2, $3, $4)',
        [file_id, scan_id, w.vendor_name, w.warning_message]
      );
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar advertencias.' });
  }
});


app.get('/api/history/:user_id', async (req, res) => {
  const { user_id } = req.params;
  try {

    const query = `
      SELECT 
        f.file_id,
        f.file_name,
        f.file_type,
        f.file_hash,
        f.uploaded_at,
        u.user_id,
        u.name AS user_name,
        u.email AS user_email,
        s.scan_id,
        s.vt_score,
        s.total_analyzers,
        s.scan_report
      FROM file f
      INNER JOIN users u ON u.user_id = f.user_id
      LEFT JOIN LATERAL (
        SELECT sc.scan_id, sc.vt_score, sc.total_analyzers, sc.scan_report
        FROM scan sc
        WHERE sc.file_id = f.file_id
        ORDER BY sc.scan_id DESC
        LIMIT 1
      ) s ON TRUE
      WHERE f.user_id = $1
      ORDER BY f.uploaded_at DESC, f.file_id DESC;`;
    const result = await pool.query(query, [user_id]);
    res.json(result.rows.map(r => ({
      file_id: r.file_id,
      file_name: r.file_name,
      file_type: r.file_type,
      file_hash: r.file_hash,
      uploaded_at: r.uploaded_at,
      scan_id: r.scan_id,
      vt_score: r.vt_score,
      total_analyzers: r.total_analyzers,
      scan_report: r.scan_report,
      user_id: r.user_id,
      user_name: r.user_name,
      user_email: r.user_email,
      scan_timestamp: null
    })));
  } catch (err) {
    console.error('Error /api/history:', err.message);
    res.status(500).json({ error: 'Error al obtener historial.', details: err.message });
  }
});

app.delete('/api/files/:file_id', async (req, res) => {
  console.log('DELETE /api/files/:file_id')
  const { file_id } = req.params;
  try {
    await pool.query('DELETE FROM file WHERE file_id = $1', [file_id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error DELETE /api/files/:file_id', err.message);
    res.status(500).json({ error: 'Error al eliminar archivo.' });
  }
})

app.listen(3001, () => {
  console.log('Servidor backend en http://localhost:3001');
});
