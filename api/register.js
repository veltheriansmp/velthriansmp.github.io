import { sql } from '@vercel/postgres';
import bcrypt from 'bcryptjs';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const { username, password } = req.body ?? {};

  // --- Validation ---
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) {
    return res.status(400).json({
      error: 'Username must be 3–16 chars, alphanumeric/underscore only.',
    });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    // Case-insensitive dupe check
    const existing = await sql`
      SELECT id FROM users WHERE LOWER(username) = LOWER(${username}) LIMIT 1
    `;
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: 'Username already taken.' });
    }

    const password_hash = await bcrypt.hash(password, 12);

    const { rows } = await sql`
      INSERT INTO users (username, password_hash, status)
      VALUES (${username}, ${password_hash}, 'active')
      RETURNING id, username, status
    `;

    const user = rows[0];

    // Minimal token: base64(username:id) — validated server-side in /api/me.js
    const token = Buffer.from(`${user.username}:${user.id}`).toString('base64');

    return res.status(201).json({
      message: 'Registration successful.',
      token,
      user: {
        id: user.id,
        username: user.username,
        status: user.status,
      },
    });
  } catch (err) {
    console.error('[register] DB error:', err);
    return res.status(500).json({ error: 'Internal server error. Try again later.' });
  }
}
