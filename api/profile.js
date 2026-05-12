import { sql } from '@vercel/postgres';

async function resolveUser(req, res) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing Authorization header.' });
    return null;
  }
  const token = auth.slice(7).trim();
  let username, id;
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    [username, id] = decoded.split(':');
    if (!username || !id || isNaN(Number(id))) throw new Error();
  } catch {
    res.status(401).json({ error: 'Invalid token.' });
    return null;
  }
  const { rows, rowCount } = await sql`
    SELECT id, username, status, role FROM users
    WHERE id = ${Number(id)} AND username = ${username} LIMIT 1
  `;
  if (rowCount === 0) { res.status(401).json({ error: 'Session invalid.' }); return null; }
  if (rows[0].status === 'banned') { res.status(403).json({ error: 'You are banned.' }); return null; }
  return rows[0];
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const user = await resolveUser(req, res);
  if (!user) return;

  // GET /api/profile?username=xxx — fetch any user's public profile
  if (req.method === 'GET') {
    const { username } = req.query;
    const target = username ?? user.username;
    const { rows, rowCount } = await sql`
      SELECT username, role, avatar_url, bio, status
      FROM users WHERE LOWER(username) = LOWER(${target}) LIMIT 1
    `;
    if (rowCount === 0) return res.status(404).json({ error: 'User not found.' });
    return res.status(200).json(rows[0]);
  }

  // PATCH /api/profile — update own avatar_url and/or bio
  if (req.method === 'PATCH') {
    const { avatar_url, bio } = req.body ?? {};

    if (avatar_url !== undefined) {
      // Basic URL validation
      try { new URL(avatar_url); } catch {
        return res.status(400).json({ error: 'Invalid URL.' });
      }
      // Only allow http/https
      if (!avatar_url.startsWith('http://') && !avatar_url.startsWith('https://')) {
        return res.status(400).json({ error: 'URL must start with http:// or https://' });
      }
    }

    if (bio !== undefined && bio.length > 100) {
      return res.status(400).json({ error: 'Bio max 100 characters.' });
    }

    await sql`
      UPDATE users SET
        avatar_url = COALESCE(${avatar_url ?? null}, avatar_url),
        bio = COALESCE(${bio ?? null}, bio)
      WHERE id = ${user.id}
    `;

    const { rows } = await sql`
      SELECT username, role, avatar_url, bio FROM users WHERE id = ${user.id}
    `;

    return res.status(200).json({ message: 'Profile updated.', user: rows[0] });
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}
