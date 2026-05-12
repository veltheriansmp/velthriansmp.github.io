import { sql } from '@vercel/postgres';
import Pusher from 'pusher';

const pusher = new Pusher({
  appId: "2153636",
  key: "280cbae97b79cb1421b2",
  secret: "bcfb2533ab20cc8368c1",
  cluster: "ap1",
  useTLS: true
});

// Reuse token auth from me.js
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
    SELECT id, username, status FROM users
    WHERE id = ${Number(id)} AND username = ${username} LIMIT 1
  `;
  if (rowCount === 0) { res.status(401).json({ error: 'Session invalid.' }); return null; }
  if (rows[0].status === 'banned') { res.status(403).json({ error: 'You are banned.' }); return null; }
  return rows[0];
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();

  // Ensure messages table exists (idempotent)
  await sql`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'web',  -- 'web' | 'discord' | 'minecraft'
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  // ---- GET: fetch last 50 messages ----
  if (req.method === 'GET') {
    const user = await resolveUser(req, res);
    if (!user) return;

    const { rows } = await sql`
      SELECT id, username, source, content, created_at
      FROM chat_messages
      ORDER BY created_at DESC
      LIMIT 50
    `;
    return res.status(200).json({ messages: rows.reverse() });
  }

  // ---- POST: send a message ----
  if (req.method === 'POST') {
    // Discord/MC bridge can POST with a special server secret instead of user token
    const bridgeSecret = req.headers['x-bridge-secret'];
    let username, source;

    if (bridgeSecret && bridgeSecret === process.env.BRIDGE_SECRET) {
      // Trusted bridge — accepts { username, source, content } directly
      username = req.body?.username;
      source = req.body?.source ?? 'discord';
    } else {
      const user = await resolveUser(req, res);
      if (!user) return;
      username = user.username;
      source = 'web';
    }

    const content = req.body?.content?.trim();
    if (!content) return res.status(400).json({ error: 'Message content is required.' });
    if (content.length > 500) return res.status(400).json({ error: 'Max 500 characters.' });

    const { rows } = await sql`
      INSERT INTO chat_messages (username, source, content)
      VALUES (${username}, ${source}, ${content})
      RETURNING id, username, source, content, created_at
    `;

    const msg = rows[0];

    // Broadcast to all connected Pusher clients
    await pusher.trigger('smp-chat', 'new-message', {
      id: msg.id,
      username: msg.username,
      source: msg.source,
      content: msg.content,
      created_at: msg.created_at,
    });

    return res.status(201).json({ message: msg });
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}
