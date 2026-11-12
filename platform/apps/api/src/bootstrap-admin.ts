import './config.js';
import pg from 'pg';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { databaseUrl } from './config.js';
import { hashPassword } from './security.js';
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const client = new pg.Client({ connectionString: databaseUrl });
const prompt = createInterface({ input, output });
try {
  await client.connect();
  const count = await client.query("SELECT count(*)::int AS total FROM users WHERE role='admin'");
  if (count.rows[0].total !== 0) throw new Error('Admin already exists; bootstrap is disabled');
  const email = (await prompt.question('Admin email: ')).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Invalid email');
  const displayName = (await prompt.question('Display name: ')).trim();
  if (!displayName) throw new Error('Display name required');
  const password = await prompt.question('Local password (visible as typed, 12+ characters): ');
  const passwordHash = await hashPassword(password);
  await client.query("INSERT INTO users(email,display_name,password_hash,role) VALUES($1,$2,$3,'admin')", [email, displayName, passwordHash]);
  output.write('Local admin account created.\n');
} finally { prompt.close(); await client.end(); }
