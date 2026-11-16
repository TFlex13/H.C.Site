import './config.js';
import pg from 'pg';
import { databaseUrl } from './config.js';
import { createApp } from './app.js';

const pool = databaseUrl ? new pg.Pool({ connectionString: databaseUrl, max: 10, connectionTimeoutMillis: 3000 }) : null;
const app = await createApp(pool);
const shutdown = async () => { await app.close(); await pool?.end(); };
process.on('SIGINT', () => { void shutdown().then(() => process.exit(0)); });
process.on('SIGTERM', () => { void shutdown().then(() => process.exit(0)); });
try { await app.listen({ port: Number(process.env.API_PORT ?? 3002), host: process.env.API_HOST ?? '127.0.0.1' }); }
catch (err) { app.log.error(err); await shutdown(); process.exit(1); }
