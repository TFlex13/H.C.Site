import 'dotenv/config';
import Fastify from 'fastify';
import pg from 'pg';

const app = Fastify({ logger: true });
const port = Number(process.env.API_PORT ?? 3002);
const host = process.env.API_HOST ?? '127.0.0.1';
const databaseUrl = process.env.DATABASE_URL;

app.get('/health', async () => ({ status: 'ok', service: 'highline-api' }));
app.get('/health/db', async (_request, reply) => {
  if (!databaseUrl) return reply.code(503).send({ status: 'unavailable', reason: 'DATABASE_URL not configured' });
  const client = new pg.Client({ connectionString: databaseUrl, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    await client.query('SELECT 1');
    return { status: 'ok', database: 'postgresql' };
  } catch (error) {
    app.log.error({ err: error }, 'Database health check failed');
    return reply.code(503).send({ status: 'unavailable', database: 'postgresql' });
  } finally {
    await client.end().catch(() => undefined);
  }
});

const shutdown = async () => { await app.close(); process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

try {
  await app.listen({ port, host });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
