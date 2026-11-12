import { config } from 'dotenv';
import { resolve } from 'node:path';
// Resolve from the API package, regardless of the shell's working directory.
config({ path: resolve(import.meta.dirname, '../../../.env') });
config({ path: resolve(import.meta.dirname, '../.env'), override: false });
export const databaseUrl = process.env.DATABASE_URL;
