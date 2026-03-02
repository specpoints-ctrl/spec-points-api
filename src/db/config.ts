import pgPromise from 'pg-promise';
import { logger } from '../index.js';

const pgp = pgPromise({
  query(e) {
    logger.debug('Query:', e.query);
  },
  error(err, e) {
    logger.error('Database error:', err);
    if (e.query) {
      logger.error('Query:', e.query);
    }
  },
});

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error('DATABASE_URL environment variable is not set');
}

export const db = pgp(databaseUrl);

// Test connection
export const testConnection = async () => {
  try {
    await db.connect();
    logger.info('Database connection established successfully');
    return true;
  } catch (error) {
    logger.error('Failed to connect to database:', error);
    return false;
  }
};

// Helper function for transactions
export const withTransaction = async <T>(
  callback: (tx: pgPromise.ITask<any>) => Promise<T>
): Promise<T> => {
  return db.tx(callback);
};
