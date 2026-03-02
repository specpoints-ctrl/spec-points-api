import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import winston from 'winston';

// Load environment variables
dotenv.config();

// Initialize logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple(),
    }),
  ],
});

// Initialize Express app
export const app: Express = express();

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    credentials: true,
  })
);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max: parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS || '100'),
  message: 'Too many requests from this IP, please try again later.',
});

app.use(limiter);

// Logging middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  logger.info(`${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    firebase: {
      configured: !!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY),
      projectId: process.env.FIREBASE_PROJECT_ID ? '✓ set' : '✗ missing',
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL ? '✓ set' : '✗ missing',
      privateKey: process.env.FIREBASE_PRIVATE_KEY ? `✓ set (${process.env.FIREBASE_PRIVATE_KEY.length} chars)` : '✗ missing',
    },
    database: {
      configured: !!process.env.DATABASE_URL,
      url: process.env.DATABASE_URL ? '✓ set' : '✗ missing',
    },
  });
});

// Debug endpoint (development only)
app.get('/debug/env', (_req: Request, res: Response) => {
  const envVars = Object.keys(process.env)
    .filter(key => 
      key.startsWith('FIREBASE_') || 
      key.startsWith('DATABASE_') ||
      key.startsWith('NODE_') ||
      key.startsWith('API_') ||
      key.startsWith('PORT') ||
      key.startsWith('CORS_') ||
      key.startsWith('JWT_') ||
      key.startsWith('LOG_')
    )
    .reduce((acc, key) => {
      // Mask sensitive values
      if (key.includes('SECRET') || key.includes('PRIVATE_KEY') || key.includes('DATABASE_URL')) {
        acc[key] = process.env[key] 
          ? `${process.env[key].substring(0, 20)}...(${process.env[key].length} chars total)` 
          : '(not set)';
      } else {
        acc[key] = process.env[key] || '(not set)';
      }
      return acc;
    }, {} as Record<string, string>);

  res.json({
    message: 'Environment variables (sensitive values masked)',
    env: envVars,
    totalEnvVars: Object.keys(process.env).length,
  });
});

// Import routes
import authRoutes from './routes/auth.js';

// API Routes
app.get('/api', (_req: Request, res: Response) => {
  res.json({
    message: 'SpecPoints API v1.0',
    status: 'running',
    endpoints: {
      health: '/health',
      auth: '/api/auth/*',
      architects: '/api/architects',
      stores: '/api/stores',
      sales: '/api/sales',
    },
  });
});

// Mount routes
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  logger.error(`Error: ${err.message}`);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    status: err.status || 500,
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    path: req.path,
  });
});

export { logger };
