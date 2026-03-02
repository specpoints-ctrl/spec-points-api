import admin from 'firebase-admin';
import { Request, Response, NextFunction } from 'express';
import { logger } from '../index.js';

// Initialize Firebase Admin SDK
const initializeFirebase = () => {
  try {
    if (admin.apps.length > 0) {
      return admin.app();
    }

    const projectId = process.env.FIREBASE_PROJECT_ID;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;

    if (!projectId || !privateKey || !clientEmail) {
      throw new Error('Firebase credentials are not properly configured');
    }

    return admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        privateKey,
        clientEmail,
      }),
    });
  } catch (error) {
    logger.error('Failed to initialize Firebase:', error);
    throw error;
  }
};

// Initialize on module load
export const firebaseApp = initializeFirebase();

// Extended Request type with user info
export interface AuthRequest extends Request {
  user?: {
    uid: string;
    email?: string;
    emailVerified?: boolean;
  };
  userId?: string;
}

// Middleware to verify Firebase authentication token
export const authenticateToken = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        error: 'No authorization header provided',
      });
    }

    const token = authHeader.split(' ')[1]; // Bearer <token>

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'No token provided',
      });
    }

    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(token);

    // Attach user info to request
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      emailVerified: decodedToken.email_verified,
    };
    req.userId = decodedToken.uid;

    logger.debug(`Authenticated user: ${decodedToken.email}`);
    next();
  } catch (error: any) {
    logger.error('Authentication error:', error.message);

    if (error.code === 'auth/id-token-expired') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
      });
    }

    return res.status(403).json({
      success: false,
      error: 'Invalid or expired token',
    });
  }
};

// Middleware to check user role
export const requireRole = (...roles: string[]) => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user?.uid) {
        return res.status(401).json({
          success: false,
          error: 'User not authenticated',
        });
      }

      // Import db here to avoid circular dependency
      const { db } = await import('../db/config.js');

      // Get user role from database
      const userRole = await db.oneOrNone(
        `SELECT ur.role 
         FROM user_roles ur
         JOIN users u ON u.id = ur.user_id
         WHERE u.firebase_uid = $1
         LIMIT 1`,
        [req.user.uid]
      );

      if (!userRole) {
        return res.status(403).json({
          success: false,
          error: 'User has no assigned role',
        });
      }

      if (!roles.includes(userRole.role)) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions',
        });
      }

      logger.debug(`Role check passed: ${userRole.role}`);
      next();
    } catch (error) {
      logger.error('Role check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to verify user role',
      });
    }
  };
};

// Helper to create Firebase user
export const createFirebaseUser = async (
  email: string,
  password: string
): Promise<admin.auth.UserRecord> => {
  try {
    const userRecord = await admin.auth().createUser({
      email,
      password,
      emailVerified: false,
    });
    return userRecord;
  } catch (error) {
    logger.error('Failed to create Firebase user:', error);
    throw error;
  }
};

// Helper to delete Firebase user
export const deleteFirebaseUser = async (uid: string) => {
  try {
    await admin.auth().deleteUser(uid);
    logger.info(`Deleted Firebase user: ${uid}`);
  } catch (error) {
    logger.error('Failed to delete Firebase user:', error);
    throw error;
  }
};

// Helper to generate custom token
export const generateCustomToken = async (uid: string) => {
  try {
    return await admin.auth().createCustomToken(uid);
  } catch (error) {
    logger.error('Failed to generate custom token:', error);
    throw error;
  }
};
