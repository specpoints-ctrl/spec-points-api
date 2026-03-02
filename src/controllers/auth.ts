import { Request, Response } from 'express';
import { db } from '../db/config.js';
import { createFirebaseUser } from '../middleware/auth.js';
import { logger } from '../index.js';

// Register new user
export const register = async (req: Request, res: Response) => {
  try {
    const { email, password, name, role = 'architect' } = req.body;

    // Validate input
    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        error: 'Email, password, and name are required',
      });
    }

    // Validate password strength (basic check)
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 8 characters',
      });
    }

    // Check if email already exists in database
    const existingUser = await db.oneOrNone(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Email already in use',
      });
    }

    // Create Firebase user
    const firebaseUser = await createFirebaseUser(email, password);

    // Create user in database
    const user = await db.one(
      `INSERT INTO users (firebase_uid, email, email_verified, status) 
       VALUES ($1, $2, $3, $4) 
       RETURNING *`,
      [firebaseUser.uid, email, false, 'pending']
    );

    // If role is architect or lojista, create related record
    let relatedId = null;

    if (role === 'architect') {
      const architect = await db.one(
        `INSERT INTO architects (name, email, status) 
         VALUES ($1, $2, 'pending') 
         RETURNING id`,
        [name, email]
      );
      relatedId = architect.id;
    }

    // Create user role
    await db.none(
      `INSERT INTO user_roles (user_id, role, architect_id, store_id) 
       VALUES ($1, $2, $3, NULL)`,
      [user.id, role, relatedId]
    );

    // Log audit
    await db.none(
      `INSERT INTO security_audit_log (user_id, action, resource) 
       VALUES ($1, 'USER_REGISTER', $2)`,
      [user.id, `User ${email} registered with role ${role}`]
    );

    logger.info(`New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully. Account is pending approval.',
      data: {
        uid: firebaseUser.uid,
        email: user.email,
        status: user.status,
      },
    });
  } catch (error: any) {
    logger.error('Registration error:', error);

    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({
        success: false,
        error: 'Email already in use',
      });
    }

    res.status(500).json({
      success: false,
      error: 'Failed to register user',
    });
  }
};

// Login user (verify rate limiting)
export const login = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required',
      });
    }

    // Check rate limiting (last 15 minutes)
    const recentAttempts = await db.oneOrNone(
      `SELECT COUNT(*) as count 
       FROM login_attempts 
       WHERE email = $1 
       AND success = false 
       AND created_at > NOW() - INTERVAL '15 minutes'`,
      [email]
    );

    if (recentAttempts && parseInt(recentAttempts.count) >= 5) {
      return res.status(429).json({
        success: false,
        error: 'Too many failed login attempts. Please try again in 15 minutes.',
      });
    }

    // Check user status
    const user = await db.oneOrNone(
      'SELECT id, firebase_uid, email, status FROM users WHERE email = $1',
      [email]
    );

    if (!user) {
      // Record failed attempt
      await db.none(
        'INSERT INTO login_attempts (email, success, ip_address) VALUES ($1, false, $2)',
        [email, ipAddress]
      );

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
      });
    }

    // Check if user is blocked
    if (user.status === 'blocked') {
      return res.status(403).json({
        success: false,
        error: 'Account is blocked. Please contact support.',
      });
    }

    // Check if user is pending
    if (user.status === 'pending') {
      return res.status(403).json({
        success: false,
        error: 'Account is pending approval.',
      });
    }

    // Get user role
    const userRole = await db.oneOrNone(
      'SELECT role, architect_id, store_id FROM user_roles WHERE user_id = $1',
      [user.id]
    );

    // Record successful attempt
    await db.none(
      'INSERT INTO login_attempts (email, success, ip_address) VALUES ($1, true, $2)',
      [email, ipAddress]
    );

    logger.info(`User logged in: ${email}`);

    // Note: Client will handle Firebase authentication
    // This endpoint just validates status and rate limiting
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          firebase_uid: user.firebase_uid,
          email: user.email,
          status: user.status,
        },
        role: userRole,
      },
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process login',
    });
  }
};

// Get current user info
export const getCurrentUser = async (req: any, res: Response) => {
  try {
    const firebaseUid = req.user?.uid;

    if (!firebaseUid) {
      return res.status(401).json({
        success: false,
        error: 'Not authenticated',
      });
    }

    const user = await db.oneOrNone(
      `SELECT u.id, u.firebase_uid, u.email, u.status, u.created_at,
              ur.role, ur.architect_id, ur.store_id
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       WHERE u.firebase_uid = $1`,
      [firebaseUid]
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
      });
    }

    res.json({
      success: true,
      data: user,
    });
  } catch (error) {
    logger.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get user info',
    });
  }
};

// Cleanup old login attempts (can be called periodically)
export const cleanupLoginAttempts = async () => {
  try {
    const result = await db.result(
      `DELETE FROM login_attempts 
       WHERE created_at < NOW() - INTERVAL '1 day'`
    );
    logger.info(`Cleaned up ${result.rowCount} old login attempts`);
  } catch (error) {
    logger.error('Cleanup login attempts error:', error);
  }
};
