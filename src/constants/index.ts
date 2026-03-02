export const APP_ROLES = {
  ADMIN: 'admin',
  ARCHITECT: 'architect',
  LOJISTA: 'lojista',
} as const;

export const USER_STATUS = {
  PENDING: 'pending',
  ACTIVE: 'active',
  BLOCKED: 'blocked',
} as const;

export const ARCHITECT_STATUS = {
  PENDING: 'pending',
  ACTIVE: 'active',
  INACTIVE: 'inactive',
} as const;

export const REDEMPTION_STATUS = {
  PENDING: 'pending',
  APPROVED: 'approved',
  DELIVERED: 'delivered',
} as const;

export const POINTS_PER_DOLLAR = 1;

export const RATE_LIMIT = {
  WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  MAX_ATTEMPTS: 5,
};

export const API_MESSAGES = {
  AUTH: {
    INVALID_CREDENTIALS: 'Invalid email or password',
    ACCOUNT_BLOCKED: 'Account is blocked. Please contact support.',
    ACCOUNT_PENDING: 'Account is pending approval.',
    EMAIL_IN_USE: 'Email already in use',
    WEAK_PASSWORD: 'Password does not meet security requirements',
    TOKEN_EXPIRED: 'Authentication token expired',
    UNAUTHORIZED: 'Unauthorized access',
  },
  SUCCESS: {
    CREATED: 'Resource created successfully',
    UPDATED: 'Resource updated successfully',
    DELETED: 'Resource deleted successfully',
  },
  ERROR: {
    NOT_FOUND: 'Resource not found',
    SERVER_ERROR: 'Internal server error',
    VALIDATION_ERROR: 'Validation error',
    INSUFFICIENT_POINTS: 'Insufficient points for redemption',
    OUT_OF_STOCK: 'Prize is out of stock',
  },
};
