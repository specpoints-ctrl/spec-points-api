// User types
export interface User {
  id: string;
  firebase_uid: string;
  email: string;
  email_verified: boolean;
  status: 'pending' | 'active' | 'blocked';
  created_at: Date;
  updated_at: Date;
}

export interface UserRole {
  id: number;
  user_id: string;
  role: 'admin' | 'architect' | 'lojista';
  architect_id?: number;
  store_id?: number;
  created_at: Date;
}

// Architect types
export interface Architect {
  id: number;
  name: string;
  email: string;
  phone?: string;
  document_id?: string;
  company?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  points_total: number;
  points_redeemed: number;
  status: 'pending' | 'active' | 'inactive';
  created_at: Date;
  updated_at: Date;
}

// Store types
export interface Store {
  id: number;
  name: string;
  cnpj: string;
  email?: string;
  phone?: string;
  branch?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  status: 'active' | 'inactive';
  created_at: Date;
  updated_at: Date;
}

// Sale types
export interface Sale {
  id: number;
  architect_id: number;
  store_id: number;
  client_name?: string;
  client_phone?: string;
  amount_usd: number;
  points_generated: number;
  description?: string;
  created_at: Date;
  updated_at: Date;
}

// Prize types
export interface Prize {
  id: number;
  name: string;
  description?: string;
  image_url?: string;
  points_required: number;
  stock: number;
  active: boolean;
  expires_at?: Date;
  created_at: Date;
  updated_at: Date;
}

// Redemption types
export interface Redemption {
  id: number;
  architect_id: number;
  prize_id: number;
  status: 'pending' | 'approved' | 'delivered';
  created_at: Date;
  updated_at: Date;
}

// API response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// Auth types
export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
  role?: 'architect' | 'lojista';
}

export interface AuthResponse {
  user: User;
  token: string;
  role: UserRole;
}
