-- SpecPoints Database Schema - Initial Migration
-- Version: 0001
-- Created: 2026-03-02

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (linked with Firebase)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  firebase_uid VARCHAR(128) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'blocked')),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- User Roles table
CREATE TABLE IF NOT EXISTS user_roles (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'architect', 'lojista')),
  architect_id BIGINT,
  store_id BIGINT,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, role)
);

-- Architects table
CREATE TABLE IF NOT EXISTS architects (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  phone VARCHAR(20),
  document_id VARCHAR(20),
  company VARCHAR(255),
  address TEXT,
  city VARCHAR(100),
  state VARCHAR(2),
  country VARCHAR(100),
  points_total BIGINT DEFAULT 0 CHECK (points_total >= 0),
  points_redeemed BIGINT DEFAULT 0 CHECK (points_redeemed >= 0),
  status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'inactive')),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Stores table
CREATE TABLE IF NOT EXISTS stores (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  cnpj VARCHAR(18) UNIQUE NOT NULL,
  email VARCHAR(255),
  phone VARCHAR(20),
  branch VARCHAR(100),
  address TEXT,
  city VARCHAR(100),
  state VARCHAR(2),
  country VARCHAR(100),
  status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Sales table
CREATE TABLE IF NOT EXISTS sales (
  id BIGSERIAL PRIMARY KEY,
  architect_id BIGINT NOT NULL,
  store_id BIGINT NOT NULL,
  client_name VARCHAR(255),
  client_phone VARCHAR(20),
  amount_usd DECIMAL(10,2) NOT NULL CHECK (amount_usd >= 0),
  points_generated BIGINT GENERATED ALWAYS AS (FLOOR(amount_usd)) STORED,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (architect_id) REFERENCES architects(id) ON DELETE RESTRICT,
  FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE RESTRICT
);

-- Prizes table
CREATE TABLE IF NOT EXISTS prizes (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  image_url VARCHAR(500),
  points_required BIGINT NOT NULL CHECK (points_required > 0),
  stock BIGINT NOT NULL DEFAULT 0 CHECK (stock >= 0),
  active BOOLEAN DEFAULT TRUE,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Redemptions table
CREATE TABLE IF NOT EXISTS redemptions (
  id BIGSERIAL PRIMARY KEY,
  architect_id BIGINT NOT NULL REFERENCES architects(id) ON DELETE RESTRICT,
  prize_id BIGINT NOT NULL REFERENCES prizes(id) ON DELETE RESTRICT,
  status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'delivered')),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Login Attempts (rate limiting)
CREATE TABLE IF NOT EXISTS login_attempts (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  success BOOLEAN DEFAULT FALSE,
  ip_address VARCHAR(45),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Security Audit Log
CREATE TABLE IF NOT EXISTS security_audit_log (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(255) NOT NULL,
  resource VARCHAR(255),
  old_value TEXT,
  new_value TEXT,
  ip_address VARCHAR(45),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Dashboard Configs
CREATE TABLE IF NOT EXISTS dashboard_configs (
  id BIGSERIAL PRIMARY KEY,
  role VARCHAR(50) NOT NULL CHECK (role IN ('architect', 'lojista')),
  message TEXT,
  widget_priority JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(role)
);

-- Admin Approvals (multi-admin approval system)
CREATE TABLE IF NOT EXISTS admin_approvals (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  admin_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  approved BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, admin_id)
);

-- Add foreign key constraints for user_roles (after architects and stores exist)
ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_architect 
  FOREIGN KEY (architect_id) REFERENCES architects(id) ON DELETE CASCADE;

ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_store 
  FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);
CREATE INDEX IF NOT EXISTS idx_user_roles_architect_id ON user_roles(architect_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_store_id ON user_roles(store_id);

CREATE INDEX IF NOT EXISTS idx_architects_email ON architects(email);
CREATE INDEX IF NOT EXISTS idx_architects_status ON architects(status);
CREATE INDEX IF NOT EXISTS idx_architects_points ON architects(points_total DESC);

CREATE INDEX IF NOT EXISTS idx_stores_cnpj ON stores(cnpj);
CREATE INDEX IF NOT EXISTS idx_stores_status ON stores(status);

CREATE INDEX IF NOT EXISTS idx_sales_architect_id ON sales(architect_id);
CREATE INDEX IF NOT EXISTS idx_sales_store_id ON sales(store_id);
CREATE INDEX IF NOT EXISTS idx_sales_created_at ON sales(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_prizes_points_required ON prizes(points_required);
CREATE INDEX IF NOT EXISTS idx_prizes_active ON prizes(active);

CREATE INDEX IF NOT EXISTS idx_redemptions_architect_id ON redemptions(architect_id);
CREATE INDEX IF NOT EXISTS idx_redemptions_prize_id ON redemptions(prize_id);
CREATE INDEX IF NOT EXISTS idx_redemptions_status ON redemptions(status);

CREATE INDEX IF NOT EXISTS idx_login_attempts_email_time ON login_attempts(email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON security_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON security_audit_log(created_at DESC);

-- Trigger function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update_updated_at trigger to relevant tables
CREATE TRIGGER update_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_architects_updated_at
  BEFORE UPDATE ON architects
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_stores_updated_at
  BEFORE UPDATE ON stores
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sales_updated_at
  BEFORE UPDATE ON sales
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_prizes_updated_at
  BEFORE UPDATE ON prizes
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_redemptions_updated_at
  BEFORE UPDATE ON redemptions
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_dashboard_configs_updated_at
  BEFORE UPDATE ON dashboard_configs
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();
