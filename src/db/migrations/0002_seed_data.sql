-- Seed Data for Development
-- This creates initial admin user and test data

-- Insert default dashboard configs
INSERT INTO dashboard_configs (role, message, widget_priority) VALUES
  ('architect', 'Bem-vindo ao SpecPoints! Acumule pontos e resgate prêmios incríveis.', '{"sales": 1, "rewards": 2, "ranking": 3}'),
  ('lojista', 'Registre as vendas dos arquitetos e acompanhe o desempenho da sua loja.', '{"sales": 1, "architects": 2, "metrics": 3}')
ON CONFLICT (role) DO NOTHING;

-- Note: Admin user should be created via Firebase and the API
-- To create admin user manually in development:
-- 1. Create Firebase user via Firebase Console
-- 2. Use the API endpoint POST /api/auth/register or create directly:

-- Example (DO NOT use in production, Firebase UID must be real):
-- INSERT INTO users (firebase_uid, email, email_verified, status) VALUES
--   ('FIREBASE_UID_HERE', 'admin@specpoints.local', true, 'active');
-- 
-- INSERT INTO user_roles (user_id, role) 
-- SELECT id, 'admin' FROM users WHERE email = 'admin@specpoints.local';

-- Log seed completion
INSERT INTO security_audit_log (action, resource) VALUES
  ('SEED_DATA', 'Initial seed data applied');
