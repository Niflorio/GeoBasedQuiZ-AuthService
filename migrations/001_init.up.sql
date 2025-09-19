-- Создание таблицы user_profiles
CREATE TABLE user_profiles (
                               id UUID PRIMARY KEY,
                               username VARCHAR(50) UNIQUE NOT NULL,
                               email VARCHAR(255) UNIQUE NOT NULL,
                               avatar_base64 TEXT,
                               status VARCHAR(100) NOT NULL DEFAULT '',
                               created_at TIMESTAMPTZ DEFAULT NOW(),
                               updated_at TIMESTAMPTZ,
                               deleted_at TIMESTAMPTZ
);

-- Создание таблицы auth_data
CREATE TABLE auth_data (
                           user_id UUID PRIMARY KEY REFERENCES user_profiles(id),
                           password_hash BYTEA NOT NULL,
                           oauth_provider VARCHAR(20),
                           oauth_id VARCHAR(100),
                           last_login TIMESTAMPTZ,
                           failed_attempts INT DEFAULT 0,
                           is_locked BOOLEAN DEFAULT false,
                           created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание таблицы sessions
CREATE TABLE sessions (
                          session_id UUID PRIMARY KEY,
                          user_id UUID NOT NULL REFERENCES auth_data(user_id),
                          device_info JSONB,
                          ip_address INET,
                          issued_at TIMESTAMPTZ DEFAULT NOW(),
                          expires_at TIMESTAMPTZ NOT NULL,
                          is_revoked BOOLEAN DEFAULT false,
                          refresh_token VARCHAR(64) NOT NULL
);

-- Создание таблицы user_roles
CREATE TABLE user_roles (
                            user_id UUID NOT NULL REFERENCES user_profiles(id),
                            role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'content-moderator', 'admin')),
                            granted_at TIMESTAMPTZ DEFAULT NOW(),
                            granted_by UUID REFERENCES user_profiles(id),
                            scope VARCHAR(50),
                            PRIMARY KEY (user_id, role)
);