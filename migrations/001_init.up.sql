-- Создание таблицы user_profiles
CREATE TABLE user_profiles (
                               id UUID PRIMARY KEY,
                               username VARCHAR(50) UNIQUE NOT NULL,
                               email VARCHAR(255) UNIQUE NOT NULL,
                               avatar_base64 TEXT,
                               status VARCHAR(100) NOT NULL DEFAULT '',
                               is_verified BOOLEAN NOT NULL DEFAULT FALSE,
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
                           locked_until TIMESTAMP,
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

CREATE TABLE verification_tokens (
                                     token UUID PRIMARY KEY,
                                     user_id UUID NOT NULL REFERENCES user_profiles(id),
                                     expires_at TIMESTAMP NOT NULL,
                                     created_at TIMESTAMP NOT NULL
);


CREATE INDEX idx_user_profiles_username ON user_profiles(username);
CREATE INDEX idx_user_profiles_email ON user_profiles(email);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE UNIQUE INDEX idx_user_profiles_username_active ON user_profiles(username) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_user_profiles_email_active ON user_profiles(email) WHERE deleted_at IS NULL;