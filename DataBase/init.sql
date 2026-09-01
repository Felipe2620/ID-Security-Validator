-- 1. Tabla para el Registro de Auditoría Interna de la Aplicación
-- Almacena las remediaciones y acciones ejecutadas a través de la interfaz web.
CREATE TABLE IF NOT EXISTS app_audit_logs (
    id SERIAL PRIMARY KEY,
    adm_usr VARCHAR(150) NOT NULL,            -- UPN/Email del admin (extraído del JWT de Entra ID)
    usr_role VARCHAR(50) NOT NULL,            -- Rol activo del admin en Entra ID (ej: Administrador_Remediacion)
    act_code VARCHAR(50) NOT NULL,            -- Código de constante del Backend (ej: RESET_PASSWORD, ENFORCE_MFA)
    tgt_usr VARCHAR(150) NOT NULL,            -- Correo/UPN del usuario afectado en Azure
    details JSONB DEFAULT '{}',               -- Metadatos dinámicos (IP, HTTP Status, respuesta de Graph API)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla para el Histórico Diario del Perímetro de Seguridad (Tenant)
-- Guarda las "fotografías" diarias del escáner para construir gráficos de tendencia.
CREATE TABLE IF NOT EXISTS sec_score_hist (
    id SERIAL PRIMARY KEY,
    no_mfa_cnt INT NOT NULL,                  -- Conteo de usuarios detectados sin MFA activo
    total_usrs INT NOT NULL,                  -- Total de usuarios analizados durante el escaneo
    scan_dt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================================================
-- ÍNDICES DE RENDIMIENTO
-- ==============================================================================

-- Índice para acelerar búsquedas y filtros por código de acción en los logs
CREATE INDEX IF NOT EXISTS idx_audit_act_code ON app_audit_logs(act_code);

-- Índice para acelerar la búsqueda de historial de auditoría por usuario objetivo
CREATE INDEX IF NOT EXISTS idx_audit_tgt_usr ON app_audit_logs(tgt_usr);

-- Índice GIN especial para realizar consultas veloces dentro de la estructura JSONB
CREATE INDEX IF NOT EXISTS idx_audit_details_gin ON app_audit_logs USING gin (details);

