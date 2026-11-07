const EMAIL_UPN_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const TENANT_IDENTIFIER_REGEX = /^[a-zA-Z0-9-]{8,64}$/;
const DANGEROUS_CHARS_REGEX = /[<>"'`;\\]/g;

export interface SecurityEnvConfig {
  readonly apiBaseUrl: string;
  readonly defaultTenantId: string;
  readonly defaultClientId: string;
}

export function getSecurityEnvConfig(): SecurityEnvConfig {
  try {
    const env = import.meta.env || {};
    const rawBaseUrl =
      typeof env.VITE_API_BASE_URL === 'string' && env.VITE_API_BASE_URL.trim().length > 0
        ? env.VITE_API_BASE_URL.trim()
        : 'http://localhost:5000';

    const rawTenantId =
      typeof env.VITE_TENANT_ID === 'string' && env.VITE_TENANT_ID.trim().length > 0
        ? env.VITE_TENANT_ID.trim()
        : 'tenant-id-env-placeholder';

    const rawClientId =
      typeof env.VITE_CLIENT_ID === 'string' && env.VITE_CLIENT_ID.trim().length > 0
        ? env.VITE_CLIENT_ID.trim()
        : 'client-id-env-placeholder';

    return {
      apiBaseUrl: rawBaseUrl.replace(/\/+$/, ''),
      defaultTenantId: sanitizeTextInput(rawTenantId, 64),
      defaultClientId: sanitizeTextInput(rawClientId, 64),
    };
  } catch (error) {
    console.error('Error al cargar variables de entorno del FrontEnd:', error);
    return {
      apiBaseUrl: 'http://localhost:5000',
      defaultTenantId: 'tenant-id-env-placeholder',
      defaultClientId: 'client-id-env-placeholder',
    };
  }
}

export function sanitizeTextInput(input: unknown, maxLength = 120): string {
  if (typeof input !== 'string') {
    return '';
  }
  const validMaxLength =
    Number.isInteger(maxLength) && maxLength > 0 && maxLength <= 500 ? maxLength : 120;
  return input.replace(DANGEROUS_CHARS_REGEX, '').slice(0, validMaxLength);
}

export function escapeHtmlEntities(input: unknown): string {
  if (typeof input !== 'string') {
    return '';
  }
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function isValidEmailUpn(email: unknown): email is string {
  if (typeof email !== 'string') {
    return false;
  }
  const trimmed = email.trim();
  if (trimmed.length < 5 || trimmed.length > 150) {
    return false;
  }
  return EMAIL_UPN_REGEX.test(trimmed);
}

export function isValidClientOrTenantId(identifier: unknown): identifier is string {
  if (typeof identifier !== 'string') {
    return false;
  }
  const trimmed = identifier.trim();
  return TENANT_IDENTIFIER_REGEX.test(trimmed);
}

export function clampNumericRange(value: unknown, min: number, max: number): number {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    throw new TypeError(`Se esperaba un número válido entre ${min} y ${max}.`);
  }
  if (min > max) {
    throw new RangeError('El límite inferior no puede ser mayor que el límite superior.');
  }
  return Math.min(max, Math.max(min, value));
}

export function getOrCreateCsrfToken(): string {
  const storageKey = 'ipv_csrf_token';
  try {
    const existingToken = window.sessionStorage.getItem(storageKey);
    if (existingToken && existingToken.length >= 32) {
      return existingToken;
    }
    const randomBytes = new Uint8Array(16);
    window.crypto.getRandomValues(randomBytes);
    const generatedToken = Array.from(randomBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    window.sessionStorage.setItem(storageKey, generatedToken);
    return generatedToken;
  } catch {
    return 'csrf-fallback-session-token-verified';
  }
}

export function buildSecureRequestHeaders(csrfToken: string): HeadersInit {
  if (typeof csrfToken !== 'string' || csrfToken.trim().length === 0) {
    throw new Error('Token CSRF inválido al construir cabeceras de seguridad.');
  }
  return {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-CSRF-Token': csrfToken.trim(),
  };
}

export function isValidTenantConnectionPayload(
  payload: unknown
): payload is { status: string; details?: { organization?: string; tenant_id?: string } } {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }
  const record = payload as Record<string, unknown>;
  return typeof record.status === 'string';
}
