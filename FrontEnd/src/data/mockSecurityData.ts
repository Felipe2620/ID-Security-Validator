import type {
  AuditLogEntry,
  ContainerStatusItem,
  SecScoreRecord,
  TeamMemberAccount,
  VulnerableIdentity,
} from '../types/security';

export const TEAM_ACCOUNTS: TeamMemberAccount[] = [
  {
    id: 'acc-global-admin',
    fullName: 'Felipe Jurado Chamorro',
    shortName: 'Felipe Jurado',
    email: 'felipe.jurado@usc.edu.co',
    roleCode: 'Administrador_Global',
    roleLabel: 'Global Admin',
    avatarBg: '0284c7',
    initials: 'FJ',
    scopes: [
      'Directory.ReadWrite.All',
      'User.ReadWrite.All',
      'User.RevokeSessions.All',
      'RoleManagement.ReadWrite.Directory',
      'AuditLog.Read.All',
    ],
    description:
      'Control total del sistema: visualización de telemetría, ejecución de remediaciones y administración de módulos y matriz RBAC.',
    permissions: {
      canViewDashboard: true,
      canViewAuditLogs: true,
      canExecuteRemediation: true,
      canManageModulesAndRoles: true,
    },
  },
  {
    id: 'acc-remediation-admin',
    fullName: 'Juan Jose Pineda',
    shortName: 'Juan Jose Pineda',
    email: 'juan.pineda@usc.edu.co',
    roleCode: 'Administrador_Remediacion',
    roleLabel: 'Admin Remediación',
    avatarBg: '0d9488',
    initials: 'JP',
    scopes: [
      'Directory.Read.All',
      'UserAuthenticationMethod.ReadWrite.All',
      'User.RevokeSessions.All',
      'AuditLog.Read.All',
    ],
    description:
      'Operador táctico de seguridad: autorizado para auditar el perímetro y ejecutar acciones directas de mitigación (Exigir MFA, Revocar Sesiones, Reset Password).',
    permissions: {
      canViewDashboard: true,
      canViewAuditLogs: true,
      canExecuteRemediation: true,
      canManageModulesAndRoles: false,
    },
  },
  {
    id: 'acc-auditor-reader',
    fullName: 'Miguel Angel Delgado',
    shortName: 'Miguel A. Delgado',
    email: 'miguel.delgado@usc.edu.co',
    roleCode: 'Auditor_Lectura',
    roleLabel: 'Auditor Lector',
    avatarBg: '475569',
    initials: 'MD',
    scopes: ['Directory.Read.All', 'AuditLog.Read.All', 'Reports.Read.All'],
    description:
      'Analista de cumplimiento y auditoría en modo solo lectura: consulta métricas de postura, inspecciona factores de riesgo y exporta evidencias de auditoría.',
    permissions: {
      canViewDashboard: true,
      canViewAuditLogs: true,
      canExecuteRemediation: false,
      canManageModulesAndRoles: false,
    },
  },
];

export const INITIAL_IDENTITIES: VulnerableIdentity[] = [
  {
    id: 'usr-1',
    name: 'David Ruiz',
    email: 'david.ruiz@empresa.com',
    initials: 'DR',
    department: 'Infraestructura TI',
    mfaStatus: 'Configurado',
    riskType: 'critical',
    riskScore: 88,
    riskLabel: 'ALTO',
    lastAccess: 'Hace 5 min (IP Desconocida: 185.220.101.4)',
    actionCode: 'REVOKE_SESSION',
    actionText: 'Revocar Sesión',
    actionIcon: 'ph-prohibit',
    graphEndpoint: 'Revocación de Sesiones Activas',
    remediated: false,
    riskReason:
      'Inicio de sesión desde nodo de salida Tor / IP anónima (Tokio, JP) con anomalía de viaje imposible en menos de 15 minutos desde Bogotá, CO.',
    aiDiagnosis:
      'Se detectó un patrón de Viaje Imposible combinado con el uso de una dirección IP catalogada como proxy anónimo (185.220.101.4). Aunque la cuenta posee MFA configurado, existe alta probabilidad de robo de token de sesión en un perfil con privilegios de Infraestructura TI.',
    aiActionPlan: [
      'Invalidar de inmediato todas las sesiones y tokens de actualización activos del usuario.',
      'Forzar el re-enrolamiento de métodos de autenticación multifactor.',
      'Verificar reglas de reenvío y auditar los eventos recientes de acceso.',
    ],
    ipHistory: [
      { ip: '185.220.101.4', loc: 'Tokio, JP (Nodo Anónimo)', status: 'Denegado', time: 'Hace 5 min' },
      { ip: '190.14.22.1', loc: 'Bogotá, CO', status: 'Exitoso', time: 'Ayer, 08:30' },
      { ip: '190.14.22.1', loc: 'Bogotá, CO', status: 'Exitoso', time: 'Hace 2 días, 09:12' },
    ],
  },
  {
    id: 'usr-2',
    name: 'Laura Mendoza',
    email: 'laura.m@empresa.com',
    initials: 'LM',
    department: 'Contabilidad',
    mfaStatus: 'Pendiente',
    riskType: 'mfa',
    riskScore: 45,
    riskLabel: 'MEDIO',
    lastAccess: 'Ayer, 14:30 (Acceso Directo sin 2FA)',
    actionCode: 'ENFORCE_MFA',
    actionText: 'Exigir MFA',
    actionIcon: 'ph-lock-key',
    graphEndpoint: 'Requerimiento Forzoso de MFA',
    remediated: false,
    riskReason:
      'Autenticación multifactor (MFA) no habilitada en una cuenta perteneciente a un departamento financiero sensible (Contabilidad).',
    aiDiagnosis:
      'La identidad opera únicamente con factor de contraseña simple dentro del área de Contabilidad. Ante ataques de suplantación o fuerza bruta, el perímetro carece de barrera secundaria de verificación.',
    aiActionPlan: [
      'Aplicar requerimiento de registro obligatorio de autenticación multifactor (MFA).',
      'Incluir el grupo de seguridad de Contabilidad en la Directiva de Acceso Condicional.',
      'Validar en el próximo corte de seguridad la disminución de cuentas pendientes de MFA.',
    ],
    ipHistory: [
      { ip: '190.14.22.15', loc: 'Bogotá, CO', status: 'Exitoso', time: 'Ayer, 14:30' },
      { ip: '190.14.22.15', loc: 'Bogotá, CO', status: 'Exitoso', time: 'Hace 2 días' },
    ],
  },
  {
    id: 'usr-3',
    name: 'Carlos Pérez',
    email: 'carlos.p@empresa.com',
    initials: 'CP',
    department: 'Finanzas & Tesorería',
    mfaStatus: 'Pendiente',
    riskType: 'mfa',
    riskScore: 76,
    riskLabel: 'ALTO',
    lastAccess: 'Hoy, 07:45 (Protocolo Legacy IMAP)',
    actionCode: 'ENFORCE_MFA',
    actionText: 'Exigir MFA',
    actionIcon: 'ph-lock-key',
    graphEndpoint: 'Requerimiento Forzoso de MFA',
    remediated: false,
    riskReason:
      'Cuenta de Tesorería sin MFA activo y con autenticaciones heredadas que omiten controles modernos.',
    aiDiagnosis:
      'La cuenta combina ausencia de MFA con inicios de sesión mediante protocolos básicos. Esto expone las operaciones de Tesorería a ataques de fuerza bruta automatizados que no activan desafíos interactivos.',
    aiActionPlan: [
      'Forzar requerimiento MFA inmediato sobre el perfil del usuario.',
      'Bloquear protocolos de autenticación heredados en la cuenta.',
      'Monitorear intentos fallidos posteriores en el registro de auditoría.',
    ],
    ipHistory: [
      { ip: '181.55.104.22', loc: 'Cali, CO', status: 'Sospechoso', time: 'Hoy, 07:45' },
      { ip: '181.55.104.20', loc: 'Cali, CO', status: 'Exitoso', time: 'Ayer, 17:10' },
    ],
  },
  {
    id: 'usr-4',
    name: 'Sofía Vargas',
    email: 'sofia.vargas@empresa.com',
    initials: 'SV',
    department: 'Infraestructura TI',
    mfaStatus: 'Configurado',
    riskType: 'critical',
    riskScore: 91,
    riskLabel: 'ALTO',
    lastAccess: 'Hace 12 min (Múltiples fallos MFA + IP Externa)',
    actionCode: 'REVOKE_SESSION',
    actionText: 'Revocar Sesión',
    actionIcon: 'ph-prohibit',
    graphEndpoint: 'Revocación de Sesiones Activas',
    remediated: false,
    riskReason:
      'Detección de ataque MFA Fatigue (bombardeo de notificaciones Push) seguido de sesión activa desde Frankfurt, DE.',
    aiDiagnosis:
      'Se identificaron 14 solicitudes consecutivas de aprobación MFA en un lapso de 3 minutos desde una jurisdicción no habitual (Frankfurt, DE), seguidas de una aceptación. Alto riesgo de compromiso de cuenta privilegiada.',
    aiActionPlan: [
      'Revocar de inmediato todas las sesiones y tokens activos del usuario.',
      'Activar coincidencia de números en la política de verificación multifactor.',
      'Auditar cambios realizados por la cuenta en los últimos 30 minutos.',
    ],
    ipHistory: [
      { ip: '91.108.56.110', loc: 'Frankfurt, DE', status: 'Sospechoso', time: 'Hace 12 min' },
      { ip: '91.108.56.110', loc: 'Frankfurt, DE', status: 'Denegado', time: 'Hace 14 min' },
      { ip: '190.14.22.9', loc: 'Medellín, CO', status: 'Exitoso', time: 'Ayer, 18:05' },
    ],
  },
];

export const EXTRA_GRAPH_IDENTITIES: VulnerableIdentity[] = [
  {
    id: 'usr-5',
    name: 'Andrés Morales',
    email: 'andres.morales@empresa.com',
    initials: 'AM',
    department: 'Recursos Humanos',
    mfaStatus: 'Pendiente',
    riskType: 'inactive',
    riskScore: 38,
    riskLabel: 'BAJO',
    lastAccess: 'Hace 42 días (Cuenta Inactiva sin MFA)',
    actionCode: 'RESET_PASSWORD',
    actionText: 'Restablecer Clave',
    actionIcon: 'ph-key',
    graphEndpoint: 'Restablecimiento de Credenciales',
    remediated: false,
    riskReason:
      'Cuenta sin actividad durante más de 30 días y sin MFA configurado, aumentando la superficie de ataque latente.',
    aiDiagnosis:
      'Las cuentas inactivas por más de 30 días sin MFA representan vectores silenciosos de persistencia para accesos externos no autorizados.',
    aiActionPlan: [
      'Forzar restablecimiento de contraseña temporal o deshabilitar preventivamente la cuenta.',
      'Exigir enrolamiento MFA en el siguiente inicio de sesión interactivo.',
    ],
    ipHistory: [
      { ip: '190.14.22.40', loc: 'Bogotá, CO', status: 'Exitoso', time: 'Hace 42 días' },
    ],
  },
  {
    id: 'usr-6',
    name: 'Camila Castro',
    email: 'camila.castro@empresa.com',
    initials: 'CC',
    department: 'Contabilidad',
    mfaStatus: 'Pendiente',
    riskType: 'mfa',
    riskScore: 54,
    riskLabel: 'MEDIO',
    lastAccess: 'Hoy, 09:20 (Web Browser - Windows 11)',
    actionCode: 'ENFORCE_MFA',
    actionText: 'Exigir MFA',
    actionIcon: 'ph-lock-key',
    graphEndpoint: 'Requerimiento Forzoso de MFA',
    remediated: false,
    riskReason:
      'Usuario activo en Contabilidad con período de gracia de configuración MFA vencido.',
    aiDiagnosis:
      'El usuario ha pospuesto el registro de segundo factor más allá del umbral permitido por la política de gobernanza.',
    aiActionPlan: [
      'Exigir configuración inmediata de MFA eliminando el aplazamiento de registro.',
      'Verificar dispositivo autorizado en el inventario corporativo.',
    ],
    ipHistory: [
      { ip: '190.14.22.88', loc: 'Cali, CO', status: 'Exitoso', time: 'Hoy, 09:20' },
      { ip: '190.14.22.88', loc: 'Cali, CO', status: 'Exitoso', time: 'Ayer, 16:40' },
    ],
  },
];

export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 104,
    created_at: '2026-10-31 11:45:12 UTC',
    adm_usr: 'sistema@empresa.com',
    adm_name: 'Sistema Automático',
    usr_role: 'Administrador_Global',
    act_code: 'TENANT_SCAN',
    actionLabel: 'Escaneo Automático de Seguridad',
    tgt_usr: 'Directorio General (1,245 usuarios)',
    details: {
      httpStatus: 'Completado',
      graphEndpoint: 'Escaneo General',
    },
  },
  {
    id: 103,
    created_at: '2026-10-31 10:30:45 UTC',
    adm_usr: 'juan.pineda@usc.edu.co',
    adm_name: 'Juan Jose Pineda',
    usr_role: 'Administrador_Remediacion',
    act_code: 'ENFORCE_MFA',
    actionLabel: 'Exigir MFA Forzoso',
    tgt_usr: 'ricardo.s@empresa.com',
    details: {
      ip: '190.14.22.10',
      httpStatus: 'Exitoso',
      graphEndpoint: 'Requerimiento MFA',
    },
  },
  {
    id: 102,
    created_at: '2026-10-31 09:18:22 UTC',
    adm_usr: 'felipe.jurado@usc.edu.co',
    adm_name: 'Felipe Jurado Chamorro',
    usr_role: 'Administrador_Global',
    act_code: 'REVOKE_SESSION',
    actionLabel: 'Revocar Sesión',
    tgt_usr: 'marcela.gomez@empresa.com',
    details: {
      ip: '185.220.101.9',
      httpStatus: 'Exitoso',
      graphEndpoint: 'Revocación de Sesión',
    },
  },
  {
    id: 101,
    created_at: '2026-10-30 17:05:19 UTC',
    adm_usr: 'juan.pineda@usc.edu.co',
    adm_name: 'Juan Jose Pineda',
    usr_role: 'Administrador_Remediacion',
    act_code: 'RESET_PASSWORD',
    actionLabel: 'Restablecer Contraseña Temporal',
    tgt_usr: 'jorge.ospina@empresa.com',
    details: {
      ip: '190.14.22.55',
      httpStatus: 'Exitoso',
      graphEndpoint: 'Restablecimiento de Clave',
    },
  },
];

export const MONTHLY_SEC_SCORE_HIST: SecScoreRecord[] = [
  { label: 'Mayo', scorePct: 68, no_mfa_cnt: 142, total_usrs: 1180, scan_dt: '2026-05-31' },
  { label: 'Junio', scorePct: 72, no_mfa_cnt: 118, total_usrs: 1195, scan_dt: '2026-06-30' },
  { label: 'Julio', scorePct: 70, no_mfa_cnt: 125, total_usrs: 1205, scan_dt: '2026-07-31' },
  { label: 'Agosto', scorePct: 78, no_mfa_cnt: 89, total_usrs: 1218, scan_dt: '2026-08-31' },
  { label: 'Septiembre', scorePct: 83, no_mfa_cnt: 64, total_usrs: 1230, scan_dt: '2026-09-30' },
  { label: 'Octubre', scorePct: 89, no_mfa_cnt: 48, total_usrs: 1245, scan_dt: '2026-10-31' },
];

export const WEEKLY_SEC_SCORE_HIST: SecScoreRecord[] = [
  { label: 'Sem 1 Oct', scorePct: 84, no_mfa_cnt: 61, total_usrs: 1233, scan_dt: '2026-10-07' },
  { label: 'Sem 2 Oct', scorePct: 86, no_mfa_cnt: 56, total_usrs: 1238, scan_dt: '2026-10-14' },
  { label: 'Sem 3 Oct', scorePct: 87, no_mfa_cnt: 52, total_usrs: 1241, scan_dt: '2026-10-21' },
  { label: 'Sem 4 Oct', scorePct: 89, no_mfa_cnt: 48, total_usrs: 1245, scan_dt: '2026-10-31' },
];

export const INITIAL_CONTAINERS: ContainerStatusItem[] = [
  {
    containerName: 'validator_frontend',
    serviceKey: 'frontend_ui',
    techStack: 'React 19 + TypeScript + Vite 8 + Tailwind CSS',
    endpoint: 'http://localhost:3000',
    statusLabel: 'Operativo',
    healthy: true,
  },
  {
    containerName: 'validator_backend',
    serviceKey: 'backend_api',
    techStack: 'Node.js + Express + Servicio de Validación',
    endpoint: 'http://localhost:5000/api/health',
    statusLabel: 'Operativo',
    healthy: true,
  },
  {
    containerName: 'validator_db',
    serviceKey: 'postgres_db',
    techStack: 'PostgreSQL 15 Alpine',
    endpoint: 'tcp://localhost:5432',
    statusLabel: 'Conectado',
    healthy: true,
  },
];
