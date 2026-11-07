export type RoleCode =
  | 'Administrador_Global'
  | 'Administrador_Remediacion'
  | 'Auditor_Lectura';

export type TabId = 'dashboard' | 'audit' | 'modules';

export interface RolePermissions {
  canViewDashboard: boolean;
  canViewAuditLogs: boolean;
  canExecuteRemediation: boolean;
  canManageModulesAndRoles: boolean;
}

export interface TeamMemberAccount {
  id: string;
  fullName: string;
  shortName: string;
  email: string;
  roleCode: RoleCode;
  roleLabel: string;
  avatarBg: string;
  initials: string;
  scopes: string[];
  description: string;
  permissions: RolePermissions;
}

export interface IpAccessRecord {
  ip: string;
  loc: string;
  status: 'Exitoso' | 'Denegado' | 'Sospechoso';
  time: string;
}

export type RiskCategory = 'critical' | 'mfa' | 'inactive';

export type ActionCode =
  | 'REVOKE_SESSION'
  | 'ENFORCE_MFA'
  | 'RESET_PASSWORD'
  | 'DISABLE_ACCOUNT'
  | 'TENANT_SCAN';

export interface VulnerableIdentity {
  id: string;
  name: string;
  email: string;
  initials: string;
  department: 'Infraestructura TI' | 'Contabilidad' | 'Finanzas & Tesorería' | 'Recursos Humanos';
  mfaStatus: 'Configurado' | 'Pendiente';
  riskType: RiskCategory;
  riskScore: number;
  riskLabel: 'ALTO' | 'MEDIO' | 'BAJO';
  lastAccess: string;
  actionCode: ActionCode;
  actionText: string;
  actionIcon: string;
  graphEndpoint: string;
  remediated: boolean;
  riskReason: string;
  aiDiagnosis: string;
  aiActionPlan: string[];
  ipHistory: IpAccessRecord[];
}

export interface AuditLogEntry {
  id: number;
  created_at: string;
  adm_usr: string;
  adm_name: string;
  usr_role: RoleCode;
  act_code: ActionCode;
  actionLabel: string;
  tgt_usr: string;
  details: {
    ip?: string;
    httpStatus: string;
    graphEndpoint: string;
  };
}

export interface SecScoreRecord {
  label: string;
  scorePct: number;
  no_mfa_cnt: number;
  total_usrs: number;
  scan_dt: string;
}

export interface ContainerStatusItem {
  containerName: string;
  serviceKey: string;
  techStack: string;
  endpoint: string;
  statusLabel: string;
  healthy: boolean;
}

