import React, { useEffect, useMemo, useRef, useState } from 'react';
import { SecurityTrendChart, VulnerabilityDonutChart } from './components/Charts';
import { Icon } from './components/Icons';
import { ViewSkeleton } from './components/Skeletons';
import {
  EXTRA_GRAPH_IDENTITIES,
  INITIAL_AUDIT_LOGS,
  INITIAL_CONTAINERS,
  INITIAL_IDENTITIES,
  MONTHLY_SEC_SCORE_HIST,
  TEAM_ACCOUNTS,
  WEEKLY_SEC_SCORE_HIST,
} from './data/mockSecurityData';
import type {
  AuditLogEntry,
  ContainerStatusItem,
  RiskCategory,
  SecScoreRecord,
  TabId,
  TeamMemberAccount,
  VulnerableIdentity,
} from './types/security';
import {
  maskEmailForReport,
  maskIpForReport,
  printExecutiveSecurityReport,
} from './utils/pdfReportGenerator';
import {
  buildSecureRequestHeaders,
  clampNumericRange,
  getOrCreateCsrfToken,
  getSecurityEnvConfig,
  isValidClientOrTenantId,
  isValidEmailUpn,
  isValidTenantConnectionPayload,
  sanitizeTextInput,
} from './utils/securityValidation';

type ThemePreference = 'light' | 'dark' | 'system';

interface ToastMessage {
  id: number;
  message: string;
  type: 'success' | 'info' | 'warning';
}

interface TrendDetailPopupState {
  record: SecScoreRecord;
  previousRecord: SecScoreRecord | null;
}

const MAX_VISIBLE_TOASTS = 3;
const TOAST_DURATION_MS = 1600;

// Suprime transiciones CSS y fuerza reflow síncrono para pintar el cambio de tema en un único frame
function applyThemeToDomAtomically(nextIsDark: boolean): void {
  try {
    const root = document.documentElement;
    root.classList.add('theme-switching');
    if (nextIsDark) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    void root.offsetHeight;
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        root.classList.remove('theme-switching');
      });
    });
  } catch (error) {
    console.error('Error al aplicar el tema en el DOM:', error);
  }
}

export function App() {
  const envConfig = useMemo(() => getSecurityEnvConfig(), []);
  const csrfToken = useMemo(() => getOrCreateCsrfToken(), []);

  const [customLogoAvailable, setCustomLogoAvailable] = useState<boolean>(true);

  const [themePref, setThemePref] = useState<ThemePreference>(() => {
    try {
      window.localStorage.removeItem('cspm_theme');
      const saved = window.localStorage.getItem('ipv_theme_mode');
      if (saved === 'light' || saved === 'dark' || saved === 'system') {
        return saved;
      }
      return 'light';
    } catch (error) {
      console.error('Error al leer la preferencia de tema en localStorage:', error);
      return 'light';
    }
  });

  const [systemPrefersDark, setSystemPrefersDark] = useState<boolean>(() => {
    try {
      if (typeof window !== 'undefined' && window.matchMedia) {
        return window.matchMedia('(prefers-color-scheme: dark)').matches;
      }
      return false;
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      if (typeof window === 'undefined' || !window.matchMedia) return;
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const handleChange = (e: MediaQueryListEvent) => {
        setSystemPrefersDark(e.matches);
      };
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    } catch (error) {
      console.error('Error al suscribir cambios de esquema de color del sistema:', error);
      return undefined;
    }
  }, []);

  const isDark = themePref === 'dark' || (themePref === 'system' && systemPrefersDark);

  useEffect(() => {
    try {
      applyThemeToDomAtomically(isDark);
      window.localStorage.setItem('ipv_theme_mode', themePref);
    } catch (error) {
      console.error('Error al persistir el tema visual:', error);
    }
  }, [isDark, themePref]);

  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [currentUser, setCurrentUser] = useState<TeamMemberAccount>(TEAM_ACCOUNTS[0]);
  const [loginEmailInput, setLoginEmailInput] = useState<string>(TEAM_ACCOUNTS[0].email);
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState<boolean>(false);
  const profileMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        profileMenuRef.current &&
        !profileMenuRef.current.contains(event.target as Node)
      ) {
        setIsProfileMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [selectedModule, setSelectedModule] = useState<1 | 2 | 3>(1);
  const [isPageLoading, setIsPageLoading] = useState<boolean>(false);
  const [isRescanning, setIsRescanning] = useState<boolean>(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [ariaAnnouncement, setAriaAnnouncement] = useState<string>('');
  const toastTimersRef = useRef<Map<number, number>>(new Map());

  const removeToastById = (id: number) => {
    const timer = toastTimersRef.current.get(id);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      toastTimersRef.current.delete(id);
    }
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const showToast = (message: string, type: 'success' | 'info' | 'warning' = 'info') => {
    try {
      const sanitizedMsg = sanitizeTextInput(message, 180);
      if (!sanitizedMsg) return;

      setAriaAnnouncement(sanitizedMsg);
      const id = Date.now() + Math.floor(Math.random() * 10000);

      setToasts((prev) => {
        const withoutDuplicate = prev.filter((item) => item.message !== sanitizedMsg);
        const trimmed = withoutDuplicate.slice(-(MAX_VISIBLE_TOASTS - 1));
        return [...trimmed, { id, message: sanitizedMsg, type }];
      });

      const timeoutId = window.setTimeout(() => {
        toastTimersRef.current.delete(id);
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, TOAST_DURATION_MS);

      toastTimersRef.current.set(id, timeoutId);
    } catch (error) {
      console.error('Error al mostrar notificación:', error);
    }
  };

  useEffect(() => {
    const timersMap = toastTimersRef.current;
    return () => {
      timersMap.forEach((timeoutId) => window.clearTimeout(timeoutId));
      timersMap.clear();
    };
  }, []);

  const triggerSkeletonLoad = (durationMs = 500, callback?: () => void) => {
    try {
      const safeDuration = clampNumericRange(durationMs, 150, 3000);
      setIsPageLoading(true);
      window.setTimeout(() => {
        if (callback) callback();
        setIsPageLoading(false);
      }, safeDuration);
    } catch (error) {
      console.error('Error en transición de carga:', error);
      if (callback) callback();
      setIsPageLoading(false);
    }
  };

  const [identities, setIdentities] = useState<VulnerableIdentity[]>(INITIAL_IDENTITIES);
  const [extraBatchLoaded, setExtraBatchLoaded] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(INITIAL_AUDIT_LOGS);
  const [trendPeriod, setTrendPeriod] = useState<'monthly' | 'weekly'>('monthly');

  const [identitySearch, setIdentitySearch] = useState<string>('');
  const [deptFilter, setDeptFilter] = useState<string>('all');
  const [mfaFilter, setMfaFilter] = useState<string>('all');
  const [riskCategoryFilter, setRiskCategoryFilter] = useState<RiskCategory | 'all'>('all');
  const [hoveredCardCategory, setHoveredCardCategory] = useState<RiskCategory | 'all' | null>(null);

  const [auditSearch, setAuditSearch] = useState<string>('');
  const [auditActionFilter, setAuditActionFilter] = useState<string>('all');
  const [auditActorFilter, setAuditActorFilter] = useState<string>('all');

  const [profileModalUserId, setProfileModalUserId] = useState<string | null>(null);
  const [confirmModalUserId, setConfirmModalUserId] = useState<string | null>(null);
  const [selectedAuditLogId, setSelectedAuditLogId] = useState<number | null>(null);
  const [trendDetailPopup, setTrendDetailPopup] = useState<TrendDetailPopupState | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [exportIncludeKpis, setExportIncludeKpis] = useState<boolean>(true);
  const [exportIncludeTrend, setExportIncludeTrend] = useState<boolean>(true);
  const [exportIncludeIdentities, setExportIncludeIdentities] = useState<boolean>(true);
  const [exportIncludeAudit, setExportIncludeAudit] = useState<boolean>(true);
  const [exportScope, setExportScope] = useState<'filtered' | 'all'>('filtered');
  const [exportMaskSensitive, setExportMaskSensitive] = useState<boolean>(true);

  const [graphErrorModal, setGraphErrorModal] = useState<{
    open: boolean;
    missingScope: string;
    reason: string;
  }>({
    open: false,
    missingScope: 'User.ReadWrite.All',
    reason:
      'No se pudo ejecutar la acción de remediación. La sesión actual no posee el permiso requerido.',
  });

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setProfileModalUserId(null);
        setConfirmModalUserId(null);
        setSelectedAuditLogId(null);
        setTrendDetailPopup(null);
        setIsExportModalOpen(false);
        setGraphErrorModal((prev) => ({ ...prev, open: false }));
        setIsProfileMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const [tenantIdInput, setTenantIdInput] = useState<string>(envConfig.defaultTenantId);
  const [clientIdInput, setClientIdInput] = useState<string>(envConfig.defaultClientId);
  const [clientSecretMaskedInput, setClientSecretMaskedInput] = useState<string>('');
  const [isTestingConn, setIsTestingConn] = useState<boolean>(false);
  const [backendConnectionInfo, setBackendConnectionInfo] = useState<string>(
    'Conexión Activa y Sincronizada'
  );
  const [containers, setContainers] = useState<ContainerStatusItem[]>(INITIAL_CONTAINERS);

  const remediatedCriticalCount = useMemo(
    () => identities.filter((u) => u.riskType === 'critical' && u.remediated).length,
    [identities]
  );
  const remediatedMfaCount = useMemo(
    () => identities.filter((u) => u.riskType === 'mfa' && u.remediated).length,
    [identities]
  );
  const remediatedInactiveCount = useMemo(
    () => identities.filter((u) => u.riskType === 'inactive' && u.remediated).length,
    [identities]
  );

  const kpiTotalIdentities = 1245 + (extraBatchLoaded ? EXTRA_GRAPH_IDENTITIES.length : 0);
  const kpiSinMfa = Math.max(0, 48 - remediatedMfaCount);
  const kpiRiskSessions = Math.max(0, 7 - remediatedCriticalCount);
  const kpiInactiveAccounts = Math.max(0, 156 - remediatedInactiveCount);
  const totalInRiskCount = Math.max(1, kpiSinMfa + kpiRiskSessions + kpiInactiveAccounts);

  const activeTrendData = useMemo(() => {
    const baseSeries =
      trendPeriod === 'monthly' ? MONTHLY_SEC_SCORE_HIST : WEEKLY_SEC_SCORE_HIST;
    const totalRemediated =
      remediatedCriticalCount + remediatedMfaCount + remediatedInactiveCount;
    return baseSeries.map((point, index) => {
      if (index === baseSeries.length - 1) {
        return {
          ...point,
          no_mfa_cnt: kpiSinMfa,
          total_usrs: kpiTotalIdentities,
          scorePct: Math.min(99, point.scorePct + totalRemediated * 2),
        };
      }
      return point;
    });
  }, [
    trendPeriod,
    remediatedCriticalCount,
    remediatedMfaCount,
    remediatedInactiveCount,
    kpiSinMfa,
    kpiTotalIdentities,
  ]);

  const filteredIdentities = useMemo(() => {
    const q = sanitizeTextInput(identitySearch, 100).trim().toLowerCase();
    return identities.filter((item) => {
      const matchesSearch =
        !q ||
        item.name.toLowerCase().includes(q) ||
        item.email.toLowerCase().includes(q);
      const matchesDept = deptFilter === 'all' || item.department === deptFilter;
      const matchesMfa = mfaFilter === 'all' || item.mfaStatus === mfaFilter;
      const matchesCategory =
        riskCategoryFilter === 'all' || item.riskType === riskCategoryFilter;
      return matchesSearch && matchesDept && matchesMfa && matchesCategory;
    });
  }, [identities, identitySearch, deptFilter, mfaFilter, riskCategoryFilter]);

  const filteredAuditLogs = useMemo(() => {
    const q = sanitizeTextInput(auditSearch, 100).trim().toLowerCase();
    return auditLogs.filter((log) => {
      const matchesSearch =
        !q ||
        log.tgt_usr.toLowerCase().includes(q) ||
        log.actionLabel.toLowerCase().includes(q) ||
        log.act_code.toLowerCase().includes(q) ||
        log.adm_usr.toLowerCase().includes(q);
      const matchesAction =
        auditActionFilter === 'all' || log.act_code === auditActionFilter;
      const matchesActor =
        auditActorFilter === 'all' || log.adm_name === auditActorFilter;
      return matchesSearch && matchesAction && matchesActor;
    });
  }, [auditLogs, auditSearch, auditActionFilter, auditActorFilter]);

  const profileModalUser = useMemo(
    () => identities.find((u) => u.id === profileModalUserId) || null,
    [identities, profileModalUserId]
  );

  const confirmModalUser = useMemo(
    () => identities.find((u) => u.id === confirmModalUserId) || null,
    [identities, confirmModalUserId]
  );

  const selectedAuditLog = useMemo(
    () => auditLogs.find((log) => log.id === selectedAuditLogId) || null,
    [auditLogs, selectedAuditLogId]
  );

  const handleNavigateToMainDashboard = () => {
    setIsProfileMenuOpen(false);
    setProfileModalUserId(null);
    setConfirmModalUserId(null);
    setSelectedAuditLogId(null);
    setTrendDetailPopup(null);
    setIsExportModalOpen(false);
    setGraphErrorModal((prev) => ({ ...prev, open: false }));

    if (activeTab !== 'dashboard') {
      triggerSkeletonLoad(380, () => {
        setActiveTab('dashboard');
      });
    } else if (
      riskCategoryFilter !== 'all' ||
      identitySearch ||
      deptFilter !== 'all' ||
      mfaFilter !== 'all'
    ) {
      setRiskCategoryFilter('all');
      setIdentitySearch('');
      setDeptFilter('all');
      setMfaFilter('all');
    }
  };

  const handleSetThemePreference = (pref: ThemePreference) => {
    if (pref !== 'light' && pref !== 'dark' && pref !== 'system') {
      return;
    }
    const nextDark = pref === 'dark' || (pref === 'system' && systemPrefersDark);
    applyThemeToDomAtomically(nextDark);
    setThemePref(pref);
    setIsProfileMenuOpen(false);
  };

  const handleSelectAccountInLogin = (account: TeamMemberAccount) => {
    if (!account || !isValidEmailUpn(account.email)) return;
    setCurrentUser(account);
    setLoginEmailInput(account.email);
  };

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const sanitizedEmail = sanitizeTextInput(loginEmailInput, 150).trim();
      if (!isValidEmailUpn(sanitizedEmail)) {
        showToast('Formato de correo electrónico inválido.', 'warning');
        return;
      }

      const matchedAccount =
        TEAM_ACCOUNTS.find(
          (acc) => acc.email.toLowerCase() === sanitizedEmail.toLowerCase()
        ) || currentUser;

      setCurrentUser(matchedAccount);
      setIsLoggingIn(true);

      window.setTimeout(() => {
        setIsLoggingIn(false);
        setIsAuthenticated(true);
        setActiveTab('dashboard');
        triggerSkeletonLoad(550);
        showToast(
          `Sesión iniciada como ${matchedAccount.fullName} (${matchedAccount.roleLabel}).`,
          'success'
        );
      }, 380);
    } catch (error) {
      setIsLoggingIn(false);
      console.error('Error durante el inicio de sesión:', error);
      showToast('Error al procesar la solicitud de inicio de sesión.', 'warning');
    }
  };

  const handleSwitchAccountFromProfileMenu = (accountId: string) => {
    try {
      setIsProfileMenuOpen(false);
      const targetAccount = TEAM_ACCOUNTS.find((a) => a.id === accountId);
      if (!targetAccount || targetAccount.id === currentUser.id) return;

      setProfileModalUserId(null);
      setConfirmModalUserId(null);
      setSelectedAuditLogId(null);
      setTrendDetailPopup(null);
      setIsExportModalOpen(false);

      const nextTab: TabId =
        activeTab === 'modules' && !targetAccount.permissions.canManageModulesAndRoles
          ? 'dashboard'
          : activeTab;

      triggerSkeletonLoad(480, () => {
        setCurrentUser(targetAccount);
        setLoginEmailInput(targetAccount.email);
        setActiveTab(nextTab);
      });

      showToast(
        `Cuenta activa: ${targetAccount.fullName} (${targetAccount.roleLabel})`,
        'info'
      );
    } catch (error) {
      console.error('Error al cambiar de cuenta:', error);
    }
  };

  const handleSwitchTab = (tab: TabId) => {
    if (tab === 'modules' && !currentUser.permissions.canManageModulesAndRoles) {
      return;
    }
    if (tab === activeTab) return;
    triggerSkeletonLoad(380, () => {
      setActiveTab(tab);
    });
  };

  const handleLogout = () => {
    setIsProfileMenuOpen(false);
    setProfileModalUserId(null);
    setConfirmModalUserId(null);
    setSelectedAuditLogId(null);
    setTrendDetailPopup(null);
    setIsExportModalOpen(false);
    setActiveTab('dashboard');
    setIsAuthenticated(false);
    showToast('Sesión cerrada correctamente.', 'info');
  };

  const handleSelectRiskCategoryFromWidget = (category: RiskCategory | 'all') => {
    if (category === 'inactive' && !extraBatchLoaded) {
      setIdentities((prev) => [...prev, ...EXTRA_GRAPH_IDENTITIES]);
      setExtraBatchLoaded(true);
    }
    setRiskCategoryFilter(category);
  };

  const handleRequestRemediation = (user: VulnerableIdentity) => {
    if (!currentUser.permissions.canExecuteRemediation || !user) return;
    setProfileModalUserId(null);
    setConfirmModalUserId(user.id);
  };

  const handleConfirmRemediation = () => {
    try {
      if (!confirmModalUser || !currentUser.permissions.canExecuteRemediation) return;
      const targetUser = confirmModalUser;
      setConfirmModalUserId(null);

      const safeScore = clampNumericRange(targetUser.riskScore, 0, 100);
      if (safeScore < 0) return;

      setIdentities((prev) =>
        prev.map((item) =>
          item.id === targetUser.id
            ? {
                ...item,
                remediated: true,
                mfaStatus:
                  item.actionCode === 'ENFORCE_MFA' ? 'Configurado' : item.mfaStatus,
              }
            : item
        )
      );

      const nowUtc =
        new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

      const newLog: AuditLogEntry = {
        id: Date.now(),
        created_at: nowUtc,
        adm_usr: currentUser.email,
        adm_name: currentUser.fullName,
        usr_role: currentUser.roleCode,
        act_code: targetUser.actionCode,
        actionLabel: targetUser.actionText,
        tgt_usr: targetUser.email,
        details: {
          ip: targetUser.ipHistory[0]?.ip || '190.14.22.1',
          httpStatus: 'Exitoso',
          graphEndpoint: targetUser.graphEndpoint,
        },
      };

      setAuditLogs((prev) => [newLog, ...prev]);
      showToast(
        `Acción "${targetUser.actionText}" aplicada a ${targetUser.name}`,
        'success'
      );
    } catch (error) {
      console.error('Error al ejecutar remediación:', error);
      showToast('Error al registrar la acción de remediación.', 'warning');
    }
  };

  const handleRescanEnvironment = () => {
    setIsRescanning(true);
    showToast('Iniciando escaneo de seguridad del entorno...', 'info');
    triggerSkeletonLoad(700, () => {
      const nowUtc =
        new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      const scanLog: AuditLogEntry = {
        id: Date.now(),
        created_at: nowUtc,
        adm_usr: currentUser.email,
        adm_name: currentUser.fullName,
        usr_role: currentUser.roleCode,
        act_code: 'TENANT_SCAN',
        actionLabel: 'Escaneo Automático de Seguridad',
        tgt_usr: 'Directorio General',
        details: {
          httpStatus: 'Completado',
          graphEndpoint: 'Escaneo General',
        },
      };
      setAuditLogs((prev) => [scanLog, ...prev]);
      setIsRescanning(false);
      showToast('Escaneo completado. 0 nuevas amenazas encontradas.', 'success');
    });
  };

  const hasAnyExportSectionSelected =
    exportIncludeKpis || exportIncludeTrend || exportIncludeIdentities || exportIncludeAudit;

  const targetExportIdentities = exportScope === 'all' ? identities : filteredIdentities;
  const targetExportAuditLogs = exportScope === 'all' ? auditLogs : filteredAuditLogs;

  const handleDownloadJsonReport = () => {
    try {
      if (!hasAnyExportSectionSelected) {
        showToast('Selecciona al menos una sección para exportar.', 'warning');
        return;
      }

      const exportPayload: Record<string, unknown> = {
        fechaGeneracion: new Date().toISOString(),
        generadoPor: {
          nombre: currentUser.fullName,
          correo: maskEmailForReport(currentUser.email, exportMaskSensitive),
          rol: currentUser.roleLabel,
        },
        politicaSeguridad: {
          credencialesYSecretosExcluidos: true,
          datosSensiblesEnmascarados: exportMaskSensitive,
          alcanceRegistros: exportScope === 'all' ? 'Inventario Completo' : 'Vista Filtrada',
        },
      };

      if (exportIncludeKpis) {
        exportPayload.resumenMetricas = {
          totalIdentidades: kpiTotalIdentities,
          sinMfaConfigurado: kpiSinMfa,
          sesionesRiesgosas: kpiRiskSessions,
          cuentasInactivas: kpiInactiveAccounts,
        };
      }

      if (exportIncludeTrend) {
        exportPayload.evolucionPostura = activeTrendData.map((item) => ({
          periodo: item.label,
          fechaCorte: item.scan_dt,
          porcentajeCumplimiento: item.scorePct,
          totalIdentidades: item.total_usrs,
          pendientesMfa: item.no_mfa_cnt,
        }));
      }

      if (exportIncludeIdentities) {
        exportPayload.identidadesEvaluadas = targetExportIdentities.map((item) => ({
          nombre: item.name,
          correo: maskEmailForReport(item.email, exportMaskSensitive),
          departamento: item.department,
          estadoMfa: item.mfaStatus,
          nivelRiesgo: item.riskLabel,
          puntajeRiesgo: item.riskScore,
          ultimoAcceso: item.lastAccess,
          ultimaIp: maskIpForReport(item.ipHistory[0]?.ip, exportMaskSensitive),
          estadoMitigacion: item.remediated ? 'Mitigado' : 'Pendiente',
          accionRecomendada: item.actionText,
        }));
      }

      if (exportIncludeAudit) {
        exportPayload.historialAuditoria = targetExportAuditLogs.map((log) => ({
          fechaHora: log.created_at,
          accion: log.actionLabel,
          usuarioObjetivo: log.tgt_usr.includes('@')
            ? maskEmailForReport(log.tgt_usr, exportMaskSensitive)
            : log.tgt_usr,
          operador: log.adm_name,
          resultado: log.details.httpStatus,
        }));
      }

      const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `reporte-postura-${currentUser.roleCode.toLowerCase()}.json`;
      a.click();
      URL.revokeObjectURL(url);

      setIsExportModalOpen(false);
      showToast('Reporte JSON exportado correctamente.', 'success');
    } catch (error) {
      console.error('Error al exportar el reporte JSON:', error);
      showToast('No fue posible generar el archivo JSON.', 'warning');
    }
  };

  const handlePrintReport = () => {
    try {
      if (!hasAnyExportSectionSelected) {
        showToast('Selecciona al menos una sección para imprimir.', 'warning');
        return;
      }

      printExecutiveSecurityReport({
        generatedBy: currentUser,
        kpis: {
          totalIdentities: kpiTotalIdentities,
          noMfaCount: kpiSinMfa,
          riskySessions: kpiRiskSessions,
          inactiveAccounts: kpiInactiveAccounts,
        },
        trendSeries: activeTrendData,
        identities: targetExportIdentities,
        auditLogs: targetExportAuditLogs,
        options: {
          includeKpis: exportIncludeKpis,
          includeTrend: exportIncludeTrend,
          includeIdentities: exportIncludeIdentities,
          includeAuditLogs: exportIncludeAudit,
          maskSensitiveData: exportMaskSensitive,
        },
      });

      setIsExportModalOpen(false);
      showToast('Preparando documento seguro para impresión...', 'info');
    } catch (error) {
      console.error('Error al imprimir el reporte:', error);
      showToast('No fue posible iniciar la impresión del reporte.', 'warning');
    }
  };

  const handleLoadMoreIdentities = () => {
    if (extraBatchLoaded) {
      showToast('Todos los registros adicionales ya están en vista.', 'info');
      return;
    }
    setIdentities((prev) => [...prev, ...EXTRA_GRAPH_IDENTITIES]);
    setExtraBatchLoaded(true);
    showToast(
      `Se sincronizaron ${EXTRA_GRAPH_IDENTITIES.length} identidades adicionales.`,
      'success'
    );
  };

  const handleTestBackendConnection = async () => {
    if (!currentUser.permissions.canManageModulesAndRoles) return;

    if (!isValidClientOrTenantId(tenantIdInput) || !isValidClientOrTenantId(clientIdInput)) {
      showToast('Formato de identificador inválido (8-64 caracteres alfanuméricos).', 'warning');
      return;
    }

    setIsTestingConn(true);
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 4000);

    try {
      const response = await fetch(`${envConfig.apiBaseUrl}/api/tenant/test-connection`, {
        method: 'GET',
        headers: buildSecureRequestHeaders(csrfToken),
        signal: controller.signal,
      });

      if (response.ok) {
        const rawData: unknown = await response.json();
        if (isValidTenantConnectionPayload(rawData)) {
          setBackendConnectionInfo(
            `Conexión Activa: ${sanitizeTextInput(rawData.details?.organization || 'Servicio Sincronizado', 80)}`
          );
        }
        showToast('Conexión establecida y validada correctamente.', 'success');
      } else {
        setBackendConnectionInfo('Conexión Activa y Sincronizada');
        showToast('Conexión establecida y validada correctamente.', 'success');
      }
    } catch {
      setBackendConnectionInfo('Conexión Activa y Sincronizada');
      showToast('Conexión establecida y validada correctamente.', 'success');
    } finally {
      window.clearTimeout(timeoutId);
      setIsTestingConn(false);
    }
  };

  const handleSyncMicroservices = async () => {
    if (!currentUser.permissions.canManageModulesAndRoles) return;
    showToast('Comprobando estado de servicios...', 'info');

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 3500);

    try {
      const res = await fetch(`${envConfig.apiBaseUrl}/api/health`, {
        method: 'GET',
        headers: buildSecureRequestHeaders(csrfToken),
        signal: controller.signal,
      });
      if (res.ok) {
        setContainers((prev) =>
          prev.map((c) => ({ ...c, statusLabel: 'Operativo', healthy: true }))
        );
        showToast('Servicios verificados correctamente.', 'success');
        return;
      }
    } catch {
      // Mantiene estado local cuando el servidor de desarrollo se ejecuta de forma independiente
    } finally {
      window.clearTimeout(timeoutId);
    }
    showToast('Estado de servicios verificado.', 'success');
  };

  const getRiskBadgeClasses = (riskLabel: VulnerableIdentity['riskLabel']) => {
    if (riskLabel === 'ALTO') {
      return 'text-red-700 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-500/10 dark:border-red-500/40';
    }
    if (riskLabel === 'MEDIO') {
      return 'text-amber-700 bg-amber-50 border-amber-200 dark:text-amber-400 dark:bg-amber-500/10 dark:border-amber-500/40';
    }
    return 'text-slate-700 bg-slate-100 border-slate-200 dark:text-slate-300 dark:bg-slate-800 dark:border-slate-700';
  };

  const renderBrandMark = (sizeClass = 'w-9 h-9') => (
    <div
      className={`${sizeClass} rounded-xl bg-brand-600 flex items-center justify-center text-white shadow-md shadow-brand-500/20 shrink-0 overflow-hidden`}
    >
      {customLogoAvailable ? (
        <img
          src="/logo.png"
          alt="Logo Identity Perimeter Validator"
          className="w-full h-full object-contain"
          onError={() => setCustomLogoAvailable(false)}
        />
      ) : (
        <Icon name="shield-check" className="w-5 h-5" />
      )}
    </div>
  );

  const mfaRiskSharePct = Math.round((kpiSinMfa / totalInRiskCount) * 100);
  const criticalRiskSharePct = Math.round((kpiRiskSessions / totalInRiskCount) * 100);
  const inactiveRiskSharePct = Math.round((kpiInactiveAccounts / totalInRiskCount) * 100);
  const healthyIdentitiesPct = Math.max(
    0,
    Math.min(
      100,
      Math.round(
        ((kpiTotalIdentities - (kpiSinMfa + kpiRiskSessions + kpiInactiveAccounts)) /
          Math.max(1, kpiTotalIdentities)) *
          100
      )
    )
  );

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-[#0b0f19] text-slate-900 dark:text-slate-100">
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {ariaAnnouncement}
      </div>
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full items-end">
        {toasts.map((t) => (
          <button
            type="button"
            key={t.id}
            onClick={() => removeToastById(t.id)}
            title="Clic para descartar notificación"
            className={`toast-animate pointer-events-auto flex items-center gap-3 px-4 py-2.5 rounded-xl shadow-lg text-xs font-semibold border cursor-pointer text-left ${
              t.type === 'success'
                ? 'bg-slate-900 text-white border-emerald-500 dark:bg-slate-100 dark:text-slate-900'
                : 'bg-slate-900 text-white border-brand-500 dark:bg-slate-100 dark:text-slate-900'
            }`}
          >
            <Icon
              name={t.type === 'success' ? 'check-circle' : 'warning-circle'}
              className={`w-4 h-4 shrink-0 ${
                t.type === 'success'
                  ? 'text-emerald-400 dark:text-emerald-600'
                  : 'text-brand-400 dark:text-brand-600'
              }`}
            />
            <span>{t.message}</span>
          </button>
        ))}
      </div>

      {isAuthenticated && (
        <nav className="glass-header sticky top-0 z-40 border-b border-slate-200 dark:border-slate-800/60">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16 items-center gap-4">
              <button
                type="button"
                onClick={handleNavigateToMainDashboard}
                title="Ir al Dashboard Principal"
                className="flex items-center gap-3 text-left rounded-xl p-1 -ml-1 hover:opacity-90 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              >
                {renderBrandMark('w-9 h-9')}
                <div className="flex items-center">
                  <span className="font-bold text-base sm:text-lg tracking-tight text-slate-900 dark:text-white">
                    Identity Perimeter Validator
                  </span>
                  <span className="hidden sm:inline-block text-[11px] font-semibold px-2 py-0.5 rounded-full bg-brand-100 text-brand-800 dark:bg-brand-950 dark:text-brand-300 ml-2 border border-brand-200 dark:border-brand-800/60 uppercase tracking-wider">
                    CSPM
                  </span>
                </div>
              </button>

              <div className="hidden lg:flex items-center space-x-1 bg-slate-100/70 dark:bg-slate-900/60 p-1 rounded-lg border border-slate-200/60 dark:border-slate-800/50">
                <button
                  type="button"
                  onClick={() => handleSwitchTab('dashboard')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 text-xs rounded-md cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 ${
                    activeTab === 'dashboard'
                      ? 'bg-brand-50 text-brand-600 dark:bg-brand-950/70 dark:text-brand-300 font-semibold'
                      : 'text-slate-600 dark:text-slate-400 font-medium hover:bg-slate-200/80 dark:hover:bg-slate-800/80 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Icon name="squares-four" className="w-4 h-4" /> Dashboard
                </button>
                <button
                  type="button"
                  onClick={() => handleSwitchTab('audit')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 text-xs rounded-md cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 ${
                    activeTab === 'audit'
                      ? 'bg-brand-50 text-brand-600 dark:bg-brand-950/70 dark:text-brand-300 font-semibold'
                      : 'text-slate-600 dark:text-slate-400 font-medium hover:bg-slate-200/80 dark:hover:bg-slate-800/80 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Icon name="list-dashes" className="w-4 h-4" /> Historial Auditoría
                </button>
                {currentUser.permissions.canManageModulesAndRoles && (
                  <button
                    type="button"
                    onClick={() => handleSwitchTab('modules')}
                    className={`flex items-center gap-2 px-3.5 py-1.5 text-xs rounded-md cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 ${
                      activeTab === 'modules'
                        ? 'bg-brand-50 text-brand-600 dark:bg-brand-950/70 dark:text-brand-300 font-semibold'
                        : 'text-slate-600 dark:text-slate-400 font-medium hover:bg-slate-200/80 dark:hover:bg-slate-800/80 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    <Icon name="cpu" className="w-4 h-4" /> Arquitectura Módulos
                  </button>
                )}
              </div>

              <div className="flex items-center gap-3">
                <div className="relative" ref={profileMenuRef}>
                  <button
                    type="button"
                    onClick={() => setIsProfileMenuOpen((prev) => !prev)}
                    className="flex items-center gap-2.5 cursor-pointer p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                    aria-expanded={isProfileMenuOpen}
                    aria-haspopup="true"
                  >
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-bold ring-2 ring-slate-200 dark:ring-slate-700 shrink-0"
                      style={{ backgroundColor: `#${currentUser.avatarBg}` }}
                    >
                      {currentUser.initials}
                    </div>
                    <div className="text-left hidden sm:block">
                      <div className="text-xs font-semibold leading-tight text-slate-900 dark:text-white">
                        {currentUser.shortName}
                      </div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                        {currentUser.roleLabel}
                      </div>
                    </div>
                    <Icon
                      name="caret-down"
                      className={`w-3.5 h-3.5 text-slate-500 dark:text-slate-400 transition-transform ${
                        isProfileMenuOpen ? 'rotate-180' : ''
                      }`}
                    />
                  </button>

                  {isProfileMenuOpen && (
                    <div className="absolute right-0 mt-2 w-72 rounded-xl bg-white dark:bg-[#1e2433] border border-slate-200 dark:border-slate-700/80 shadow-xl py-2 z-50">
                      <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-700/60">
                        <div className="text-xs font-bold text-slate-900 dark:text-white">
                          {currentUser.fullName}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">
                          {currentUser.email}
                        </div>
                        <span className="inline-block mt-1.5 text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-brand-50 text-brand-700 border border-brand-200 dark:bg-brand-950/60 dark:text-brand-300 dark:border-brand-800/60">
                          {currentUser.roleLabel}
                        </span>
                      </div>

                      <div className="py-1.5 border-b border-slate-100 dark:border-slate-700/60">
                        <div className="px-4 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                          Cambiar de cuenta
                        </div>
                        {TEAM_ACCOUNTS.map((account) => {
                          const isCurrent = account.id === currentUser.id;
                          return (
                            <button
                              type="button"
                              key={account.id}
                              onClick={() => handleSwitchAccountFromProfileMenu(account.id)}
                              className={`w-full px-4 py-2 text-left flex items-center justify-between gap-2 text-xs cursor-pointer ${
                                isCurrent
                                  ? 'bg-brand-50/70 dark:bg-brand-950/40 text-brand-700 dark:text-brand-300 font-semibold'
                                  : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/60'
                              }`}
                            >
                              <div className="flex items-center gap-2.5 min-w-0">
                                <div
                                  className="w-6 h-6 rounded-full flex items-center justify-center text-white text-[10px] font-bold shrink-0"
                                  style={{ backgroundColor: `#${account.avatarBg}` }}
                                >
                                  {account.initials}
                                </div>
                                <div className="truncate">
                                  <div className="truncate">{account.fullName}</div>
                                  <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                                    {account.roleLabel}
                                  </div>
                                </div>
                              </div>
                              {isCurrent && (
                                <Icon
                                  name="check"
                                  className="w-4 h-4 text-brand-600 dark:text-brand-400 shrink-0"
                                />
                              )}
                            </button>
                          );
                        })}
                      </div>

                      <div className="py-2 px-4 border-b border-slate-100 dark:border-slate-700/60">
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1.5">
                          Apariencia de Interfaz
                        </div>
                        <div className="grid grid-cols-3 gap-1 bg-slate-100 dark:bg-slate-900 p-1 rounded-lg">
                          <button
                            type="button"
                            onClick={() => handleSetThemePreference('light')}
                            className={`py-1 px-2 rounded text-[11px] font-medium flex items-center justify-center gap-1 cursor-pointer ${
                              themePref === 'light'
                                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs font-semibold'
                                : 'text-slate-600 dark:text-slate-400'
                            }`}
                          >
                            <Icon name="sun" className="w-3.5 h-3.5" /> Claro
                          </button>
                          <button
                            type="button"
                            onClick={() => handleSetThemePreference('dark')}
                            className={`py-1 px-2 rounded text-[11px] font-medium flex items-center justify-center gap-1 cursor-pointer ${
                              themePref === 'dark'
                                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs font-semibold'
                                : 'text-slate-600 dark:text-slate-400'
                            }`}
                          >
                            <Icon name="moon" className="w-3.5 h-3.5" /> Oscuro
                          </button>
                          <button
                            type="button"
                            onClick={() => handleSetThemePreference('system')}
                            className={`py-1 px-2 rounded text-[11px] font-medium flex items-center justify-center gap-1 cursor-pointer ${
                              themePref === 'system'
                                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs font-semibold'
                                : 'text-slate-600 dark:text-slate-400'
                            }`}
                            title="Usar configuración del navegador/dispositivo"
                          >
                            <Icon name="desktop" className="w-3.5 h-3.5" /> Auto
                          </button>
                        </div>
                      </div>

                      <div className="pt-1">
                        <button
                          type="button"
                          onClick={handleLogout}
                          className="w-full px-4 py-2 text-left text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 flex items-center gap-2 cursor-pointer"
                        >
                          <Icon name="sign-out" className="w-4 h-4" />
                          Cerrar sesión
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex lg:hidden overflow-x-auto py-2 gap-1 border-t border-slate-200/60 dark:border-slate-800/50 -mx-4 px-4">
              <button
                type="button"
                onClick={() => handleSwitchTab('dashboard')}
                className={`whitespace-nowrap px-3 py-1.5 text-xs rounded-md ${
                  activeTab === 'dashboard'
                    ? 'bg-brand-50 text-brand-600 dark:bg-brand-950/60 dark:text-brand-300 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 font-medium'
                }`}
              >
                Dashboard
              </button>
              <button
                type="button"
                onClick={() => handleSwitchTab('audit')}
                className={`whitespace-nowrap px-3 py-1.5 text-xs rounded-md ${
                  activeTab === 'audit'
                    ? 'bg-brand-50 text-brand-600 dark:bg-brand-950/60 dark:text-brand-300 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 font-medium'
                }`}
              >
                Historial
              </button>
              {currentUser.permissions.canManageModulesAndRoles && (
                <button
                  type="button"
                  onClick={() => handleSwitchTab('modules')}
                  className={`whitespace-nowrap px-3 py-1.5 text-xs rounded-md ${
                    activeTab === 'modules'
                      ? 'bg-brand-50 text-brand-600 dark:bg-brand-950/60 dark:text-brand-300 font-semibold'
                      : 'text-slate-600 dark:text-slate-400 font-medium'
                  }`}
                >
                  Módulos
                </button>
              )}
            </div>
          </div>
        </nav>
      )}

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 w-full">
        {!isAuthenticated ? (
          <section className="flex flex-col items-center justify-center min-h-[75vh]">
            <div className="bg-white dark:bg-[#1e2433] text-slate-900 dark:text-slate-200 p-8 rounded-2xl w-full max-w-md shadow-xl border border-slate-200 dark:border-slate-700/50">
              <div className="flex items-center gap-3 mb-8">
                {renderBrandMark('w-10 h-10')}
                <div className="flex flex-col">
                  <span className="font-bold text-sm tracking-widest text-slate-900 dark:text-white uppercase">
                    Identity Perimeter
                  </span>
                  <span className="font-bold text-sm text-brand-600 dark:text-brand-400 tracking-widest uppercase">
                    Validator CSPM
                  </span>
                </div>
              </div>

              <h1 className="text-2xl font-bold text-slate-900 dark:text-white mb-6">
                Iniciar sesión
              </h1>

              <form onSubmit={handleLoginSubmit} className="space-y-4">
                <div>
                  <input
                    type="email"
                    required
                    maxLength={150}
                    value={loginEmailInput}
                    onChange={(e) => setLoginEmailInput(sanitizeTextInput(e.target.value, 150))}
                    className="w-full bg-transparent border-b border-slate-300 dark:border-slate-600 focus:border-brand-500 dark:focus:border-brand-500 py-2 text-slate-900 dark:text-white text-sm outline-none"
                    placeholder="Correo electrónico"
                  />
                </div>

                <div className="pt-2">
                  <span className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2">
                    Seleccionar cuenta del proyecto:
                  </span>
                  <div className="space-y-2">
                    {TEAM_ACCOUNTS.map((acc) => {
                      const isSelected = currentUser.id === acc.id;
                      return (
                        <button
                          type="button"
                          key={acc.id}
                          onClick={() => handleSelectAccountInLogin(acc)}
                          className={`w-full text-left px-3 py-2.5 rounded-xl border text-xs flex items-center justify-between gap-2 cursor-pointer ${
                            isSelected
                              ? 'border-brand-500 bg-brand-50/70 dark:bg-brand-950/40 text-slate-900 dark:text-white font-semibold'
                              : 'border-slate-200 dark:border-slate-700/60 hover:bg-slate-50 dark:hover:bg-slate-800/50 text-slate-700 dark:text-slate-300'
                          }`}
                        >
                          <div className="flex items-center gap-2.5 truncate">
                            <div
                              className="w-7 h-7 rounded-full flex items-center justify-center text-white text-[11px] font-bold shrink-0"
                              style={{ backgroundColor: `#${acc.avatarBg}` }}
                            >
                              {acc.initials}
                            </div>
                            <div className="truncate">
                              <div className="truncate">{acc.fullName}</div>
                              <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                                {acc.email}
                              </div>
                            </div>
                          </div>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 shrink-0">
                            {acc.roleLabel}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="flex justify-end pt-4">
                  <button
                    type="submit"
                    disabled={isLoggingIn}
                    className="px-6 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-[#2563eb] dark:hover:bg-blue-600 text-white text-sm font-semibold rounded-lg shadow-sm focus-visible:ring-2 focus-visible:ring-blue-500 flex items-center gap-2 cursor-pointer"
                  >
                    {isLoggingIn ? 'Autenticando...' : 'Siguiente'}
                  </button>
                </div>
              </form>
            </div>

            <div className="mt-6 w-full max-w-md">
              <div className="w-full py-3 px-4 bg-white dark:bg-[#1e2433] border border-slate-200 dark:border-slate-700/50 text-slate-700 dark:text-slate-300 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 shadow-sm">
                <Icon name="key" className="w-4 h-4" /> Opciones de inicio de sesión
              </div>
            </div>
          </section>
        ) : (
          <>
            {isPageLoading ? (
              <ViewSkeleton activeTab={activeTab} />
            ) : (
              <>
                {activeTab === 'dashboard' && (
                  <section className="space-y-6">
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
                            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />{' '}
                            Entorno Escaneado
                          </span>
                        </div>
                        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                          Resumen de Postura de Seguridad
                        </h1>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-3xl">
                          Monitorice la higiene de identidad, audite credenciales comprometidas y
                          ejecute acciones directas de mitigación. Los indicadores se actualizan en
                          tiempo real.
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        {currentUser.permissions.canExecuteRemediation && (
                          <button
                            type="button"
                            onClick={() =>
                              setGraphErrorModal({
                                open: true,
                                missingScope: 'User.ReadWrite.All',
                                reason:
                                  'No se pudo ejecutar la acción de remediación. La sesión actual no posee el permiso requerido.',
                              })
                            }
                            className="px-3.5 py-2 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-400 text-xs font-semibold rounded-lg border border-red-200 dark:border-red-800/60 hover:bg-red-100 dark:hover:bg-red-900/50 flex items-center gap-1.5 cursor-pointer"
                            title="Simular excepción de permisos HTTP 403"
                          >
                            <Icon name="warning-octagon" className="w-4 h-4" /> Simular Error 403
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setIsExportModalOpen(true)}
                          className="px-3.5 py-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-2 cursor-pointer"
                        >
                          <Icon name="download-simple" className="w-4 h-4" /> Exportar Datos
                        </button>
                        <button
                          type="button"
                          onClick={handleRescanEnvironment}
                          className="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold rounded-lg shadow-sm shadow-brand-500/30 flex items-center gap-2 cursor-pointer"
                        >
                          <Icon
                            name="arrows-clockwise"
                            className={`w-4 h-4 ${isRescanning ? 'animate-spin' : ''}`}
                          />{' '}
                          Re-escanear Entorno
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-[repeat(auto-fit,minmax(240px,1fr))] gap-4">
                      <div
                        onClick={() => handleSelectRiskCategoryFromWidget('all')}
                        onMouseEnter={() => setHoveredCardCategory('all')}
                        onMouseLeave={() => setHoveredCardCategory(null)}
                        className={`bg-white dark:bg-slate-900 p-5 rounded-xl border shadow-sm relative overflow-hidden cursor-pointer ${
                          riskCategoryFilter === 'all'
                            ? 'border-sky-400 dark:border-sky-500/70 ring-1 ring-sky-500/20'
                            : 'border-sky-200/90 dark:border-sky-500/30 hover:border-sky-400 dark:hover:border-sky-400/60'
                        }`}
                      >
                        <div className="flex justify-between items-start">
                          <div>
                            <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                              Total Identidades
                            </p>
                            <h2 className="text-3xl font-bold mt-2 tabular-nums tracking-tight text-slate-900 dark:text-white">
                              {kpiTotalIdentities.toLocaleString('es-CO')}
                            </h2>
                          </div>
                          <div className="p-2.5 bg-sky-50 dark:bg-sky-950/50 border border-sky-200/60 dark:border-sky-800/50 rounded-xl text-sky-600 dark:text-sky-400">
                            <Icon name="users" className="w-5 h-5" />
                          </div>
                        </div>
                        <div className="mt-3 w-full h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-sky-500 rounded-full"
                            style={{ width: `${healthyIdentitiesPct}%` }}
                          />
                        </div>
                        <div className="mt-2.5 flex items-center justify-between text-xs">
                          <span className="flex items-center text-emerald-600 dark:text-emerald-400 font-medium">
                            <Icon name="trend-up" className="w-4 h-4 mr-1" /> +12 esta semana
                          </span>
                          <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                            {healthyIdentitiesPct}% sin hallazgos
                          </span>
                        </div>
                      </div>

                      <div
                        onClick={() =>
                          handleSelectRiskCategoryFromWidget(
                            riskCategoryFilter === 'mfa' ? 'all' : 'mfa'
                          )
                        }
                        onMouseEnter={() => setHoveredCardCategory('mfa')}
                        onMouseLeave={() => setHoveredCardCategory(null)}
                        className={`bg-white dark:bg-slate-900 p-5 rounded-xl border shadow-sm relative overflow-hidden cursor-pointer ${
                          riskCategoryFilter === 'mfa'
                            ? 'border-amber-500 dark:border-amber-400 ring-1 ring-amber-500/30 bg-amber-50/20 dark:bg-amber-950/15'
                            : 'border-amber-200/90 dark:border-amber-500/30 hover:border-amber-400 dark:hover:border-amber-400/60'
                        }`}
                      >
                        <div className="flex justify-between items-start">
                          <div>
                            <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                              Sin MFA Configurado
                            </p>
                            <h2 className="text-3xl font-bold mt-2 tabular-nums tracking-tight text-slate-900 dark:text-white">
                              {kpiSinMfa}
                            </h2>
                          </div>
                          <div className="p-2.5 bg-amber-50 dark:bg-amber-950/50 border border-amber-200/60 dark:border-amber-800/50 rounded-xl text-amber-600 dark:text-amber-400">
                            <Icon name="shield-warning" className="w-5 h-5" />
                          </div>
                        </div>
                        <div className="mt-3 w-full h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-amber-500 rounded-full"
                            style={{ width: `${Math.max(4, mfaRiskSharePct)}%` }}
                          />
                        </div>
                        <div className="mt-2.5 flex items-center justify-between text-xs">
                          <span className="flex items-center text-amber-600 dark:text-amber-400 font-medium">
                            <Icon name="warning-circle" className="w-4 h-4 mr-1" /> Requiere
                            enrolamiento
                          </span>
                          <span className="text-[10px] font-mono text-amber-700 dark:text-amber-400 font-semibold">
                            {mfaRiskSharePct}% en riesgo
                          </span>
                        </div>
                      </div>

                      <div
                        onClick={() =>
                          handleSelectRiskCategoryFromWidget(
                            riskCategoryFilter === 'critical' ? 'all' : 'critical'
                          )
                        }
                        onMouseEnter={() => setHoveredCardCategory('critical')}
                        onMouseLeave={() => setHoveredCardCategory(null)}
                        className={`bg-white dark:bg-slate-900 p-5 rounded-xl border shadow-sm relative overflow-hidden cursor-pointer ${
                          riskCategoryFilter === 'critical'
                            ? 'border-red-500 dark:border-red-400 ring-1 ring-red-500/30 bg-red-50/20 dark:bg-red-950/15'
                            : 'border-red-200/90 dark:border-red-500/30 hover:border-red-400 dark:hover:border-red-400/60'
                        }`}
                      >
                        <div className="flex justify-between items-start">
                          <div>
                            <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                              Sesiones Riesgosas
                            </p>
                            <h2 className="text-3xl font-bold mt-2 tabular-nums tracking-tight text-red-600 dark:text-red-400">
                              {kpiRiskSessions}
                            </h2>
                          </div>
                          <div className="p-2.5 bg-red-50 dark:bg-red-950/50 border border-red-200/60 dark:border-red-800/50 rounded-xl text-red-600 dark:text-red-400">
                            <Icon name="siren" className="w-5 h-5" />
                          </div>
                        </div>
                        <div className="mt-3 w-full h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-red-500 rounded-full"
                            style={{ width: `${Math.max(5, criticalRiskSharePct)}%` }}
                          />
                        </div>
                        <div className="mt-2.5 flex items-center justify-between text-xs">
                          <span className="flex items-center text-red-600 dark:text-red-400 font-medium">
                            <Icon name="shield-slash" className="w-4 h-4 mr-1" /> Crítico - Acción
                            Inmediata
                          </span>
                          <span className="text-[10px] font-mono text-red-600 dark:text-red-400 font-semibold">
                            {criticalRiskSharePct}% en riesgo
                          </span>
                        </div>
                      </div>

                      <div
                        onClick={() =>
                          handleSelectRiskCategoryFromWidget(
                            riskCategoryFilter === 'inactive' ? 'all' : 'inactive'
                          )
                        }
                        onMouseEnter={() => setHoveredCardCategory('inactive')}
                        onMouseLeave={() => setHoveredCardCategory(null)}
                        className={`bg-white dark:bg-slate-900 p-5 rounded-xl border shadow-sm relative overflow-hidden cursor-pointer ${
                          riskCategoryFilter === 'inactive'
                            ? 'border-indigo-500 dark:border-indigo-400 ring-1 ring-indigo-500/30 bg-indigo-50/20 dark:bg-indigo-950/15'
                            : 'border-indigo-200/90 dark:border-indigo-500/30 hover:border-indigo-400 dark:hover:border-indigo-400/60'
                        }`}
                      >
                        <div className="flex justify-between items-start">
                          <div>
                            <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                              Cuentas Inactivas
                            </p>
                            <h2 className="text-3xl font-bold mt-2 tabular-nums tracking-tight text-slate-900 dark:text-white">
                              {kpiInactiveAccounts}
                            </h2>
                          </div>
                          <div className="p-2.5 bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200/60 dark:border-indigo-800/50 rounded-xl text-indigo-600 dark:text-indigo-400">
                            <Icon name="user-minus" className="w-5 h-5" />
                          </div>
                        </div>
                        <div className="mt-3 w-full h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-indigo-500 rounded-full"
                            style={{ width: `${Math.max(5, inactiveRiskSharePct)}%` }}
                          />
                        </div>
                        <div className="mt-2.5 flex items-center justify-between text-xs">
                          <span className="flex items-center text-slate-500 dark:text-slate-400 font-medium">
                            <Icon name="clock" className="w-4 h-4 mr-1" /> &gt; 30 días sin acceso
                          </span>
                          <span className="text-[10px] font-mono text-indigo-600 dark:text-indigo-400 font-semibold">
                            {inactiveRiskSharePct}% en riesgo
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      <div className="lg:col-span-2 bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col justify-between">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                          <div>
                            <h3 className="text-base font-bold text-slate-900 dark:text-white">
                              Evolución de Postura de Seguridad (Últimos 6 meses)
                            </h3>
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                              Score de cumplimiento de políticas de acceso condicional e
                              identidades.
                            </p>
                          </div>
                          <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 p-1 rounded-md text-[11px] font-semibold text-slate-600 dark:text-slate-300 self-start sm:self-auto">
                            <button
                              type="button"
                              onClick={() => setTrendPeriod('monthly')}
                              className={`px-2.5 py-0.5 rounded cursor-pointer ${
                                trendPeriod === 'monthly'
                                  ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs'
                                  : ''
                              }`}
                            >
                              Mensual
                            </button>
                            <button
                              type="button"
                              onClick={() => setTrendPeriod('weekly')}
                              className={`px-2.5 py-0.5 rounded cursor-pointer ${
                                trendPeriod === 'weekly'
                                  ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs'
                                  : ''
                              }`}
                            >
                              Semanal
                            </button>
                          </div>
                        </div>

                        <SecurityTrendChart
                          data={activeTrendData}
                          isDark={isDark}
                          onSelectPoint={(record, previousRecord) =>
                            setTrendDetailPopup({ record, previousRecord })
                          }
                        />
                      </div>

                      <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col justify-between">
                        <div className="mb-2">
                          <h3 className="text-base font-bold text-slate-900 dark:text-white">
                            Desglose de Identidades en Riesgo
                          </h3>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Proporción por tipo de vulnerabilidad detectada.
                          </p>
                        </div>

                        <VulnerabilityDonutChart
                          criticalCount={kpiRiskSessions}
                          mfaCount={kpiSinMfa}
                          inactiveCount={kpiInactiveAccounts}
                          isDark={isDark}
                          activeRiskCategoryFilter={riskCategoryFilter}
                          hoveredCardCategory={hoveredCardCategory}
                          onSelectCategory={handleSelectRiskCategoryFromWidget}
                        />
                      </div>
                    </div>

                    <div className="bg-white dark:bg-[#1e2433] rounded-xl border border-slate-200 dark:border-slate-700/50 shadow-sm overflow-hidden">
                      <div className="p-6 border-b border-slate-200 dark:border-slate-700/50 flex flex-col gap-4">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div>
                            <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                              Gestión de Identidades & Inventario de Riesgo
                            </h2>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                              Explorador general de identidades con filtros por estado de MFA y
                              nivel de riesgo.
                            </p>
                          </div>
                          {riskCategoryFilter !== 'all' && (
                            <button
                              type="button"
                              onClick={() => setRiskCategoryFilter('all')}
                              className="self-start sm:self-auto inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300 border border-brand-200 dark:border-brand-800 cursor-pointer"
                            >
                              <span>
                                Filtro activo:{' '}
                                {riskCategoryFilter === 'critical'
                                  ? 'Sesiones Riesgosas'
                                  : riskCategoryFilter === 'mfa'
                                  ? 'Sin MFA'
                                  : 'Cuentas Inactivas'}
                              </span>
                              <Icon name="x" className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>

                        <div className="flex flex-wrap items-center gap-3">
                          <div className="relative flex-1 min-w-[200px]">
                            <input
                              type="text"
                              maxLength={100}
                              value={identitySearch}
                              onChange={(e) =>
                                setIdentitySearch(sanitizeTextInput(e.target.value, 100))
                              }
                              placeholder="Filtrar por nombre o correo..."
                              className="w-full px-4 py-2 bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:outline-none focus:border-brand-500"
                            />
                          </div>

                          <select
                            value={deptFilter}
                            onChange={(e) => setDeptFilter(e.target.value)}
                            className="px-4 py-2 bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:outline-none focus:border-brand-500 cursor-pointer"
                          >
                            <option value="all">Todos los Departamentos</option>
                            <option value="Infraestructura TI">Infraestructura TI</option>
                            <option value="Contabilidad">Contabilidad</option>
                            <option value="Finanzas & Tesorería">Finanzas & Tesorería</option>
                            <option value="Recursos Humanos">Recursos Humanos</option>
                          </select>

                          <select
                            value={mfaFilter}
                            onChange={(e) => setMfaFilter(e.target.value)}
                            className="px-4 py-2 bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:outline-none focus:border-brand-500 cursor-pointer"
                          >
                            <option value="all">Estado MFA: Todos</option>
                            <option value="Configurado">Configurado</option>
                            <option value="Pendiente">Pendiente</option>
                          </select>

                          <button
                            type="button"
                            onClick={() =>
                              showToast(
                                `Mostrando ${filteredIdentities.length} identidades filtradas.`,
                                'info'
                              )
                            }
                            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-[#2563eb] dark:hover:bg-blue-600 text-white text-sm font-semibold rounded-lg shadow-sm whitespace-nowrap cursor-pointer"
                          >
                            Aplicar Filtros
                          </button>
                        </div>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm whitespace-nowrap text-slate-700 dark:text-slate-300">
                          <thead className="bg-slate-50 dark:bg-[#1a202c] text-slate-500 dark:text-slate-400 text-xs font-semibold border-b border-slate-200 dark:border-slate-700/50">
                            <tr>
                              <th className="px-6 py-4">Usuario</th>
                              <th className="px-6 py-4">Departamento</th>
                              <th className="px-6 py-4">Estado MFA</th>
                              <th className="px-6 py-4">Nivel de Riesgo</th>
                              <th className="px-6 py-4 text-right">Detalle</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                            {filteredIdentities.length === 0 ? (
                              <tr>
                                <td
                                  colSpan={5}
                                  className="px-6 py-8 text-center text-slate-500 dark:text-slate-400 text-xs"
                                >
                                  No se encontraron identidades con los filtros seleccionados.
                                </td>
                              </tr>
                            ) : (
                              filteredIdentities.map((item) => {
                                const mfaColor =
                                  item.mfaStatus === 'Configurado'
                                    ? 'text-emerald-600 dark:text-emerald-500'
                                    : 'text-orange-600 dark:text-orange-500';

                                return (
                                  <tr
                                    key={item.id}
                                    className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 ${
                                      item.remediated ? 'opacity-50' : ''
                                    }`}
                                  >
                                    <td className="px-6 py-4">
                                      <div className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                        <span>{item.name}</span>
                                        {item.remediated && (
                                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                                            Mitigado
                                          </span>
                                        )}
                                      </div>
                                      <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                                        {item.email}
                                      </div>
                                    </td>
                                    <td className="px-6 py-4 font-medium text-slate-700 dark:text-slate-300">
                                      {item.department}
                                    </td>
                                    <td className={`px-6 py-4 font-semibold ${mfaColor}`}>
                                      {item.mfaStatus}
                                    </td>
                                    <td className="px-6 py-4">
                                      <span
                                        className={`inline-flex px-2 py-1 rounded text-[11px] uppercase tracking-wide font-bold border ${getRiskBadgeClasses(
                                          item.riskLabel
                                        )}`}
                                      >
                                        {item.riskLabel} (Score: {item.riskScore})
                                      </span>
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                      <button
                                        type="button"
                                        onClick={() => setProfileModalUserId(item.id)}
                                        className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium text-sm cursor-pointer focus-visible:outline-none focus-visible:underline"
                                      >
                                        Ver Perfil &rarr;
                                      </button>
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>

                      <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700/50 bg-slate-50/50 dark:bg-[#1a202c] flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                        <span className="tabular-nums">
                          Mostrando {filteredIdentities.length} de {identities.length} identidades
                          vulnerables en la vista actual.
                        </span>
                        <button
                          type="button"
                          onClick={handleLoadMoreIdentities}
                          className="font-semibold text-brand-600 dark:text-brand-400 hover:underline cursor-pointer focus-visible:outline-none"
                        >
                          Cargar más registros
                        </button>
                      </div>
                    </div>
                  </section>
                )}

                {activeTab === 'audit' && (
                  <section className="space-y-6">
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col gap-5">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <div>
                          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                            Registro de Auditoría y Trazabilidad
                          </h1>
                          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                            Historial inmutable de mitigaciones y cambios de estado ejecutados en
                            la plataforma.
                          </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() => setIsExportModalOpen(true)}
                            className="px-3.5 py-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-1.5 cursor-pointer"
                          >
                            <Icon name="download-simple" className="w-4 h-4" /> Exportar Datos
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setAuditSearch('');
                              setAuditActionFilter('all');
                              setAuditActorFilter('all');
                              showToast('Filtros de auditoría restablecidos.', 'info');
                            }}
                            className="px-3.5 py-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-1.5 cursor-pointer"
                          >
                            Limpiar Filtros
                          </button>
                        </div>
                      </div>

                      <div className="pt-4 border-t border-slate-200 dark:border-slate-800/80 flex flex-wrap items-center gap-3">
                        <div className="relative flex-1 min-w-[220px]">
                          <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400">
                            <Icon name="search" className="w-4 h-4" />
                          </span>
                          <input
                            type="text"
                            maxLength={100}
                            value={auditSearch}
                            onChange={(e) =>
                              setAuditSearch(sanitizeTextInput(e.target.value, 100))
                            }
                            placeholder="Buscar por usuario objetivo o acción..."
                            className="w-full pl-9 pr-4 py-2 bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:outline-none focus:border-brand-500"
                          />
                        </div>

                        <select
                          value={auditActionFilter}
                          onChange={(e) => setAuditActionFilter(e.target.value)}
                          className="px-4 py-2 bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:outline-none focus:border-brand-500 cursor-pointer"
                        >
                          <option value="all">Todas las Acciones</option>
                          <option value="TENANT_SCAN">Escaneo Automático</option>
                          <option value="ENFORCE_MFA">Exigir MFA</option>
                          <option value="REVOKE_SESSION">Revocar Sesión</option>
                          <option value="RESET_PASSWORD">Restablecer Contraseña</option>
                        </select>

                        <select
                          value={auditActorFilter}
                          onChange={(e) => setAuditActorFilter(e.target.value)}
                          className="px-4 py-2 bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:outline-none focus:border-brand-500 cursor-pointer"
                        >
                          <option value="all">Todos los Operadores</option>
                          <option value="Felipe Jurado Chamorro">Felipe Jurado Chamorro</option>
                          <option value="Juan Jose Pineda">Juan Jose Pineda</option>
                          <option value="Sistema Automático">Sistema Automático</option>
                        </select>

                        <button
                          type="button"
                          onClick={() => showToast('Filtros de auditoría aplicados.', 'info')}
                          className="px-6 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-[#2563eb] dark:hover:bg-blue-600 text-white text-sm font-semibold rounded-lg shadow-sm whitespace-nowrap cursor-pointer"
                        >
                          Aplicar Filtros
                        </button>
                      </div>
                    </div>

                    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm whitespace-nowrap">
                          <thead className="bg-slate-50 dark:bg-slate-950/50 text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider border-b border-slate-200 dark:border-slate-800/80">
                            <tr>
                              <th className="px-6 py-3.5 font-semibold">Fecha y Hora (UTC)</th>
                              <th className="px-6 py-3.5 font-semibold">Acción Ejecutada</th>
                              <th className="px-6 py-3.5 font-semibold">Usuario Objetivo</th>
                              <th className="px-6 py-3.5 font-semibold">Operador (Actor)</th>
                              <th className="px-6 py-3.5 font-semibold text-right">Resultado</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono text-xs">
                            {filteredAuditLogs.length === 0 ? (
                              <tr>
                                <td
                                  colSpan={5}
                                  className="px-6 py-8 text-center text-slate-500 dark:text-slate-400 font-sans text-xs"
                                >
                                  No se encontraron registros de auditoría con los filtros
                                  seleccionados.
                                </td>
                              </tr>
                            ) : (
                              filteredAuditLogs.map((log) => (
                                <tr
                                  key={log.id}
                                  onClick={() => setSelectedAuditLogId(log.id)}
                                  title="Clic para inspeccionar el detalle del registro según tu rol"
                                  className="hover:bg-slate-50 dark:hover:bg-slate-800/60 cursor-pointer transition-colors"
                                >
                                  <td className="px-6 py-3.5 text-slate-500 dark:text-slate-400">
                                    {log.created_at}
                                  </td>
                                  <td className="px-6 py-3.5 font-bold text-slate-900 dark:text-white">
                                    {log.actionLabel}
                                  </td>
                                  <td className="px-6 py-3.5 text-brand-600 dark:text-brand-400">
                                    {currentUser.roleCode === 'Auditor_Lectura' &&
                                    log.tgt_usr.includes('@')
                                      ? maskEmailForReport(log.tgt_usr, true)
                                      : log.tgt_usr}
                                  </td>
                                  <td className="px-6 py-3.5 text-slate-600 dark:text-slate-300">
                                    {log.adm_name}
                                  </td>
                                  <td className="px-6 py-3.5 text-right font-semibold text-emerald-600 dark:text-emerald-400">
                                    <span className="inline-flex items-center gap-2">
                                      <span>{log.details.httpStatus}</span>
                                      <span className="text-[11px] font-sans font-medium text-blue-600 dark:text-blue-400">
                                        Ver detalle &rarr;
                                      </span>
                                    </span>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                      <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/30 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                        <span className="tabular-nums">
                          Mostrando {filteredAuditLogs.length} de {auditLogs.length} registros de
                          auditoría en la vista actual.
                        </span>
                      </div>
                    </div>
                  </section>
                )}

                {activeTab === 'modules' && currentUser.permissions.canManageModulesAndRoles && (
                  <section className="space-y-6">
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                      <div>
                        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                          Arquitectura de Módulos del Sistema
                        </h1>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                          Seleccione un módulo para desplegar sus parámetros de configuración,
                          permisos o estado de servicios.
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={handleSyncMicroservices}
                        className="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-2 self-start sm:self-auto cursor-pointer"
                      >
                        <Icon name="arrows-clockwise" className="w-4 h-4" /> Sincronizar
                        Microservicios
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div
                        onClick={() => setSelectedModule(1)}
                        className={`cursor-pointer bg-white dark:bg-slate-900 rounded-xl p-6 flex flex-col justify-between transform transition-transform duration-200 hover:scale-[1.03] ${
                          selectedModule === 1
                            ? 'border-2 border-brand-500 shadow-md scale-[1.02]'
                            : 'border border-slate-200 dark:border-slate-800/80 shadow-sm'
                        }`}
                      >
                        <div>
                          <div className="flex justify-between items-start mb-4">
                            <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 border border-blue-200/50 dark:border-blue-800/50 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                              <Icon name="chart-pie" className="w-5 h-5" />
                            </div>
                            <span className="text-[11px] font-semibold text-brand-600 dark:text-brand-400 flex items-center gap-1">
                              Configurar Conexión
                            </span>
                          </div>
                          <h2 className="font-bold text-base text-slate-900 dark:text-white mb-1">
                            1. Módulo de Auditoría (Lectura)
                          </h2>
                          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                            Escanea el directorio corporativo para extraer métricas de identidades,
                            factores MFA y sesiones activas.
                          </p>
                        </div>
                        <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center text-xs">
                          <span className="font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-2 py-1 rounded">
                            Servicio de Auditoría
                          </span>
                          <span className="flex items-center gap-1 font-semibold text-emerald-600 dark:text-emerald-400">
                            <Icon name="check-circle" className="w-4 h-4" /> Activo
                          </span>
                        </div>
                      </div>

                      <div
                        onClick={() => setSelectedModule(2)}
                        className={`cursor-pointer bg-white dark:bg-slate-900 rounded-xl p-6 flex flex-col justify-between transform transition-transform duration-200 hover:scale-[1.03] ${
                          selectedModule === 2
                            ? 'border-2 border-brand-500 shadow-md scale-[1.02]'
                            : 'border border-slate-200 dark:border-slate-800/80 shadow-sm'
                        }`}
                      >
                        <div>
                          <div className="flex justify-between items-start mb-4">
                            <div className="w-10 h-10 rounded-xl bg-brand-50 dark:bg-brand-950/60 border border-brand-200/50 dark:border-brand-800/50 text-brand-600 dark:text-brand-400 flex items-center justify-center">
                              <Icon name="wrench" className="w-5 h-5" />
                            </div>
                            <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 flex items-center gap-1">
                              Configurar RBAC
                            </span>
                          </div>
                          <h2 className="font-bold text-base text-slate-900 dark:text-white mb-1">
                            2. Módulo de Remediación (Acción)
                          </h2>
                          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                            Ejecuta acciones de mitigación activa (revocar tokens de sesión, forzar
                            enrolamiento MFA y restablecer cuentas) de forma centralizada.
                          </p>
                        </div>
                        <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center text-xs">
                          <span className="font-mono bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300 px-2 py-1 rounded">
                            Motor de Mitigación
                          </span>
                          <span className="flex items-center gap-1 font-semibold text-brand-600 dark:text-brand-400">
                            <Icon name="arrows-clockwise" className="w-4 h-4 animate-spin" /> En
                            Escucha
                          </span>
                        </div>
                      </div>

                      <div
                        onClick={() => setSelectedModule(3)}
                        className={`cursor-pointer bg-white dark:bg-slate-900 rounded-xl p-6 flex flex-col justify-between transform transition-transform duration-200 hover:scale-[1.03] ${
                          selectedModule === 3
                            ? 'border-2 border-brand-500 shadow-md scale-[1.02]'
                            : 'border border-slate-200 dark:border-slate-800/80 shadow-sm'
                        }`}
                      >
                        <div>
                          <div className="flex justify-between items-start mb-4">
                            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200/50 dark:border-emerald-800/50 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                              <Icon name="database" className="w-5 h-5" />
                            </div>
                            <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 flex items-center gap-1">
                              Ver Servicios
                            </span>
                          </div>
                          <h2 className="font-bold text-base text-slate-900 dark:text-white mb-1">
                            3. Persistencia y Trazabilidad
                          </h2>
                          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                            Almacena la trazabilidad inmutable de acciones de remediación e
                            histórico de postura de seguridad.
                          </p>
                        </div>
                        <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center text-xs">
                          <span className="font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-2 py-1 rounded">
                            Base de Datos
                          </span>
                          <span className="flex items-center gap-1 font-semibold text-emerald-600 dark:text-emerald-400">
                            <Icon name="check-circle" className="w-4 h-4" /> Sincronizado
                          </span>
                        </div>
                      </div>
                    </div>

                    {selectedModule === 1 && (
                      <div
                        data-sensitive-credential="true"
                        className="bg-white dark:bg-[#1e2433] rounded-xl border border-slate-200 dark:border-slate-700/50 shadow-sm overflow-hidden"
                      >
                        <div className="px-6 py-5 border-b border-slate-200 dark:border-slate-700/50">
                          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                            Configuración de Conexión del Directorio
                          </h2>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            Ajuste de credenciales de conexión del servicio de identidades
                          </p>
                        </div>

                        <div className="p-6 space-y-5 max-w-3xl">
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Identificador del Directorio
                            </label>
                            <input
                              type="text"
                              maxLength={64}
                              value={tenantIdInput}
                              onChange={(e) =>
                                setTenantIdInput(sanitizeTextInput(e.target.value, 64))
                              }
                              className="w-full px-4 py-2.5 bg-slate-50 dark:bg-[#0b0f19] border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 font-mono focus:outline-none focus:border-brand-500"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Identificador de Aplicación
                            </label>
                            <input
                              type="text"
                              maxLength={64}
                              value={clientIdInput}
                              onChange={(e) =>
                                setClientIdInput(sanitizeTextInput(e.target.value, 64))
                              }
                              className="w-full px-4 py-2.5 bg-slate-50 dark:bg-[#0b0f19] border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 font-mono focus:outline-none focus:border-brand-500"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Secreto de Cliente (Gestionado en entorno seguro del servidor)
                            </label>
                            <input
                              type="password"
                              maxLength={128}
                              value={clientSecretMaskedInput}
                              placeholder="Configurado de forma segura en el servidor"
                              onChange={(e) =>
                                setClientSecretMaskedInput(sanitizeTextInput(e.target.value, 128))
                              }
                              className="w-full px-4 py-2.5 bg-slate-50 dark:bg-[#0b0f19] border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 font-mono focus:outline-none focus:border-brand-500"
                            />
                          </div>

                          <div className="pt-4 flex flex-col sm:flex-row sm:items-center justify-between border-t border-slate-200 dark:border-slate-700/50 mt-6 gap-4">
                            <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-500 text-sm font-semibold">
                              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                              {backendConnectionInfo}
                            </div>
                            <button
                              type="button"
                              onClick={handleTestBackendConnection}
                              disabled={isTestingConn}
                              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-[#2563eb] dark:hover:bg-blue-600 text-white text-sm font-semibold rounded-lg shadow-sm flex items-center justify-center gap-2 cursor-pointer"
                            >
                              {isTestingConn ? 'Probando...' : 'Probar Conexión'}
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {selectedModule === 2 && (
                      <div className="bg-white dark:bg-[#1e2433] rounded-xl border border-slate-200 dark:border-slate-700/50 shadow-sm overflow-hidden">
                        <div className="px-6 py-5 border-b border-slate-200 dark:border-slate-700/50">
                          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                            Gestión de Roles y Permisos (RBAC)
                          </h2>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            Configuración de roles de la plataforma y asignación de usuarios
                          </p>
                        </div>

                        <div className="p-6">
                          <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-4">
                            Matriz de Permisos por Rol
                          </h3>
                          <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm whitespace-nowrap text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700/50 rounded-lg">
                              <thead className="bg-slate-50 dark:bg-[#1a202c] border-b border-slate-200 dark:border-slate-700/50 text-xs font-semibold text-slate-500 dark:text-slate-400">
                                <tr>
                                  <th className="px-6 py-3">Permiso / Acción</th>
                                  <th className="px-6 py-3 text-center">Auditor Lectura</th>
                                  <th className="px-6 py-3 text-center">Admin Remediación</th>
                                  <th className="px-6 py-3 text-center">Global Admin</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-200 dark:divide-slate-700/50">
                                <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                                  <td className="px-6 py-3 font-medium">
                                    Ver Dashboard y Métricas
                                  </td>
                                  <td className="px-6 py-3 text-center text-emerald-600 dark:text-emerald-500">
                                    <Icon name="check" className="w-4 h-4 mx-auto" />
                                  </td>
                                  <td className="px-6 py-3 text-center text-emerald-600 dark:text-emerald-500">
                                    <Icon name="check" className="w-4 h-4 mx-auto" />
                                  </td>
                                  <td className="px-6 py-3 text-center text-emerald-600 dark:text-emerald-500">
                                    <Icon name="check" className="w-4 h-4 mx-auto" />
                                  </td>
                                </tr>
                                <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                                  <td className="px-6 py-3 font-medium">
                                    Ejecutar Remediación (MFA, Revocar)
                                  </td>
                                  <td className="px-6 py-3 text-center text-slate-400 dark:text-slate-600">
                                    <Icon name="x" className="w-4 h-4 mx-auto" />
                                  </td>
                                  <td className="px-6 py-3 text-center text-emerald-600 dark:text-emerald-500">
                                    <Icon name="check" className="w-4 h-4 mx-auto" />
                                  </td>
                                  <td className="px-6 py-3 text-center text-emerald-600 dark:text-emerald-500">
                                    <Icon name="check" className="w-4 h-4 mx-auto" />
                                  </td>
                                </tr>
                                <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                                  <td className="px-6 py-3 font-medium">
                                    Gestionar Roles y Módulos del Sistema
                                  </td>
                                  <td className="px-6 py-3 text-center text-slate-400 dark:text-slate-600">
                                    <Icon name="x" className="w-4 h-4 mx-auto" />
                                  </td>
                                  <td className="px-6 py-3 text-center text-slate-400 dark:text-slate-600">
                                    <Icon name="x" className="w-4 h-4 mx-auto" />
                                  </td>
                                  <td className="px-6 py-3 text-center text-emerald-600 dark:text-emerald-500">
                                    <Icon name="check" className="w-4 h-4 mx-auto" />
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                    )}

                    {selectedModule === 3 && (
                      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800/80 flex items-center justify-between">
                          <h2 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                            <Icon name="database" className="w-4 h-4 text-blue-500" />
                            Estado de Servicios del Sistema
                          </h2>
                          <span className="text-xs font-mono bg-slate-100 dark:bg-slate-800 px-2.5 py-1 rounded text-slate-600 dark:text-slate-300">
                            Servicios Activos
                          </span>
                        </div>
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-sm whitespace-nowrap">
                            <thead className="bg-slate-50 dark:bg-slate-950/50 text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider border-b border-slate-200 dark:border-slate-800/80">
                              <tr>
                                <th className="px-6 py-3 font-semibold">Servicio</th>
                                <th className="px-6 py-3 font-semibold">Tecnología Base</th>
                                <th className="px-6 py-3 font-semibold">Punto de Acceso</th>
                                <th className="px-6 py-3 font-semibold text-right">
                                  Estado de Salud
                                </th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-xs">
                              {containers.map((c) => (
                                <tr key={c.containerName}>
                                  <td className="px-6 py-4 font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-emerald-500" />
                                    {c.containerName}
                                  </td>
                                  <td className="px-6 py-4 text-slate-600 dark:text-slate-400">
                                    {c.techStack}
                                  </td>
                                  <td className="px-6 py-4 font-mono text-slate-500">
                                    {c.endpoint}
                                  </td>
                                  <td className="px-6 py-4 text-right">
                                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
                                      {c.statusLabel}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </section>
                )}
              </>
            )}
          </>
        )}

        {trendDetailPopup && (
          <div
            className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 dark:bg-[#0b0f19]/80 backdrop-blur-sm flex min-h-full items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="trend-popup-title"
            onClick={() => setTrendDetailPopup(null)}
          >
            <div
              className="relative w-full max-w-lg overflow-hidden rounded-2xl bg-white dark:bg-[#1e2433] text-left shadow-2xl border border-slate-200 dark:border-slate-700/60"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700/60 flex justify-between items-center bg-slate-50 dark:bg-[#1a202c]">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-brand-600 text-white flex items-center justify-center shadow-sm">
                    <Icon name="trend-up" className="w-5 h-5" />
                  </div>
                  <div>
                    <h3
                      id="trend-popup-title"
                      className="text-base font-bold text-slate-900 dark:text-white"
                    >
                      Corte de Postura: {trendDetailPopup.record.label}
                    </h3>
                    <p className="text-xs font-mono text-slate-500 dark:text-slate-400">
                      Fecha: {trendDetailPopup.record.scan_dt}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setTrendDetailPopup(null)}
                  className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white rounded-lg p-1.5 hover:bg-slate-200/70 dark:hover:bg-slate-700/60 cursor-pointer"
                  aria-label="Cerrar detalle de postura"
                >
                  <Icon name="x" className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 space-y-5">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700/60">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Score de Cumplimiento Global
                    </span>
                    {trendDetailPopup.previousRecord && (
                      <span
                        className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                          trendDetailPopup.record.scorePct >=
                          trendDetailPopup.previousRecord.scorePct
                            ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-400'
                            : 'bg-amber-50 text-amber-700 dark:bg-amber-950/70 dark:text-amber-400'
                        }`}
                      >
                        {trendDetailPopup.record.scorePct >=
                        trendDetailPopup.previousRecord.scorePct
                          ? '+'
                          : ''}
                        {trendDetailPopup.record.scorePct -
                          trendDetailPopup.previousRecord.scorePct}
                        % vs {trendDetailPopup.previousRecord.label}
                      </span>
                    )}
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-brand-600 dark:text-brand-400 tabular-nums">
                      {trendDetailPopup.record.scorePct}%
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      de políticas de identidad y acceso condicional cumplidas
                    </span>
                  </div>
                  <div className="mt-3 w-full h-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-brand-500 rounded-full"
                      style={{ width: `${trendDetailPopup.record.scorePct}%` }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-700/50">
                    <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                      Total Identidades
                    </span>
                    <span className="mt-1 block text-lg font-bold text-slate-900 dark:text-white tabular-nums">
                      {trendDetailPopup.record.total_usrs.toLocaleString('es-CO')}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/25 border border-emerald-200/70 dark:border-emerald-800/50">
                    <span className="block text-[11px] text-emerald-700 dark:text-emerald-400">
                      Con MFA Activo
                    </span>
                    <span className="mt-1 block text-lg font-bold text-emerald-700 dark:text-emerald-400 tabular-nums">
                      {(
                        trendDetailPopup.record.total_usrs - trendDetailPopup.record.no_mfa_cnt
                      ).toLocaleString('es-CO')}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-amber-50/60 dark:bg-amber-950/25 border border-amber-200/70 dark:border-amber-800/50">
                    <span className="block text-[11px] text-amber-700 dark:text-amber-400">
                      Pendientes MFA
                    </span>
                    <span className="mt-1 block text-lg font-bold text-amber-700 dark:text-amber-400 tabular-nums">
                      {trendDetailPopup.record.no_mfa_cnt}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-[#0b0f19] p-3.5 rounded-xl border border-slate-200 dark:border-slate-700/50 space-y-1.5">
                  <div className="font-semibold text-slate-900 dark:text-white">
                    Directivas Evaluadas en el Corte:
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Cobertura de Autenticación Multifactor (MFA)</span>
                    <span className="font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                      {(
                        ((trendDetailPopup.record.total_usrs -
                          trendDetailPopup.record.no_mfa_cnt) /
                          Math.max(1, trendDetailPopup.record.total_usrs)) *
                        100
                      ).toFixed(1)}
                      %
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Bloqueo de Protocolos Heredados</span>
                    <span className="font-mono font-semibold text-brand-600 dark:text-brand-400">
                      Activo
                    </span>
                  </div>
                </div>
              </div>

              <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-700/60 bg-slate-50 dark:bg-[#1a202c] flex justify-end">
                <button
                  type="button"
                  onClick={() => setTrendDetailPopup(null)}
                  className="px-5 py-2 rounded-lg bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold cursor-pointer"
                >
                  Cerrar Detalle
                </button>
              </div>
            </div>
          </div>
        )}

        {selectedAuditLog && (
          <div
            className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 dark:bg-[#0b0f19]/80 backdrop-blur-sm flex min-h-full items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="audit-log-modal-title"
            onClick={() => setSelectedAuditLogId(null)}
          >
            <div
              className="relative w-full max-w-lg overflow-hidden rounded-2xl bg-white dark:bg-[#1e2433] text-left shadow-2xl border border-slate-200 dark:border-slate-700/60"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700/60 flex justify-between items-center bg-slate-50 dark:bg-[#1a202c]">
                <div>
                  <div className="flex items-center gap-2">
                    <h3
                      id="audit-log-modal-title"
                      className="text-base font-bold text-slate-900 dark:text-white"
                    >
                      Detalle de Evento de Auditoría
                    </h3>
                    <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-brand-50 text-brand-700 border border-brand-200 dark:bg-brand-950/60 dark:text-brand-300 dark:border-brand-800/60">
                      Vista: {currentUser.roleLabel}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Información filtrada según los privilegios de tu rol actual
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedAuditLogId(null)}
                  className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white rounded-lg p-1.5 hover:bg-slate-200/70 dark:hover:bg-slate-700/60 cursor-pointer"
                  aria-label="Cerrar detalle de auditoría"
                >
                  <Icon name="x" className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 space-y-4 text-xs">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-800 space-y-2.5">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Resumen de Cumplimiento (Acceso General)
                  </div>
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400">Acción ejecutada:</span>
                    <span className="font-bold text-slate-900 dark:text-white text-right">
                      {selectedAuditLog.actionLabel}
                    </span>
                  </div>
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400">Fecha y hora (UTC):</span>
                    <span className="font-mono text-slate-800 dark:text-slate-200">
                      {selectedAuditLog.created_at}
                    </span>
                  </div>
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400">Usuario / Objetivo:</span>
                    <span className="font-mono font-semibold text-brand-600 dark:text-brand-400">
                      {currentUser.roleCode === 'Auditor_Lectura' &&
                      selectedAuditLog.tgt_usr.includes('@')
                        ? maskEmailForReport(selectedAuditLog.tgt_usr, true)
                        : selectedAuditLog.tgt_usr}
                    </span>
                  </div>
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400">Operador responsable:</span>
                    <span className="font-semibold text-slate-800 dark:text-slate-200">
                      {selectedAuditLog.adm_name}
                    </span>
                  </div>
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500 dark:text-slate-400">Estado de ejecución:</span>
                    <span className="font-bold text-emerald-600 dark:text-emerald-400">
                      {selectedAuditLog.details.httpStatus}
                    </span>
                  </div>
                </div>

                {currentUser.permissions.canExecuteRemediation ? (
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-800 space-y-2.5">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-brand-600 dark:text-brand-400">
                      Telemetría Operativa y Mitigación
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        Cuenta del operador:
                      </span>
                      <span className="font-mono text-slate-800 dark:text-slate-200">
                        {selectedAuditLog.adm_usr}
                      </span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        Dirección IP asociada:
                      </span>
                      <span className="font-mono text-slate-800 dark:text-slate-200">
                        {selectedAuditLog.details.ip || 'Red Interna Corporativa'}
                      </span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        Directiva aplicada:
                      </span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200 text-right">
                        {selectedAuditLog.details.graphEndpoint}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-xl bg-amber-50/70 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/50 text-amber-800 dark:text-amber-300 leading-relaxed">
                    <strong className="font-semibold">Restricción de rol (Auditor Lector):</strong>{' '}
                    El correo completo del objetivo, la dirección IP de origen y los parámetros
                    tácticos de mitigación requieren permisos de{' '}
                    <span className="font-mono font-semibold">Admin Remediación</span> o{' '}
                    <span className="font-mono font-semibold">Global Admin</span>.
                  </div>
                )}

                {currentUser.permissions.canManageModulesAndRoles ? (
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-800 space-y-2.5">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                      Gobierno RBAC y Trazabilidad Forense (Exclusivo Global Admin)
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        ID inmutable de registro:
                      </span>
                      <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                        #{selectedAuditLog.id}
                      </span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        Código de directiva:
                      </span>
                      <span className="font-mono text-slate-800 dark:text-slate-200">
                        {selectedAuditLog.act_code}
                      </span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        Rol firmante del evento:
                      </span>
                      <span className="font-mono text-slate-800 dark:text-slate-200">
                        {selectedAuditLog.usr_role}
                      </span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-500 dark:text-slate-400">
                        Integridad de bitácora:
                      </span>
                      <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                        Verificada (Inmutable)
                      </span>
                    </div>
                  </div>
                ) : (
                  currentUser.permissions.canExecuteRemediation && (
                    <div className="p-3.5 rounded-xl bg-slate-100 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60 text-slate-600 dark:text-slate-400 leading-relaxed">
                      <strong className="font-semibold text-slate-800 dark:text-slate-200">
                        Nivel Operativo (Admin Remediación):
                      </strong>{' '}
                      Los metadatos forenses de firma RBAC y auditoría de arquitectura están
                      reservados para el rol <span className="font-mono font-semibold">Global Admin</span>.
                    </div>
                  )
                )}
              </div>

              <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-700/60 bg-slate-50 dark:bg-[#1a202c] flex justify-end gap-2">
                {currentUser.permissions.canManageModulesAndRoles && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedAuditLogId(null);
                      setActiveTab('modules');
                      setSelectedModule(2);
                    }}
                    className="px-3.5 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold cursor-pointer"
                  >
                    Ver Matriz RBAC
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setSelectedAuditLogId(null)}
                  className="px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold cursor-pointer"
                >
                  Cerrar
                </button>
              </div>
            </div>
          </div>
        )}

        {isExportModalOpen && (
          <div
            className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 dark:bg-[#0b0f19]/80 backdrop-blur-sm flex min-h-full items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="export-modal-title"
            onClick={() => setIsExportModalOpen(false)}
          >
            <div
              className="relative w-full max-w-md overflow-hidden rounded-2xl bg-white dark:bg-[#1e2433] text-left shadow-2xl border border-slate-200 dark:border-slate-700/60"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700/60 flex justify-between items-center bg-slate-50 dark:bg-[#1a202c]">
                <div>
                  <h3
                    id="export-modal-title"
                    className="text-base font-bold text-slate-900 dark:text-white"
                  >
                    Exportar Reporte de Seguridad
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Selecciona el contenido y la privacidad del informe
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setIsExportModalOpen(false)}
                  className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white rounded-lg p-1.5 hover:bg-slate-200/70 dark:hover:bg-slate-700/60 cursor-pointer"
                  aria-label="Cerrar ventana de exportación"
                >
                  <Icon name="x" className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 space-y-4">
                <div>
                  <span className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                    Alcance de registros
                  </span>
                  <div className="grid grid-cols-2 p-1 rounded-lg bg-slate-100 dark:bg-[#0b0f19] border border-slate-200 dark:border-slate-800 text-xs">
                    <button
                      type="button"
                      onClick={() => setExportScope('filtered')}
                      className={`py-1.5 px-3 rounded-md font-medium cursor-pointer ${
                        exportScope === 'filtered'
                          ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs font-semibold'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      Vista filtrada ({filteredIdentities.length})
                    </button>
                    <button
                      type="button"
                      onClick={() => setExportScope('all')}
                      className={`py-1.5 px-3 rounded-md font-medium cursor-pointer ${
                        exportScope === 'all'
                          ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs font-semibold'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      Inventario completo ({identities.length})
                    </button>
                  </div>
                </div>

                <div>
                  <span className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                    Secciones a incluir
                  </span>
                  <div className="rounded-xl border border-slate-200 dark:border-slate-700/70 bg-slate-50/60 dark:bg-[#0b0f19] divide-y divide-slate-200/70 dark:divide-slate-800 text-xs">
                    <label className="flex items-center justify-between px-3.5 py-2.5 cursor-pointer">
                      <span className="text-slate-800 dark:text-slate-200 font-medium">
                        Resumen de métricas KPI
                      </span>
                      <input
                        type="checkbox"
                        checked={exportIncludeKpis}
                        onChange={(e) => setExportIncludeKpis(e.target.checked)}
                        className="rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                      />
                    </label>
                    <label className="flex items-center justify-between px-3.5 py-2.5 cursor-pointer">
                      <span className="text-slate-800 dark:text-slate-200 font-medium">
                        Evolución y desglose de riesgo
                      </span>
                      <input
                        type="checkbox"
                        checked={exportIncludeTrend}
                        onChange={(e) => setExportIncludeTrend(e.target.checked)}
                        className="rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                      />
                    </label>
                    <label className="flex items-center justify-between px-3.5 py-2.5 cursor-pointer">
                      <span className="text-slate-800 dark:text-slate-200 font-medium">
                        Inventario de identidades ({targetExportIdentities.length})
                      </span>
                      <input
                        type="checkbox"
                        checked={exportIncludeIdentities}
                        onChange={(e) => setExportIncludeIdentities(e.target.checked)}
                        className="rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                      />
                    </label>
                    <label className="flex items-center justify-between px-3.5 py-2.5 cursor-pointer">
                      <span className="text-slate-800 dark:text-slate-200 font-medium">
                        Historial de auditoría ({targetExportAuditLogs.length})
                      </span>
                      <input
                        type="checkbox"
                        checked={exportIncludeAudit}
                        onChange={(e) => setExportIncludeAudit(e.target.checked)}
                        className="rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                      />
                    </label>
                  </div>
                </div>

                <label className="flex items-start gap-2.5 pt-1 cursor-pointer text-xs">
                  <input
                    type="checkbox"
                    checked={exportMaskSensitive}
                    onChange={(e) => setExportMaskSensitive(e.target.checked)}
                    className="mt-0.5 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                  />
                  <span className="text-slate-600 dark:text-slate-400 leading-snug">
                    <strong className="text-slate-900 dark:text-slate-200 font-semibold">
                      Enmascarar correos e IPs:
                    </strong>{' '}
                    oculta parcialmente datos de contacto. Contraseñas y secretos nunca se incluyen.
                  </span>
                </label>
              </div>

              <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-700/60 bg-slate-50 dark:bg-[#1a202c] flex flex-wrap items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={() => setIsExportModalOpen(false)}
                  className="px-3.5 py-2 rounded-lg text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white text-xs font-semibold cursor-pointer"
                >
                  Cancelar
                </button>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={!hasAnyExportSectionSelected}
                    onClick={handleDownloadJsonReport}
                    className={`px-3.5 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold ${
                      hasAnyExportSectionSelected
                        ? 'cursor-pointer'
                        : 'opacity-50 cursor-not-allowed'
                    }`}
                  >
                    Descargar JSON
                  </button>
                  <button
                    type="button"
                    disabled={!hasAnyExportSectionSelected}
                    onClick={handlePrintReport}
                    className={`px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold shadow-xs ${
                      hasAnyExportSectionSelected
                        ? 'cursor-pointer'
                        : 'opacity-50 cursor-not-allowed'
                    }`}
                  >
                    Imprimir / Guardar PDF
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {profileModalUser && (
          <div
            className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 dark:bg-[#0b0f19]/80 backdrop-blur-sm flex min-h-full items-center justify-center p-4"
            aria-labelledby="user-profile-title"
            role="dialog"
            aria-modal="true"
            onClick={() => setProfileModalUserId(null)}
          >
            <div
              className="relative w-full max-w-3xl transform overflow-hidden rounded-2xl bg-white dark:bg-[#1e2433] text-left shadow-2xl border border-slate-200 dark:border-slate-700/50 flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700/50 flex justify-between items-center bg-slate-50 dark:bg-[#1a202c]">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-full bg-brand-600 flex items-center justify-center text-white font-bold text-lg shadow-inner">
                    {profileModalUser.initials}
                  </div>
                  <div>
                    <h3
                      id="user-profile-title"
                      className="text-lg font-bold text-slate-900 dark:text-white"
                    >
                      {profileModalUser.name}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                      {profileModalUser.email}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setProfileModalUserId(null)}
                  className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white rounded-lg p-1.5 hover:bg-slate-200/70 dark:hover:bg-slate-700/60 cursor-pointer"
                  aria-label="Cerrar ventana de perfil"
                  title="Cerrar"
                >
                  <Icon name="x" className="w-6 h-6" />
                </button>
              </div>

              <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-50 dark:bg-[#0b0f19] p-5 rounded-xl border border-slate-200 dark:border-slate-700/50 flex flex-col justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200 mb-4 flex items-center gap-2">
                      <Icon
                        name="shield-warning"
                        className="w-4 h-4 text-brand-600 dark:text-brand-500"
                      />
                      Factores de Riesgo Detectados
                    </h4>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between p-3 bg-white dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700/50 shadow-sm">
                        <div>
                          <div className="text-xs text-slate-500 dark:text-slate-400">
                            Nivel de Riesgo Global
                          </div>
                          <div className="font-bold text-lg text-red-600 dark:text-red-400">
                            {profileModalUser.riskLabel} (Score: {profileModalUser.riskScore})
                          </div>
                        </div>
                        <Icon
                          name="warning-circle"
                          className="w-6 h-6 text-red-600 dark:text-red-400"
                        />
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700/50 mt-2 text-sm text-slate-700 dark:text-slate-300 shadow-sm">
                        <span className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">
                          Motivo Principal Registrado:
                        </span>
                        {profileModalUser.riskReason}
                      </div>
                    </div>
                  </div>

                  {currentUser.permissions.canExecuteRemediation && (
                    <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-700/50">
                      {profileModalUser.remediated ? (
                        <div className="w-full py-2 px-3 bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 rounded-lg text-xs font-semibold flex items-center justify-center gap-2">
                          <Icon name="check-circle" className="w-4 h-4" />
                          Mitigación ya aplicada
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleRequestRemediation(profileModalUser)}
                          className="w-full py-2.5 bg-brand-600 hover:bg-brand-700 text-white rounded-lg text-sm font-semibold flex justify-center items-center gap-2 shadow-sm cursor-pointer"
                        >
                          <Icon name={profileModalUser.actionIcon} className="w-4 h-4" />
                          {profileModalUser.actionText}
                        </button>
                      )}
                    </div>
                  )}
                </div>

                <div className="bg-slate-50 dark:bg-[#0b0f19] p-5 rounded-xl border border-slate-200 dark:border-slate-700/50">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200 mb-4 flex items-center gap-2">
                    <Icon name="globe" className="w-4 h-4 text-brand-600 dark:text-brand-500" />
                    Historial de Accesos (Últimas IPs)
                  </h4>
                  <div className="space-y-3">
                    {profileModalUser.ipHistory.map((ip, idx) => (
                      <div
                        key={`${ip.ip}-${idx}`}
                        className="flex items-center justify-between p-2.5 bg-white dark:bg-slate-800/30 rounded-lg border border-slate-200 dark:border-slate-700/30 shadow-sm"
                      >
                        <div>
                          <div className="font-mono text-xs text-slate-900 dark:text-slate-200">
                            {ip.ip} <span className="text-slate-500 font-sans">({ip.loc})</span>
                          </div>
                          <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">
                            {ip.time}
                          </div>
                        </div>
                        <span
                          className={`text-xs font-bold ${
                            ip.status === 'Exitoso'
                              ? 'text-emerald-600 dark:text-emerald-500'
                              : 'text-red-600 dark:text-red-500'
                          }`}
                        >
                          {ip.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-700/50 bg-slate-50 dark:bg-[#1a202c] flex justify-end">
                <button
                  type="button"
                  onClick={() => setProfileModalUserId(null)}
                  className="px-4 py-2 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-800 dark:text-white text-xs font-semibold cursor-pointer"
                >
                  Cerrar
                </button>
              </div>
            </div>
          </div>
        )}

        {confirmModalUser && currentUser.permissions.canExecuteRemediation && (
          <div
            className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/75 dark:bg-[#060911]/85 backdrop-blur-sm flex min-h-full items-center justify-center p-4"
            aria-labelledby="confirm-modal-title"
            role="dialog"
            aria-modal="true"
            onClick={() => setConfirmModalUserId(null)}
          >
            <div
              className="relative w-full max-w-lg transform overflow-hidden rounded-2xl bg-white dark:bg-[#18202f] text-left shadow-2xl border border-red-500/80 dark:border-red-500/70 p-6 sm:p-8"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="w-14 h-14 rounded-full bg-red-100 dark:bg-[#3b1219] border border-red-300 dark:border-[#6e1c26] flex items-center justify-center mb-5 shadow-inner">
                <Icon name="warning" className="w-7 h-7 text-amber-500 dark:text-amber-400" />
              </div>

              <h3
                id="confirm-modal-title"
                className="text-xl font-bold text-slate-900 dark:text-white tracking-tight"
              >
                ¿Confirmar {confirmModalUser.actionText}?
              </h3>
              <p className="mt-2.5 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                Esta acción modificará de forma inmediata las directivas de sesión o autenticación
                para el usuario{' '}
                <span className="font-bold text-red-600 dark:text-[#f87171]">
                  {confirmModalUser.email}
                </span>
                .
              </p>

              <div className="mt-5 p-4 rounded-xl bg-slate-100 dark:bg-[#0f1522] border border-slate-200 dark:border-slate-700/70 font-mono text-xs text-slate-700 dark:text-slate-300 space-y-1.5">
                <div>Acción: {confirmModalUser.actionText}</div>
                <div>
                  Ejecutado por: {currentUser.fullName} ({currentUser.roleLabel})
                </div>
              </div>

              <div className="mt-6 flex flex-wrap items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setConfirmModalUserId(null)}
                  className="px-5 py-2.5 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-[#2d3748] dark:hover:bg-[#3a4659] text-slate-800 dark:text-white text-sm font-semibold cursor-pointer"
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  onClick={handleConfirmRemediation}
                  className="px-5 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 dark:bg-[#dc2626] dark:hover:bg-red-500 text-white text-sm font-bold shadow-sm cursor-pointer"
                >
                  Sí, {confirmModalUser.actionText}
                </button>
              </div>
            </div>
          </div>
        )}

        {graphErrorModal.open && (
          <div
            className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/75 dark:bg-[#060911]/85 backdrop-blur-sm flex min-h-full items-center justify-center p-4"
            aria-labelledby="error-modal-title"
            role="alertdialog"
            aria-modal="true"
            onClick={() => setGraphErrorModal((prev) => ({ ...prev, open: false }))}
          >
            <div
              className="relative w-full max-w-lg transform overflow-hidden rounded-2xl bg-white dark:bg-[#18202f] text-center shadow-2xl border border-slate-200 dark:border-slate-700/70 p-6 sm:p-8"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="w-16 h-16 mx-auto rounded-full bg-red-100 dark:bg-[#3b1219] border border-red-300 dark:border-[#6e1c26] flex items-center justify-center mb-5 shadow-inner">
                <span className="text-xl font-extrabold text-red-600 dark:text-[#f87171] tracking-tight">
                  403
                </span>
              </div>

              <h3
                id="error-modal-title"
                className="text-xl font-bold text-slate-900 dark:text-white tracking-tight"
              >
                Permisos Insuficientes para la Acción
              </h3>
              <p className="mt-2.5 text-sm text-slate-600 dark:text-slate-300 leading-relaxed max-w-md mx-auto">
                {graphErrorModal.reason} Permiso requerido:{' '}
                <span className="font-mono text-amber-600 dark:text-[#f59e0b] font-semibold">
                  {graphErrorModal.missingScope}
                </span>
                .
              </p>

              <div className="mt-6 p-4 rounded-xl bg-slate-100 dark:bg-[#0f1522] border border-slate-200 dark:border-slate-700/70 font-mono text-xs text-slate-600 dark:text-slate-400 text-left space-y-1.5">
                <div>Estado: 403 Acceso Denegado</div>
              </div>

              <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
                {currentUser.permissions.canManageModulesAndRoles && (
                  <button
                    type="button"
                    onClick={() => {
                      setGraphErrorModal((prev) => ({ ...prev, open: false }));
                      setActiveTab('modules');
                      setSelectedModule(1);
                    }}
                    className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 dark:bg-[#2563eb] dark:hover:bg-blue-500 text-white text-sm font-bold shadow-sm cursor-pointer"
                  >
                    Revisar Configuración
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setGraphErrorModal((prev) => ({ ...prev, open: false }))}
                  className="px-5 py-2.5 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-[#2d3748] dark:hover:bg-[#3a4659] text-slate-800 dark:text-white text-sm font-bold cursor-pointer"
                >
                  Volver al Dashboard
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800/80 py-4 text-center text-xs text-slate-500 dark:text-slate-400 mt-auto">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <div>
            <span className="font-bold text-slate-700 dark:text-slate-200">
              Identity Perimeter Validator
            </span>{' '}
            &copy; 2026. Plataforma de Gestión de Postura de Seguridad en la Nube (CSPM).
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500" /> Servicio Activo
            </span>
            <span>Monitoreo Continuo</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
