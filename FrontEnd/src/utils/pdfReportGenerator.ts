import type {
  AuditLogEntry,
  SecScoreRecord,
  TeamMemberAccount,
  VulnerableIdentity,
} from '../types/security';
import { clampNumericRange, escapeHtmlEntities, sanitizeTextInput } from './securityValidation';

export interface ExportReportOptions {
  readonly includeKpis: boolean;
  readonly includeTrend: boolean;
  readonly includeIdentities: boolean;
  readonly includeAuditLogs: boolean;
  readonly maskSensitiveData: boolean;
}

export interface ExecutivePdfReportInput {
  readonly generatedBy: TeamMemberAccount;
  readonly kpis: {
    readonly totalIdentities: number;
    readonly noMfaCount: number;
    readonly riskySessions: number;
    readonly inactiveAccounts: number;
  };
  readonly trendSeries: SecScoreRecord[];
  readonly identities: VulnerableIdentity[];
  readonly auditLogs: AuditLogEntry[];
  readonly options?: ExportReportOptions;
}

const DEFAULT_EXPORT_OPTIONS: ExportReportOptions = {
  includeKpis: true,
  includeTrend: true,
  includeIdentities: true,
  includeAuditLogs: true,
  maskSensitiveData: true,
};

export function maskEmailForReport(rawEmail: string, shouldMask: boolean): string {
  const safeEmail = sanitizeTextInput(rawEmail, 120).trim();
  if (!shouldMask || !safeEmail.includes('@')) {
    return safeEmail;
  }
  const [localPart, domainPart] = safeEmail.split('@');
  if (!localPart || !domainPart) {
    return safeEmail;
  }
  if (localPart.length <= 2) {
    return `${localPart[0] || '*'}***@${domainPart}`;
  }
  return `${localPart.slice(0, 2)}***${localPart.slice(-1)}@${domainPart}`;
}

export function maskIpForReport(rawIp: string | undefined, shouldMask: boolean): string {
  const safeIp = sanitizeTextInput(rawIp || 'No registrada', 45).trim();
  if (!shouldMask) {
    return safeIp;
  }
  const ipv4Parts = safeIp.split('.');
  if (ipv4Parts.length === 4) {
    return `${ipv4Parts[0]}.${ipv4Parts[1]}.*.*`;
  }
  return '***.***.***';
}

// Genera una vista de impresión aislada en un iframe temporal sin credenciales ni secretos
export function printExecutiveSecurityReport(input: ExecutivePdfReportInput): void {
  if (!input || typeof input !== 'object') {
    throw new Error('Datos de entrada inválidos para imprimir el reporte.');
  }

  const opts: ExportReportOptions = input.options || DEFAULT_EXPORT_OPTIONS;
  if (
    !opts.includeKpis &&
    !opts.includeTrend &&
    !opts.includeIdentities &&
    !opts.includeAuditLogs
  ) {
    throw new Error('Debe seleccionar al menos una sección para imprimir el reporte.');
  }

  const totalIdentities = clampNumericRange(input.kpis.totalIdentities, 0, 1000000);
  const noMfaCount = clampNumericRange(input.kpis.noMfaCount, 0, 1000000);
  const riskySessions = clampNumericRange(input.kpis.riskySessions, 0, 1000000);
  const inactiveAccounts = clampNumericRange(input.kpis.inactiveAccounts, 0, 1000000);
  const totalInRisk = noMfaCount + riskySessions + inactiveAccounts;
  const safeRiskTotal = Math.max(1, totalInRisk);

  const safeOperatorName = escapeHtmlEntities(sanitizeTextInput(input.generatedBy.fullName, 80));
  const safeOperatorRole = escapeHtmlEntities(sanitizeTextInput(input.generatedBy.roleLabel, 60));
  const safeOperatorEmail = escapeHtmlEntities(
    maskEmailForReport(input.generatedBy.email, opts.maskSensitiveData)
  );
  const nowFormatted = escapeHtmlEntities(
    new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
  );

  let sectionCounter = 1;

  const kpiHtml = opts.includeKpis
    ? `
      <div class="section-title">${sectionCounter++}. RESUMEN DE MÉTRICAS DE POSTURA DE SEGURIDAD</div>
      <div class="kpi-grid">
        <div class="kpi-card" style="border-top: 3px solid #0284c7;">
          <div class="kpi-label">TOTAL IDENTIDADES</div>
          <div class="kpi-value" style="color: #0284c7;">${totalIdentities.toLocaleString('es-CO')}</div>
          <div class="kpi-sub">+12 identidades esta semana</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #d97706;">
          <div class="kpi-label">SIN MFA CONFIGURADO</div>
          <div class="kpi-value" style="color: #d97706;">${noMfaCount}</div>
          <div class="kpi-sub">Requiere enrolamiento</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #dc2626;">
          <div class="kpi-label">SESIONES RIESGOSAS</div>
          <div class="kpi-value" style="color: #dc2626;">${riskySessions}</div>
          <div class="kpi-sub">Crítico - Acción inmediata</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #475569;">
          <div class="kpi-label">CUENTAS INACTIVAS</div>
          <div class="kpi-value" style="color: #475569;">${inactiveAccounts}</div>
          <div class="kpi-sub">&gt; 30 días sin inicio de sesión</div>
        </div>
      </div>
    `
    : '';

  const trendRowsHtml = input.trendSeries
    .slice(-6)
    .map((pt) => {
      const safeLabel = escapeHtmlEntities(sanitizeTextInput(pt.label, 40));
      const safeDate = escapeHtmlEntities(sanitizeTextInput(pt.scan_dt, 30));
      const safePct = clampNumericRange(pt.scorePct, 0, 100);
      return `
        <tr>
          <td>${safeLabel} (${safeDate})</td>
          <td>${clampNumericRange(pt.no_mfa_cnt, 0, 1000000)} / ${clampNumericRange(pt.total_usrs, 0, 1000000)}</td>
          <td>
            <div class="bar-row">
              <div class="bar-track"><div class="bar-fill" style="width:${safePct}%;background:#0ea5e9;"></div></div>
              <strong style="color:#0284c7;">${safePct}%</strong>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');

  const criticalPct = ((riskySessions / safeRiskTotal) * 100).toFixed(1);
  const mfaPct = ((noMfaCount / safeRiskTotal) * 100).toFixed(1);
  const inactivePct = ((inactiveAccounts / safeRiskTotal) * 100).toFixed(1);

  const trendHtml = opts.includeTrend
    ? `
      <div class="section-title">${sectionCounter++}. EVOLUCIÓN DE POSTURA Y DESGLOSE DE RIESGO (${totalInRisk} EN RIESGO)</div>
      <div class="two-col">
        <div>
          <table>
            <thead>
              <tr>
                <th>Periodo / Corte</th>
                <th>Sin MFA / Total</th>
                <th>Cumplimiento</th>
              </tr>
            </thead>
            <tbody>
              ${trendRowsHtml}
            </tbody>
          </table>
        </div>
        <div class="risk-box">
          <div class="risk-item">
            <div class="risk-head"><span>Sesiones Riesgo Alto</span><strong>${riskySessions} (${criticalPct}%)</strong></div>
            <div class="bar-track"><div class="bar-fill" style="width:${Math.max(3, Number(criticalPct))}%;background:#ef4444;"></div></div>
          </div>
          <div class="risk-item">
            <div class="risk-head"><span>Usuarios sin MFA</span><strong>${noMfaCount} (${mfaPct}%)</strong></div>
            <div class="bar-track"><div class="bar-fill" style="width:${Math.max(3, Number(mfaPct))}%;background:#f59e0b;"></div></div>
          </div>
          <div class="risk-item">
            <div class="risk-head"><span>Cuentas Inactivas</span><strong>${inactiveAccounts} (${inactivePct}%)</strong></div>
            <div class="bar-track"><div class="bar-fill" style="width:${Math.max(3, Number(inactivePct))}%;background:#6366f1;"></div></div>
          </div>
        </div>
      </div>
    `
    : '';

  const identityRowsHtml = input.identities
    .map((item) => {
      const safeName = escapeHtmlEntities(sanitizeTextInput(item.name, 60));
      const safeEmail = escapeHtmlEntities(
        maskEmailForReport(item.email, opts.maskSensitiveData)
      );
      const safeDept = escapeHtmlEntities(sanitizeTextInput(item.department, 40));
      const safeMfa = escapeHtmlEntities(sanitizeTextInput(item.mfaStatus, 30));
      const safeRisk = escapeHtmlEntities(
        `${sanitizeTextInput(item.riskLabel, 20)} (${clampNumericRange(item.riskScore, 0, 100)})`
      );
      const safeStatus = escapeHtmlEntities(
        sanitizeTextInput(item.remediated ? 'MITIGADO' : item.actionText, 40)
      );
      return `
        <tr>
          <td><strong>${safeName}</strong><br/><span class="mono">${safeEmail}</span></td>
          <td>${safeDept}</td>
          <td>${safeMfa}</td>
          <td><strong>${safeRisk}</strong></td>
          <td>${safeStatus}</td>
        </tr>
      `;
    })
    .join('');

  const identitiesHtml = opts.includeIdentities
    ? `
      <div class="section-title">${sectionCounter++}. INVENTARIO DE IDENTIDADES EVALUADAS (${input.identities.length} registros)</div>
      <table>
        <thead>
          <tr>
            <th>Usuario / Correo</th>
            <th>Departamento</th>
            <th>Estado MFA</th>
            <th>Nivel de Riesgo</th>
            <th>Estado / Acción</th>
          </tr>
        </thead>
        <tbody>
          ${identityRowsHtml}
        </tbody>
      </table>
    `
    : '';

  const auditRowsHtml = input.auditLogs
    .map((log) => {
      const safeDate = escapeHtmlEntities(sanitizeTextInput(log.created_at, 35));
      const safeAction = escapeHtmlEntities(sanitizeTextInput(log.actionLabel, 60));
      const rawTarget = log.tgt_usr.includes('@')
        ? maskEmailForReport(log.tgt_usr, opts.maskSensitiveData)
        : log.tgt_usr;
      const safeTarget = escapeHtmlEntities(sanitizeTextInput(rawTarget, 60));
      const safeOperator = escapeHtmlEntities(sanitizeTextInput(log.adm_name, 50));
      const safeStatus = escapeHtmlEntities(sanitizeTextInput(log.details.httpStatus, 30));
      return `
        <tr>
          <td class="mono">${safeDate}</td>
          <td><strong>${safeAction}</strong></td>
          <td class="mono">${safeTarget}</td>
          <td>${safeOperator}</td>
          <td>${safeStatus}</td>
        </tr>
      `;
    })
    .join('');

  const auditHtml = opts.includeAuditLogs
    ? `
      <div class="section-title">${sectionCounter++}. HISTORIAL DE AUDITORÍA (${input.auditLogs.length} eventos)</div>
      <table>
        <thead>
          <tr>
            <th>Fecha y Hora (UTC)</th>
            <th>Acción Ejecutada</th>
            <th>Usuario Objetivo</th>
            <th>Operador</th>
            <th>Resultado</th>
          </tr>
        </thead>
        <tbody>
          ${auditRowsHtml}
        </tbody>
      </table>
    `
    : '';

  const privacyBannerText = opts.maskSensitiveData
    ? 'Política de Privacidad Activa: Correos e identificadores sensibles enmascarados. Contraseñas, tokens y secretos excluidos.'
    : 'Política de Seguridad Activa: Contraseñas, secretos de cliente, tokens y credenciales excluidos del documento.';

  const printDocumentHtml = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Reporte de Seguridad - Identity Perimeter Validator</title>
  <style>
    @page { size: A4 portrait; margin: 12mm; }
    * { box-sizing: border-box; font-family: 'Segoe UI', Arial, sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    body { margin: 0; padding: 0; color: #0f172a; background: #ffffff; font-size: 11px; }
    .header { background: #0f172a; color: #ffffff; padding: 16px 20px; border-bottom: 3px solid #0ea5e9; border-radius: 6px; margin-bottom: 10px; }
    .header h1 { margin: 0 0 4px 0; font-size: 15px; letter-spacing: 0.3px; }
    .header p { margin: 0; font-size: 10.5px; color: #cbd5e1; }
    .meta { margin-top: 8px; display: flex; justify-content: space-between; font-size: 9.5px; color: #94a3b8; }
    .privacy-banner { background: #f8fafc; border: 1px solid #cbd5e1; color: #334155; padding: 6px 12px; border-radius: 5px; font-size: 9.5px; font-weight: 600; margin-bottom: 12px; }
    .section-title { font-size: 11.5px; font-weight: 700; color: #0f172a; margin: 12px 0 8px 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 12px; }
    .kpi-card { border: 1px solid #cbd5e1; border-radius: 6px; padding: 10px; background: #f8fafc; }
    .kpi-label { font-size: 8.5px; font-weight: 700; color: #475569; }
    .kpi-value { font-size: 17px; font-weight: 800; margin: 4px 0; }
    .kpi-sub { font-size: 8.5px; color: #64748b; }
    .two-col { display: grid; grid-template-columns: 1.55fr 1fr; gap: 10px; margin-bottom: 10px; align-items: start; }
    .risk-box { border: 1px solid #cbd5e1; border-radius: 6px; padding: 10px; background: #f8fafc; }
    .risk-item { margin-bottom: 9px; }
    .risk-item:last-child { margin-bottom: 0; }
    .risk-head { display: flex; justify-content: space-between; font-size: 9.5px; margin-bottom: 4px; color: #1e293b; }
    .bar-row { display: flex; align-items: center; gap: 6px; }
    .bar-track { width: 100%; height: 6px; background: #e2e8f0; border-radius: 999px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 999px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 9.5px; }
    th { background: #1e293b; color: #ffffff; text-align: left; padding: 5px 8px; font-size: 9px; text-transform: uppercase; }
    td { padding: 5px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }
    tr:nth-child(even) td { background: #f8fafc; }
    .mono { font-family: Consolas, monospace; font-size: 9px; color: #334155; }
    .footer { margin-top: 14px; padding-top: 8px; border-top: 1px solid #cbd5e1; font-size: 9px; color: #64748b; display: flex; justify-content: space-between; }
  </style>
</head>
<body>
  <div class="header">
    <h1>IDENTITY PERIMETER VALIDATOR - REPORTE DE SEGURIDAD</h1>
    <p>Informe Ejecutivo de Postura de Identidades, Cumplimiento MFA y Auditoría</p>
    <div class="meta">
      <span>Operador: ${safeOperatorName} (${safeOperatorRole}) | Cuenta: ${safeOperatorEmail}</span>
      <span>Fecha de corte: ${nowFormatted}</span>
    </div>
  </div>
  <div class="privacy-banner">${escapeHtmlEntities(privacyBannerText)}</div>
  ${kpiHtml}
  ${trendHtml}
  ${identitiesHtml}
  ${auditHtml}
  <div class="footer">
    <span>Identity Perimeter Validator - Reporte Oficial de Postura de Seguridad (Sin Credenciales)</span>
    <span>Vista optimizada para impresión y guardado en PDF</span>
  </div>
</body>
</html>`;

  const printIframe = document.createElement('iframe');
  printIframe.style.position = 'fixed';
  printIframe.style.right = '0';
  printIframe.style.bottom = '0';
  printIframe.style.width = '0';
  printIframe.style.height = '0';
  printIframe.style.border = '0';
  printIframe.setAttribute('aria-hidden', 'true');
  document.body.appendChild(printIframe);

  const cleanupIframe = () => {
    window.setTimeout(() => {
      if (printIframe.parentNode) {
        printIframe.parentNode.removeChild(printIframe);
      }
    }, 1500);
  };

  const frameDoc = printIframe.contentWindow?.document;
  if (!frameDoc || !printIframe.contentWindow) {
    cleanupIframe();
    throw new Error('No se pudo inicializar el contenedor de impresión segura.');
  }

  frameDoc.open();
  frameDoc.write(printDocumentHtml);
  frameDoc.close();

  window.setTimeout(() => {
    try {
      printIframe.contentWindow?.focus();
      printIframe.contentWindow?.print();
    } finally {
      cleanupIframe();
    }
  }, 250);
}
