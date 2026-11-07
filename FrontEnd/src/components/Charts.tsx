import React, { useState } from 'react';
import type { RiskCategory, SecScoreRecord } from '../types/security';

interface SecurityTrendChartProps {
  data: SecScoreRecord[];
  isDark: boolean;
  onSelectPoint?: (record: SecScoreRecord, previousRecord: SecScoreRecord | null) => void;
}

export const SecurityTrendChart: React.FC<SecurityTrendChartProps> = ({
  data,
  isDark,
  onSelectPoint,
}) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  const width = 680;
  const height = 240;
  const padLeft = 44;
  const padRight = 24;
  const padTop = 20;
  const padBottom = 34;

  const plotW = width - padLeft - padRight;
  const plotH = height - padTop - padBottom;

  const minY = 50;
  const maxY = 100;

  const points = data.map((item, idx) => {
    const x =
      data.length > 1
        ? padLeft + (idx / (data.length - 1)) * plotW
        : padLeft + plotW / 2;
    const clampedScore = Math.max(minY, Math.min(maxY, item.scorePct));
    const y = padTop + plotH - ((clampedScore - minY) / (maxY - minY)) * plotH;
    return { x, y, item };
  });

  const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(' ');
  const areaPoints =
    points.length > 0
      ? `${points[0].x},${padTop + plotH} ${polylinePoints} ${points[points.length - 1].x},${padTop + plotH}`
      : '';

  const gridColor = isDark ? '#1e293b' : '#e2e8f0';
  const textColor = isDark ? '#94a3b8' : '#64748b';
  const yTicks = [50, 60, 70, 80, 90, 100];

  const activeIndex = hoveredIdx !== null ? hoveredIdx : selectedIdx;
  const activePoint = activeIndex !== null ? points[activeIndex] : null;

  return (
    <div className="chart-container select-none relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-full overflow-visible"
        role="img"
        aria-label="Gráfico de evolución de postura de seguridad"
      >
        <defs>
          <linearGradient id="scoreAreaGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#0ea5e9" stopOpacity={isDark ? 0.3 : 0.22} />
            <stop offset="100%" stopColor="#0ea5e9" stopOpacity={0.01} />
          </linearGradient>
        </defs>

        {yTicks.map((tick) => {
          const yPos = padTop + plotH - ((tick - minY) / (maxY - minY)) * plotH;
          return (
            <g key={tick}>
              <line
                x1={padLeft}
                y1={yPos}
                x2={width - padRight}
                y2={yPos}
                stroke={gridColor}
                strokeWidth="1"
              />
              <text
                x={padLeft - 8}
                y={yPos + 4}
                textAnchor="end"
                fill={textColor}
                fontSize="11"
                fontFamily="Inter, sans-serif"
              >
                {tick}%
              </text>
            </g>
          );
        })}

        {points.map((p, idx) => {
          const isHighlighted = activeIndex === idx;
          return (
            <g key={p.item.label}>
              <line
                x1={p.x}
                y1={padTop}
                x2={p.x}
                y2={padTop + plotH}
                stroke={isHighlighted ? '#0ea5e9' : gridColor}
                strokeWidth={isHighlighted ? '1.5' : '1'}
                strokeDasharray={isHighlighted ? 'none' : '3 3'}
                opacity={isHighlighted ? 0.7 : 1}
              />
              <text
                x={p.x}
                y={height - 8}
                textAnchor="middle"
                fill={isHighlighted ? (isDark ? '#ffffff' : '#0f172a') : textColor}
                fontSize="11"
                fontFamily="Inter, sans-serif"
                fontWeight={isHighlighted ? '700' : '400'}
              >
                {p.item.label}
              </text>
            </g>
          );
        })}

        {areaPoints && <polygon points={areaPoints} fill="url(#scoreAreaGradient)" />}

        {polylinePoints && (
          <polyline
            fill="none"
            stroke="#0ea5e9"
            strokeWidth="2.75"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={polylinePoints}
          />
        )}

        {points.map((p, idx) => {
          const isHighlighted = activeIndex === idx;
          const prevRecord = idx > 0 ? points[idx - 1].item : null;
          return (
            <g
              key={p.item.label}
              className="cursor-pointer"
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              onClick={() => {
                setSelectedIdx(idx);
                if (onSelectPoint) onSelectPoint(p.item, prevRecord);
              }}
            >
              <circle cx={p.x} cy={p.y} r={22} fill="transparent" />
              {isHighlighted && (
                <circle cx={p.x} cy={p.y} r={11} fill="#0ea5e9" fillOpacity={0.25} />
              )}
              <circle
                cx={p.x}
                cy={p.y}
                r={isHighlighted ? 6.5 : 4.5}
                fill="#0ea5e9"
                stroke={isDark ? '#0f172a' : '#ffffff'}
                strokeWidth="2"
              />
            </g>
          );
        })}
      </svg>

      {activePoint && (
        <div
          className="pointer-events-none absolute z-20 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 shadow-lg text-xs"
          style={{
            left: `${Math.min(74, Math.max(6, (activePoint.x / width) * 100 - 12))}%`,
            top: `${Math.max(2, (activePoint.y / height) * 100 - 22)}%`,
          }}
        >
          <div className="font-bold text-slate-900 dark:text-white">
            {activePoint.item.label} ({activePoint.item.scan_dt})
          </div>
          <div className="text-brand-600 dark:text-brand-400 font-semibold mt-0.5">
            Cumplimiento: {activePoint.item.scorePct}%
          </div>
        </div>
      )}
    </div>
  );
};

interface VulnerabilityDonutChartProps {
  criticalCount: number;
  mfaCount: number;
  inactiveCount: number;
  isDark: boolean;
  activeRiskCategoryFilter: RiskCategory | 'all';
  hoveredCardCategory?: RiskCategory | 'all' | null;
  onSelectCategory: (category: RiskCategory | 'all') => void;
}

export const VulnerabilityDonutChart: React.FC<VulnerabilityDonutChartProps> = ({
  criticalCount,
  mfaCount,
  inactiveCount,
  isDark,
  activeRiskCategoryFilter,
  hoveredCardCategory = null,
  onSelectCategory,
}) => {
  const [hoveredSegment, setHoveredSegment] = useState<number | null>(null);
  const [hiddenSegments, setHiddenSegments] = useState<Record<number, boolean>>({});

  const allSegments: {
    id: number;
    category: RiskCategory;
    label: string;
    shortLabel: string;
    value: number;
    color: string;
    slaText: string;
  }[] = [
    {
      id: 0,
      category: 'critical',
      label: 'Sesiones Riesgo Alto',
      shortLabel: 'Crítico',
      value: criticalCount,
      color: '#ef4444',
      slaText: 'Mitigación inmediata (< 15 min)',
    },
    {
      id: 1,
      category: 'mfa',
      label: 'Usuarios sin MFA',
      shortLabel: 'Sin MFA',
      value: mfaCount,
      color: '#f59e0b',
      slaText: 'Enrolamiento prioritario (< 24h)',
    },
    {
      id: 2,
      category: 'inactive',
      label: 'Cuentas Inactivas',
      shortLabel: 'Inactivo',
      value: inactiveCount,
      color: '#6366f1',
      slaText: 'Revisión periódica (> 30 días)',
    },
  ];

  const visibleSegments = allSegments.filter((seg) => !hiddenSegments[seg.id]);
  const visibleTotal = visibleSegments.reduce((acc, s) => acc + s.value, 0);
  const safeTotal = Math.max(1, visibleTotal);

  const radius = 66;
  const circumference = 2 * Math.PI * radius;
  let accumulatedFraction = 0;

  const toggleLegendSegment = (id: number) => {
    setHiddenSegments((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleSliceClick = (category: RiskCategory) => {
    if (activeRiskCategoryFilter === category) {
      onSelectCategory('all');
    } else {
      onSelectCategory(category);
    }
  };

  // Prioridad de foco visual: segmento bajo cursor > tarjeta KPI bajo cursor > filtro activo
  const effectiveCategory: RiskCategory | 'all' =
    hoveredSegment !== null && !hiddenSegments[hoveredSegment]
      ? allSegments[hoveredSegment].category
      : hoveredCardCategory && hoveredCardCategory !== 'all'
      ? hoveredCardCategory
      : activeRiskCategoryFilter;

  const focusedSegObj =
    effectiveCategory !== 'all'
      ? allSegments.find((s) => s.category === effectiveCategory && !hiddenSegments[s.id]) || null
      : null;

  const focusedPct = focusedSegObj
    ? ((focusedSegObj.value / safeTotal) * 100).toFixed(1)
    : null;

  return (
    <div className="flex flex-col justify-between flex-1 select-none relative">
      <div className="relative flex items-center justify-center h-[195px]">
        <svg
          viewBox="0 0 180 180"
          className="w-44 h-44 -rotate-90 overflow-visible"
          role="img"
          aria-label="Gráfico de proporción de identidades en riesgo"
        >
          {visibleTotal === 0 ? (
            <circle
              cx="90"
              cy="90"
              r={radius}
              fill="transparent"
              stroke={isDark ? '#1e293b' : '#e2e8f0'}
              strokeWidth={18}
            />
          ) : (
            visibleSegments.map((seg) => {
              const fraction = seg.value / safeTotal;
              const dashLength = Math.max(0, fraction * circumference - 1.8);
              const dashOffset = -accumulatedFraction * circumference;
              accumulatedFraction += fraction;

              const isFocused = effectiveCategory === seg.category;

              return (
                <g key={seg.id}>
                  {isFocused && (
                    <circle
                      cx="90"
                      cy="90"
                      r={radius}
                      fill="transparent"
                      stroke={seg.color}
                      strokeWidth={29}
                      strokeDasharray={`${dashLength} ${circumference}`}
                      strokeDashoffset={dashOffset}
                      strokeOpacity={0.22}
                      className="pointer-events-none"
                    />
                  )}
                  <circle
                    cx="90"
                    cy="90"
                    r={radius}
                    fill="transparent"
                    stroke={seg.color}
                    strokeWidth={isFocused ? 24 : 18}
                    strokeDasharray={`${dashLength} ${circumference}`}
                    strokeDashoffset={dashOffset}
                    strokeOpacity={effectiveCategory !== 'all' && !isFocused ? 0.32 : 1}
                    className="transition-[stroke-width,stroke-opacity] duration-200 cursor-pointer"
                    onMouseEnter={() => setHoveredSegment(seg.id)}
                    onMouseLeave={() => setHoveredSegment(null)}
                    onClick={() => handleSliceClick(seg.category)}
                  />
                </g>
              );
            })
          )}
          <circle
            cx="90"
            cy="90"
            r={radius - 12}
            fill={isDark ? '#0f172a' : '#ffffff'}
            className="pointer-events-none"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none px-4">
          {focusedSegObj ? (
            <>
              <span
                className="text-2xl font-extrabold tabular-nums"
                style={{ color: focusedSegObj.color }}
              >
                {focusedSegObj.value}
              </span>
              <span className="text-[10px] font-bold text-slate-700 dark:text-slate-200 leading-tight mt-0.5">
                {focusedSegObj.shortLabel}
              </span>
              <span className="text-[10px] font-mono font-semibold text-slate-500 dark:text-slate-400">
                {focusedPct}%
              </span>
            </>
          ) : (
            <>
              <span className="text-2xl font-extrabold tabular-nums text-slate-900 dark:text-white">
                {visibleTotal}
              </span>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                En Riesgo
              </span>
            </>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[11px] text-slate-600 dark:text-slate-400 mt-1">
        {allSegments.map((seg) => {
          const isHidden = !!hiddenSegments[seg.id];
          return (
            <button
              type="button"
              key={seg.id}
              onClick={() => toggleLegendSegment(seg.id)}
              onMouseEnter={() => !isHidden && setHoveredSegment(seg.id)}
              onMouseLeave={() => setHoveredSegment(null)}
              title="Mostrar u ocultar categoría"
              className={`flex items-center gap-1.5 px-1.5 py-0.5 rounded cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 ${
                isHidden ? 'opacity-45 line-through' : ''
              }`}
            >
              <span
                className="w-2.5 h-2.5 rounded-xs shrink-0"
                style={{ backgroundColor: seg.color }}
              />
              <span>{seg.label}</span>
            </button>
          );
        })}
      </div>

      {focusedSegObj ? (
        <div className="mt-3 p-2.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200/80 dark:border-slate-700/70 text-[11px]">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 font-bold text-slate-900 dark:text-white">
              <span
                className="w-2.5 h-2.5 rounded-full shrink-0"
                style={{ backgroundColor: focusedSegObj.color }}
              />
              <span>{focusedSegObj.label}</span>
            </div>
            {activeRiskCategoryFilter !== 'all' && (
              <button
                type="button"
                onClick={() => onSelectCategory('all')}
                className="text-[10px] font-semibold text-brand-600 dark:text-brand-400 hover:underline cursor-pointer"
              >
                Ver todo ({visibleTotal})
              </button>
            )}
          </div>
          <div className="w-full h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden my-1.5">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.max(4, Number(focusedPct))}%`,
                backgroundColor: focusedSegObj.color,
              }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400">
            <span>{focusedSegObj.slaText}</span>
            <span className="font-mono font-semibold text-slate-700 dark:text-slate-300">
              {focusedSegObj.value} de {visibleTotal} ({focusedPct}%)
            </span>
          </div>
        </div>
      ) : (
        <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex justify-around text-center text-xs">
          {allSegments.map((seg) => {
            const isSelected = activeRiskCategoryFilter === seg.category;
            const textColorClass =
              seg.category === 'critical'
                ? 'text-red-600 dark:text-red-400'
                : seg.category === 'mfa'
                ? 'text-amber-600 dark:text-amber-400'
                : 'text-indigo-600 dark:text-indigo-400';

            return (
              <button
                type="button"
                key={seg.category}
                onClick={() => handleSliceClick(seg.category)}
                onMouseEnter={() => setHoveredSegment(seg.id)}
                onMouseLeave={() => setHoveredSegment(null)}
                title={`Filtrar por ${seg.label}`}
                className={`px-3 py-1 rounded-lg cursor-pointer ${
                  isSelected
                    ? 'bg-slate-100 dark:bg-slate-800 ring-1 ring-brand-500'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                }`}
              >
                <span className={`block font-bold tabular-nums ${textColorClass}`}>
                  {seg.value}
                </span>
                <span className="text-[10px] text-slate-500">{seg.shortLabel}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};
