import React from 'react';
import type { TabId } from '../types/security';

interface ViewSkeletonProps {
  activeTab: TabId;
}

export const ViewSkeleton: React.FC<ViewSkeletonProps> = ({ activeTab }) => {
  if (activeTab === 'audit') {
    return (
      <div className="space-y-6 animate-pulse" aria-busy="true" aria-label="Cargando historial de auditoría">
        <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800/80 shadow-sm space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-2.5 flex-1">
              <div className="h-7 w-72 bg-slate-200 dark:bg-slate-800 rounded-lg" />
              <div className="h-4 w-full max-w-xl bg-slate-100 dark:bg-slate-800/70 rounded-md" />
            </div>
            <div className="h-9 w-32 bg-slate-200 dark:bg-slate-800 rounded-lg shrink-0" />
          </div>
          <div className="pt-4 border-t border-slate-200 dark:border-slate-800/80 flex flex-wrap items-center gap-3">
            <div className="h-10 flex-1 min-w-[220px] bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-44 bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-48 bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-32 bg-blue-200 dark:bg-blue-950/60 rounded-lg" />
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm overflow-hidden">
          <div className="h-11 bg-slate-50 dark:bg-slate-950/50 border-b border-slate-200 dark:border-slate-800/80 px-6 flex items-center justify-between">
            <div className="h-3.5 w-32 bg-slate-200 dark:bg-slate-800 rounded" />
            <div className="h-3.5 w-28 bg-slate-200 dark:bg-slate-800 rounded" />
            <div className="h-3.5 w-36 bg-slate-200 dark:bg-slate-800 rounded" />
            <div className="h-3.5 w-28 bg-slate-200 dark:bg-slate-800 rounded" />
            <div className="h-3.5 w-20 bg-slate-200 dark:bg-slate-800 rounded" />
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800/60">
            {[1, 2, 3, 4].map((row) => (
              <div key={row} className="px-6 py-4 flex items-center justify-between gap-4">
                <div className="h-4 w-36 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-5 w-40 bg-slate-200 dark:bg-slate-800 rounded-md" />
                <div className="h-4 w-44 bg-slate-100 dark:bg-slate-800/70 rounded" />
                <div className="h-4 w-36 bg-slate-100 dark:bg-slate-800/70 rounded" />
                <div className="h-5 w-28 bg-emerald-100 dark:bg-emerald-950/50 rounded-full" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (activeTab === 'modules') {
    return (
      <div className="space-y-6 animate-pulse" aria-busy="true" aria-label="Cargando arquitectura de módulos">
        <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-2.5">
            <div className="h-7 w-80 bg-slate-200 dark:bg-slate-800 rounded-lg" />
            <div className="h-4 w-96 max-w-full bg-slate-100 dark:bg-slate-800/70 rounded" />
          </div>
          <div className="h-9 w-44 bg-brand-200 dark:bg-brand-950 rounded-lg" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[1, 2, 3].map((card) => (
            <div
              key={card}
              className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800/80 p-6 shadow-sm space-y-4"
            >
              <div className="flex justify-between items-start">
                <div className="w-10 h-10 rounded-xl bg-slate-200 dark:bg-slate-800" />
                <div className="h-4 w-28 bg-slate-100 dark:bg-slate-800 rounded" />
              </div>
              <div className="h-5 w-48 bg-slate-200 dark:bg-slate-800 rounded" />
              <div className="space-y-2">
                <div className="h-3.5 w-full bg-slate-100 dark:bg-slate-800/80 rounded" />
                <div className="h-3.5 w-4/5 bg-slate-100 dark:bg-slate-800/80 rounded" />
              </div>
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center">
                <div className="h-6 w-28 bg-slate-100 dark:bg-slate-800 rounded" />
                <div className="h-4 w-20 bg-emerald-100 dark:bg-emerald-950/60 rounded" />
              </div>
            </div>
          ))}
        </div>

        <div className="bg-white dark:bg-[#1e2433] rounded-xl border border-slate-200 dark:border-slate-700/50 p-6 space-y-5">
          <div className="h-6 w-64 bg-slate-200 dark:bg-slate-800 rounded" />
          <div className="space-y-4 max-w-3xl">
            <div className="h-10 w-full bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-full bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-full bg-slate-100 dark:bg-slate-800 rounded-lg" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-pulse" aria-busy="true" aria-label="Cargando resumen de postura de seguridad">
      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-2.5 flex-1">
          <div className="flex items-center gap-2">
            <div className="h-5 w-32 rounded-full bg-emerald-100 dark:bg-emerald-950/60" />
          </div>
          <div className="h-7 w-80 bg-slate-200 dark:bg-slate-800 rounded-lg" />
          <div className="h-4 w-full max-w-2xl bg-slate-100 dark:bg-slate-800/70 rounded" />
        </div>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="h-9 w-32 rounded-lg bg-slate-200 dark:bg-slate-800" />
          <div className="h-9 w-40 rounded-lg bg-brand-200 dark:bg-brand-950" />
        </div>
      </div>

      <div className="grid grid-cols-[repeat(auto-fit,minmax(240px,1fr))] gap-4">
        {[1, 2, 3, 4].map((kpi) => (
          <div
            key={kpi}
            className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm space-y-4"
          >
            <div className="flex justify-between items-start">
              <div className="space-y-2.5">
                <div className="h-3.5 w-28 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-8 w-20 bg-slate-300 dark:bg-slate-700 rounded-md" />
              </div>
              <div className="w-10 h-10 rounded-xl bg-slate-100 dark:bg-slate-800" />
            </div>
            <div className="h-3.5 w-40 bg-slate-100 dark:bg-slate-800/80 rounded" />
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm space-y-4">
          <div className="flex justify-between items-center">
            <div className="space-y-2">
              <div className="h-5 w-72 bg-slate-200 dark:bg-slate-800 rounded" />
              <div className="h-3.5 w-60 bg-slate-100 dark:bg-slate-800/70 rounded" />
            </div>
            <div className="h-7 w-32 bg-slate-100 dark:bg-slate-800 rounded-md" />
          </div>
          <div className="h-[260px] w-full bg-slate-100/80 dark:bg-slate-800/50 rounded-xl flex items-end justify-between p-6 gap-4">
            <div className="w-full h-3/5 bg-slate-200/70 dark:bg-slate-700/40 rounded-t-md" />
            <div className="w-full h-2/3 bg-slate-200/70 dark:bg-slate-700/40 rounded-t-md" />
            <div className="w-full h-1/2 bg-slate-200/70 dark:bg-slate-700/40 rounded-t-md" />
            <div className="w-full h-3/4 bg-slate-200/70 dark:bg-slate-700/40 rounded-t-md" />
            <div className="w-full h-4/5 bg-slate-200/70 dark:bg-slate-700/40 rounded-t-md" />
            <div className="w-full h-full bg-brand-200/60 dark:bg-brand-900/40 rounded-t-md" />
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800/80 shadow-sm flex flex-col justify-between">
          <div className="space-y-2">
            <div className="h-5 w-52 bg-slate-200 dark:bg-slate-800 rounded" />
            <div className="h-3.5 w-44 bg-slate-100 dark:bg-slate-800/70 rounded" />
          </div>
          <div className="my-6 flex items-center justify-center">
            <div className="w-44 h-44 rounded-full border-[18px] border-slate-200 dark:border-slate-800 flex items-center justify-center">
              <div className="h-6 w-12 bg-slate-200 dark:bg-slate-800 rounded" />
            </div>
          </div>
          <div className="pt-3 border-t border-slate-100 dark:border-slate-800/80 flex justify-around">
            <div className="h-8 w-12 bg-slate-100 dark:bg-slate-800 rounded" />
            <div className="h-8 w-12 bg-slate-100 dark:bg-slate-800 rounded" />
            <div className="h-8 w-12 bg-slate-100 dark:bg-slate-800 rounded" />
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-[#1e2433] rounded-xl border border-slate-200 dark:border-slate-700/50 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700/50 space-y-4">
          <div className="space-y-2">
            <div className="h-6 w-80 bg-slate-200 dark:bg-slate-800 rounded" />
            <div className="h-3.5 w-96 max-w-full bg-slate-100 dark:bg-slate-800/70 rounded" />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="h-10 flex-1 min-w-[200px] bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-48 bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-44 bg-slate-100 dark:bg-slate-800 rounded-lg" />
            <div className="h-10 w-32 bg-blue-200 dark:bg-blue-950/60 rounded-lg" />
          </div>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {[1, 2, 3, 4].map((row) => (
            <div key={row} className="px-6 py-4 flex items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="h-4 w-36 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-3 w-44 bg-slate-100 dark:bg-slate-800/70 rounded" />
              </div>
              <div className="h-4 w-32 bg-slate-100 dark:bg-slate-800 rounded" />
              <div className="h-4 w-24 bg-slate-100 dark:bg-slate-800 rounded" />
              <div className="h-6 w-28 bg-slate-200 dark:bg-slate-800 rounded" />
              <div className="h-4 w-20 bg-blue-100 dark:bg-blue-950/50 rounded" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
