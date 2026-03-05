import { memo } from 'react';

interface CheckCardProps {
  title: string;
  icon: string;
  passed: boolean;
  skipped?: boolean;
  details: string;
  meta?: { label: string; value: string | number | null }[];
}

export default memo(function CheckCard({ title, icon, passed, skipped, details, meta }: CheckCardProps) {
  const borderColor = skipped ? 'border-gray-700' : passed ? 'border-green-800' : 'border-red-800';
  const iconBg = skipped ? 'bg-gray-800 text-gray-500' : passed ? 'bg-green-900/50 text-green-400' : 'bg-red-900/50 text-red-400';
  const statusText = skipped ? 'SKIPPED' : passed ? 'PASSED' : 'FAILED';
  const statusColor = skipped ? 'text-gray-500' : passed ? 'text-green-400' : 'text-red-400';

  return (
    <div className={`rounded-xl border ${borderColor} bg-gray-900 p-5 flex flex-col gap-3`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className={`text-2xl rounded-lg p-1.5 ${iconBg}`}>{icon}</span>
          <h3 className="font-semibold text-gray-100">{title}</h3>
        </div>
        <span className={`text-xs font-bold uppercase tracking-widest ${statusColor}`}>{statusText}</span>
      </div>

      <p className="text-sm text-gray-400 leading-relaxed">{details}</p>

      {meta && meta.length > 0 && (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 mt-1">
          {meta.map(({ label, value }) => (
            <div key={label} className="contents">
              <dt className="text-xs text-gray-500">{label}</dt>
              <dd className="text-xs text-gray-300 text-right">
                {value === null || value === undefined ? '—' : String(value)}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
});
