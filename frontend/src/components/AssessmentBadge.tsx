import { memo } from 'react';
import type { Assessment } from '../types/threat';

interface Props {
  assessment: Assessment;
}

const styles: Record<Assessment, string> = {
  Safe: 'bg-green-900/50 text-green-400 border border-green-700',
  Suspicious: 'bg-yellow-900/50 text-yellow-400 border border-yellow-700',
  Malicious: 'bg-red-900/50 text-red-400 border border-red-700',
};

const icons: Record<Assessment, string> = {
  Safe: '✓',
  Suspicious: '⚠',
  Malicious: '✕',
};

export default memo(function AssessmentBadge({ assessment }: Props) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-sm font-bold uppercase tracking-widest ${styles[assessment]}`}>
      <span>{icons[assessment]}</span>
      {assessment}
    </span>
  );
});
