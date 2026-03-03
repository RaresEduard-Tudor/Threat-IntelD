import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import type { Assessment } from '../types/threat';

interface Props {
  score: number;
  assessment: Assessment;
}

const scoreColor: Record<Assessment, string> = {
  Safe: '#22c55e',
  Suspicious: '#f59e0b',
  Malicious: '#ef4444',
};

export default function ThreatScoreDonut({ score, assessment }: Props) {
  const color = scoreColor[assessment];
  const data = [
    { name: 'Score', value: score },
    { name: 'Remaining', value: 100 - score },
  ];

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={80}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              strokeWidth={0}
            >
              <Cell fill={color} />
              <Cell fill="#1f2937" />
            </Pie>
            <Tooltip
              formatter={(value: number, name: string) =>
                name === 'Score' ? [`${value}/100`, 'Threat Score'] : null
              }
              contentStyle={{ background: '#111827', border: 'none', color: '#f9fafb' }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-4xl font-black" style={{ color }}>{score}</span>
          <span className="text-xs text-gray-400 uppercase tracking-widest">/ 100</span>
        </div>
      </div>
      <p className="mt-2 text-gray-400 text-sm">Threat Score</p>
    </div>
  );
}
