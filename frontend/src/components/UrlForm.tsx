import { useState } from 'react';

interface Props {
  onSubmit: (url: string) => void;
  loading: boolean;
}

export default function UrlForm({ onSubmit, loading }: Props) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const parsed = new URL(value.trim());
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        setError('Only HTTP and HTTPS URLs are supported.');
        return;
      }
      // Strip query string and fragment — keeps scheme + host + path
      parsed.search = '';
      parsed.hash = '';
      onSubmit(parsed.toString());
    } catch {
      setError('Please enter a valid URL (e.g. https://example.com).');
    }
  }

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
      <div className="flex flex-col sm:flex-row gap-3">
        <label htmlFor="url-input" className="sr-only">URL to analyze</label>
        <input
          id="url-input"
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="https://suspicious-site.com"
          disabled={loading}
          className="flex-1 rounded-lg bg-gray-800 border border-gray-700 px-4 py-3 text-gray-100
                     placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1
                     focus:ring-blue-500 disabled:opacity-50 transition"
        />
        <button
          type="submit"
          aria-label={loading ? 'Analyzing URL' : 'Analyze URL'}
          disabled={loading || !value.trim()}
          className="rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed
                     px-6 py-3 font-semibold text-white transition"
        >
          {loading ? 'Analyzing…' : 'Analyze'}
        </button>
      </div>
      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
    </form>
  );
}
