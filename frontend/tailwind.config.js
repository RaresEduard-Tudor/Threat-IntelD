/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        safe: '#22c55e',
        suspicious: '#f59e0b',
        malicious: '#ef4444',
      },
    },
  },
  plugins: [],
};
