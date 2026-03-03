import '@testing-library/jest-dom';

// jsdom does not implement ResizeObserver — mock it so Recharts components render without errors
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
