import '@testing-library/jest-dom';

// jsdom does not implement ResizeObserver — mock it so Recharts components render without errors
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
