import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import UrlForm from './UrlForm';

describe('UrlForm', () => {
  it('renders the input and button', () => {
    render(<UrlForm onSubmit={vi.fn()} loading={false} />);
    expect(screen.getByPlaceholderText(/https:\/\/suspicious-site\.com/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analyze/i })).toBeInTheDocument();
  });

  it('disables the button when the input is empty', () => {
    render(<UrlForm onSubmit={vi.fn()} loading={false} />);
    expect(screen.getByRole('button', { name: /analyze/i })).toBeDisabled();
  });

  it('enables the button once a value is typed', async () => {
    render(<UrlForm onSubmit={vi.fn()} loading={false} />);
    await userEvent.type(screen.getByRole('textbox'), 'https://example.com');
    expect(screen.getByRole('button', { name: /analyze/i })).toBeEnabled();
  });

  it('disables input and button while loading', () => {
    render(<UrlForm onSubmit={vi.fn()} loading={true} />);
    expect(screen.getByRole('textbox')).toBeDisabled();
    expect(screen.getByRole('button', { name: /analyzing/i })).toBeDisabled();
  });

  it('calls onSubmit with the normalised URL on valid input', async () => {
    const onSubmit = vi.fn();
    render(<UrlForm onSubmit={onSubmit} loading={false} />);
    await userEvent.type(screen.getByRole('textbox'), 'https://example.com');
    await userEvent.click(screen.getByRole('button', { name: /analyze/i }));
    expect(onSubmit).toHaveBeenCalledOnce();
    expect(onSubmit).toHaveBeenCalledWith('https://example.com/');
  });

  it('shows an error for a plain string that is not a URL', async () => {
    render(<UrlForm onSubmit={vi.fn()} loading={false} />);
    await userEvent.type(screen.getByRole('textbox'), 'not-a-url');
    await userEvent.click(screen.getByRole('button', { name: /analyze/i }));
    expect(screen.getByText(/valid URL/i)).toBeInTheDocument();
  });

  it('shows an error for a non-HTTP(S) protocol', async () => {
    render(<UrlForm onSubmit={vi.fn()} loading={false} />);
    await userEvent.type(screen.getByRole('textbox'), 'ftp://example.com');
    await userEvent.click(screen.getByRole('button', { name: /analyze/i }));
    expect(screen.getByText(/only http and https/i)).toBeInTheDocument();
  });

  it('does not call onSubmit when there is a validation error', async () => {
    const onSubmit = vi.fn();
    render(<UrlForm onSubmit={onSubmit} loading={false} />);
    await userEvent.type(screen.getByRole('textbox'), 'ftp://bad.com');
    await userEvent.click(screen.getByRole('button', { name: /analyze/i }));
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
