import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import PQCKeyGenerator from '../../components/PQCKeyGenerator';

// Mock global fetch via the project's API client which uses fetch internally
global.fetch = jest.fn();

describe('PQC Key Generator (UI)', () => {
  beforeEach(() => {
    (fetch as jest.Mock).mockClear();
    // JSDOM does not implement createObjectURL or atob by default; provide simple mocks
    // atob used to decode base64 private key
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    global.atob = (s: string) => Buffer.from(s, 'base64').toString('binary');
  // @ts-ignore
  window.URL.createObjectURL = jest.fn(() => 'blob:fake');
  // @ts-ignore
  window.URL.revokeObjectURL = jest.fn();
  // prevent navigation triggered by anchor clicks (Header Drawer links)
  // @ts-ignore
  HTMLAnchorElement.prototype.click = function () { /* no-op in tests */ };
  });

  it('lists algorithms and generates a key (mocked)', async () => {
    (fetch as jest.Mock)
      // first call: list algorithms
      .mockResolvedValueOnce({ ok: true, text: async () => JSON.stringify([{ name: 'CRYSTALS-Kyber', description: 'KEM' }]) })
      // second call: generate
      .mockResolvedValueOnce({ ok: true, text: async () => JSON.stringify({ public_key_b64: 'cHVibGlj', private_key_b64: 'cHJpdmF0ZQ==' }) });

    render(<PQCKeyGenerator />);
    await waitFor(() => expect(screen.getByRole('combobox')).toBeInTheDocument());
  fireEvent.click(screen.getByText(/Generate keypair/i));
  await waitFor(() => screen.getByText(/Key generated/i));
  });
});
