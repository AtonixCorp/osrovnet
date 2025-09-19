import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders app header', () => {
  render(<App />);
  const headers = screen.getAllByText(/Osrovnet – Network Security Platform/i);
  expect(headers.length).toBeGreaterThan(0);
});
