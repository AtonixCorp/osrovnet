import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders app header', () => {
  render(<App />);
  const header = screen.getByText(/OSROVNet - Network Security Platform/i);
  expect(header).toBeInTheDocument();
});
