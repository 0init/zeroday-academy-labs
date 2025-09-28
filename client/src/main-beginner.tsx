import React from 'react';
import ReactDOM from 'react-dom/client';
import BeginnerApp from './App-beginner';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BeginnerApp />
  </React.StrictMode>,
);

// Update document title
document.title = 'Zeroday Academy - Beginner Labs';