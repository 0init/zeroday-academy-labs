import React from 'react';
import ReactDOM from 'react-dom/client';
import IntermediateApp from './App-intermediate';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <IntermediateApp />
  </React.StrictMode>,
);

// Update document title
document.title = 'Zeroday Academy - Intermediate Labs';