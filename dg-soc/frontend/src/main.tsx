import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/inter';
import '@fontsource-variable/jetbrains-mono';
import { App } from './App';
import './styles/tokens.css';
import './styles/app.css';
import './styles/theme.css';
import './styles/live.css';
import './styles/incidents.css';
import './styles/response.css';
import './styles/chakra3d.css';
import './styles/evidence.css';

const container = document.getElementById('root');
if (!container) throw new Error('#root is missing from index.html');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
