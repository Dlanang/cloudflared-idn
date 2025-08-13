#!/usr/bin/env bash
set -euo pipefail
COMPOSE="${COMPOSE:-$(pwd)/docker-compose.yml}"

echo ">> Ensure App.jsx has default export..."
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc '
  set -e
  cd /app

  test -f src/App.jsx || { echo "ERR: src/App.jsx tidak ada"; exit 1; }

  # Jika App.jsx tidak memiliki default export, tambahkan.
  if ! grep -Eq "export default( function)? App" src/App.jsx; then
    # Cek apakah ada deklarasi fungsi bernama App
    if grep -Eq "^\\s*function\\s+App\\s*\\(" src/App.jsx; then
      echo ">> Tambah baris export default App;"
      printf "\nexport default App;\n" >> src/App.jsx
    else
      echo ">> Bungkus jadi komponen default minimal"
      cat > src/App.jsx <<'JS'
import React from "react";

function App() {
  return (
    <div style={{padding: 24}}>
      <h1>Suricata Monitor</h1>
      <p>Landing React berhasil dimuat.</p>
      <a href="/monitor">Ke Dashboard Streamlit</a>
    </div>
  );
}
export default App;
JS
    fi
  fi

  echo ">> Normalize main.jsx (default import + import CSS + render)..."
  cat > src/main.jsx <<'JS'
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import './index.css'

createRoot(document.getElementById('root')).render(<App />)
JS

  echo ">> Build & publish..."
  (npm ci || npm install)
  npm run build
  rm -rf /webroot/* && cp -r dist/* /webroot/
'
echo ">> Done. Coba refresh landing."
