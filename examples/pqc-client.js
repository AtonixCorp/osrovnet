/* Simple Node client example demonstrating the PQC endpoints
   Usage: node examples/pqc-client.js
   Assumes backend is running at http://127.0.0.1:8000
*/

const fetch = require('node-fetch');
const API = 'http://127.0.0.1:8000';

async function list() {
  const r = await fetch(`${API}/api/postquantum/algorithms/`, { credentials: 'include' });
  console.log('list status', r.status);
  console.log(await r.text());
}

async function generate() {
  const r = await fetch(`${API}/api/postquantum/generate/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm: 'CRYSTALS-Kyber', name: 'example-kyber' }),
    credentials: 'include',
  });
  console.log('generate status', r.status);
  const txt = await r.text();
  console.log(txt);
}

(async () => {
  await list();
  await generate();
})();
