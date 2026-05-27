let scannerInstance = null;
let scannerActive = false;
let pendingFile = null;

function todayDate() {
  return new Date().toISOString().slice(0, 10);
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

function round1(n) {
  return Math.round((n || 0) * 10) / 10;
}

async function loadFoodLog() {
  const date = todayDate();
  document.getElementById('today-date').textContent = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

  const res = await fetch(`/api/food/log?date=${date}`);
  const data = await res.json();

  // Update macro totals
  document.getElementById('total-cal').textContent = Math.round(data.totals.calories);
  document.getElementById('total-protein').textContent = round1(data.totals.protein_g) + 'g';
  document.getElementById('total-carbs').textContent = round1(data.totals.carbs_g) + 'g';
  document.getElementById('total-fat').textContent = round1(data.totals.fat_g) + 'g';

  const list = document.getElementById('food-list');
  if (!data.entries.length) {
    list.innerHTML = '<div class="text-center text-muted" style="padding:20px 0">No food logged yet</div>';
    return;
  }

  list.innerHTML = data.entries.map(e => {
    const cal = e.calories ? Math.round(e.calories * (e.quantity || 1)) : '–';
    const mealLabel = { breakfast: '🌅', lunch: '☀️', dinner: '🌙', snack: '🍎' }[e.meal_type] || '';
    return `
      <div class="food-entry">
        <div style="flex:1">
          <div class="food-name">${escHtml(e.product_name)}</div>
          <div class="food-meta">${mealLabel} ${e.meal_type} · qty ${e.quantity ?? 1}${e.serving_size ? ' · ' + escHtml(e.serving_size) : ''}</div>
          <div class="food-meta" style="margin-top:2px">
            ${e.protein_g ? round1(e.protein_g * e.quantity) + 'g P · ' : ''}${e.carbs_g ? round1(e.carbs_g * e.quantity) + 'g C · ' : ''}${e.fat_g ? round1(e.fat_g * e.quantity) + 'g F' : ''}
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <span class="food-kcal">${cal}<small style="font-size:11px;font-weight:400"> kcal</small></span>
          <button class="delete-btn" onclick="deleteFood(${e.id})">×</button>
        </div>
      </div>`;
  }).join('');
}

function escHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function deleteFood(id) {
  await fetch(`/api/food/log/${id}`, { method: 'DELETE' });
  loadFoodLog();
}

function fillForm(data) {
  if (data.product_name) document.getElementById('food-name').value = data.product_name;
  if (data.brand) document.getElementById('food-brand').value = data.brand;
  if (data.calories_per_100g != null) document.getElementById('food-cal').value = round1(data.calories_per_100g);
  if (data.serving_size) document.getElementById('food-serving').value = data.serving_size;
  if (data.protein_per_100g != null) document.getElementById('food-protein').value = round1(data.protein_per_100g);
  if (data.carbs_per_100g != null) document.getElementById('food-carbs').value = round1(data.carbs_per_100g);
  if (data.fat_per_100g != null) document.getElementById('food-fat').value = round1(data.fat_per_100g);
  if (data.barcode) document.getElementById('food-barcode').value = data.barcode;
}

async function addFood() {
  const name = document.getElementById('food-name').value.trim();
  if (!name) { alert('Product name is required'); return; }

  const body = {
    product_name: name,
    brand: document.getElementById('food-brand').value.trim() || null,
    calories: parseFloat(document.getElementById('food-cal').value) || null,
    serving_size: document.getElementById('food-serving').value.trim() || null,
    protein_g: parseFloat(document.getElementById('food-protein').value) || null,
    carbs_g: parseFloat(document.getElementById('food-carbs').value) || null,
    fat_g: parseFloat(document.getElementById('food-fat').value) || null,
    quantity: parseFloat(document.getElementById('food-qty').value) || 1,
    meal_type: document.getElementById('food-meal').value,
    barcode: document.getElementById('food-barcode').value || null,
    date: todayDate(),
  };

  const res = await fetch('/api/food/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (res.ok) {
    // Clear form
    ['food-name','food-brand','food-cal','food-serving','food-protein','food-carbs','food-fat','food-barcode'].forEach(id => {
      document.getElementById(id).value = '';
    });
    document.getElementById('food-qty').value = '1';
    showToast('Added to log ✓');
    loadFoodLog();
  }
}

async function toggleScanner() {
  if (scannerActive) {
    stopScanner();
    return;
  }

  const container = document.getElementById('scanner-container');
  const status = document.getElementById('scan-status');
  const btn = document.getElementById('scan-btn');

  // Check for camera access
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showToast('Camera not available');
    return;
  }

  try {
    // Dynamically load html5-qrcode
    const { Html5Qrcode } = await import('https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.esm.min.js');
    container.style.display = 'block';
    container.innerHTML = '<div id="qr-reader" style="width:100%;background:#000;min-height:200px"></div>';
    btn.textContent = '✕ Stop Scanner';
    scannerActive = true;

    scannerInstance = new Html5Qrcode('qr-reader');
    await scannerInstance.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 250, height: 150 } },
      async (decodedText) => {
        stopScanner();
        status.textContent = `Looking up barcode ${decodedText}…`;
        status.classList.remove('hidden');

        const res = await fetch(`/api/food/barcode/${encodeURIComponent(decodedText)}`);
        const data = await res.json();
        if (data.found) {
          fillForm(data);
          showToast('Product found! ✓');
          status.classList.add('hidden');
        } else {
          showToast('Product not found — enter manually');
          document.getElementById('food-barcode').value = decodedText;
          status.classList.add('hidden');
        }
      },
      () => {}
    );
  } catch (err) {
    showToast('Camera access denied');
    container.style.display = 'none';
    scannerActive = false;
  }
}

function stopScanner() {
  if (scannerInstance) {
    scannerInstance.stop().catch(() => {});
    scannerInstance = null;
  }
  document.getElementById('scanner-container').style.display = 'none';
  document.getElementById('scanner-container').innerHTML = '';
  document.getElementById('scan-btn').innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="5" height="5"/><rect x="16" y="3" width="5" height="5"/><rect x="3" y="16" width="5" height="5"/><path d="M21 16v2a2 2 0 01-2 2h-2"/><path d="M16 21h2a2 2 0 002-2v-2"/><line x1="12" y1="3" x2="12" y2="9"/><line x1="12" y1="15" x2="12" y2="21"/><line x1="3" y1="12" x2="9" y2="12"/><line x1="15" y1="12" x2="21" y2="12"/></svg> Scan Barcode`;
  scannerActive = false;
}

// Cleanup scanner on page leave
window.addEventListener('beforeunload', stopScanner);

document.addEventListener('DOMContentLoaded', loadFoodLog);
