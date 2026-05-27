let saveTimer = null;
let currentState = {};

function todayDate() {
  return new Date().toISOString().slice(0, 10);
}

function showToast(msg = 'Saved') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}

async function startChallenge() {
  const d = document.getElementById('start-date-input').value;
  if (!d) return alert('Please choose a start date');
  await fetch('/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ start_date: d })
  });
  await loadDashboard();
}

function updateUI(data) {
  currentState = data;
  const dn = data.day_number || 1;
  document.getElementById('day-num').textContent = dn;

  const pct = Math.min(100, Math.round((dn / 75) * 100));
  document.getElementById('prog-fill').style.width = pct + '%';
  document.getElementById('prog-pct').textContent = pct + '%';
  document.getElementById('day-sub').textContent = data.all_tasks_complete ? '✅ All tasks complete!' : "Today's tasks";

  const ring = document.getElementById('day-ring');
  if (data.all_tasks_complete) {
    ring.classList.add('complete');
  } else {
    ring.classList.remove('complete');
  }

  const streak = data.streak || 0;
  document.getElementById('streak-badge').textContent = `🔥 ${streak} day streak`;

  // Set checkbox values
  setToggle('diet-followed', data.diet_followed);
  setToggle('no-alcohol', data.no_alcohol);
  setToggle('w1-done', data.workout1_done);
  setToggle('w1-outdoor', data.workout1_outdoor);
  setToggle('w2-done', data.workout2_done);
  setToggle('w2-outdoor', data.workout2_outdoor);

  document.getElementById('w1-duration').value = data.workout1_duration || 45;
  document.getElementById('w2-duration').value = data.workout2_duration || 45;

  const waterOz = data.water_oz || 0;
  document.getElementById('water-slider').value = waterOz;
  document.getElementById('water-val').textContent = waterOz;

  // Card done states
  updateCardDone('card-diet', data.diet_followed && data.no_alcohol);
  updateCardDone('card-w1', data.workout1_done);
  updateCardDone('card-w2', data.workout2_done);
  updateCardDone('card-water', data.water_oz >= 128);
  updateCardDone('card-reading', data.reading_done);
  updateCardDone('card-photo', data.photo_taken);

  // Reading and photo status
  const readEl = document.getElementById('reading-status');
  readEl.textContent = data.reading_done ? '✅ Done' : 'Not done';
  readEl.style.color = data.reading_done ? 'var(--primary)' : 'var(--text-muted)';

  const photoEl = document.getElementById('photo-status');
  photoEl.textContent = data.photo_taken ? '✅ Done' : 'Not done';
  photoEl.style.color = data.photo_taken ? 'var(--primary)' : 'var(--text-muted)';
}

function setToggle(id, val) {
  document.getElementById(id).checked = !!val;
}

function updateCardDone(id, done) {
  const card = document.getElementById(id);
  if (done) card.classList.add('done');
  else card.classList.remove('done');
}

function getFormState() {
  return {
    date: todayDate(),
    diet_followed: document.getElementById('diet-followed').checked ? 1 : 0,
    no_alcohol: document.getElementById('no-alcohol').checked ? 1 : 0,
    workout1_done: document.getElementById('w1-done').checked ? 1 : 0,
    workout1_outdoor: document.getElementById('w1-outdoor').checked ? 1 : 0,
    workout1_duration: parseInt(document.getElementById('w1-duration').value) || 0,
    workout2_done: document.getElementById('w2-done').checked ? 1 : 0,
    workout2_outdoor: document.getElementById('w2-outdoor').checked ? 1 : 0,
    workout2_duration: parseInt(document.getElementById('w2-duration').value) || 0,
    water_oz: parseInt(document.getElementById('water-slider').value) || 0,
  };
}

function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const body = getFormState();
    const res = await fetch('/api/habits/today', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (res.ok) {
      const data = await res.json();
      updateUI(data);
      showToast('Saved ✓');
    }
  }, 600);
}

async function loadDashboard() {
  const config = await fetch('/api/config').then(r => r.json());
  if (!config.start_date) {
    document.getElementById('setup-screen').classList.remove('hidden');
    document.getElementById('main-dashboard').classList.add('hidden');
    // Default to today
    document.getElementById('start-date-input').value = todayDate();
    return;
  }
  document.getElementById('setup-screen').classList.add('hidden');
  document.getElementById('main-dashboard').classList.remove('hidden');

  const data = await fetch('/api/habits/today').then(r => r.json());
  updateUI(data);
}

// Wire up all inputs
document.addEventListener('DOMContentLoaded', () => {
  const inputs = [
    'diet-followed', 'no-alcohol',
    'w1-done', 'w1-outdoor', 'w2-done', 'w2-outdoor',
    'w1-duration', 'w2-duration'
  ];
  inputs.forEach(id => {
    document.getElementById(id).addEventListener('change', scheduleSave);
  });

  // Water slider: update display immediately, save on change
  const waterSlider = document.getElementById('water-slider');
  waterSlider.addEventListener('input', () => {
    document.getElementById('water-val').textContent = waterSlider.value;
  });
  waterSlider.addEventListener('change', scheduleSave);

  loadDashboard();
});
