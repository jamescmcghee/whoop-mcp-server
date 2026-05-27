let pendingFileData = null;

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

async function loadPhotos() {
  const res = await fetch('/api/photos');
  const photos = await res.json();

  document.getElementById('photo-count').textContent = `${photos.length} photo${photos.length !== 1 ? 's' : ''}`;

  const grid = document.getElementById('photo-grid');
  const empty = document.getElementById('empty-state');

  if (!photos.length) {
    grid.classList.add('hidden');
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');
  grid.classList.remove('hidden');

  grid.innerHTML = photos.map(p => `
    <div class="photo-thumb" onclick="openModal('${p.filepath}')">
      <img src="${p.filepath}" alt="Day ${p.day_number}" loading="lazy" />
      <span class="day-badge">Day ${p.day_number || '?'}</span>
      <button class="del-photo" onclick="deletePhoto(event, ${p.id})" title="Delete">×</button>
    </div>
  `).join('');
}

function uploadPhoto(event) {
  const file = event.target.files[0];
  if (!file) return;
  pendingFileData = file;
  document.getElementById('notes-form').classList.remove('hidden');
  // Reset input so same file can be re-selected
  event.target.value = '';
}

async function confirmUpload() {
  if (!pendingFileData) return;

  const notes = document.getElementById('photo-notes').value.trim();
  const formData = new FormData();
  formData.append('photo', pendingFileData);
  if (notes) formData.append('notes', notes);

  // Show progress
  const progWrap = document.getElementById('upload-progress');
  const progBar = document.getElementById('upload-bar');
  progWrap.classList.remove('hidden');

  // Animate the bar (fake progress — XHR would be needed for real progress)
  let prog = 0;
  const ticker = setInterval(() => {
    prog = Math.min(prog + 15, 85);
    progBar.style.width = prog + '%';
  }, 100);

  const res = await fetch('/api/photos/upload', {
    method: 'POST',
    body: formData
    // NOTE: do NOT set Content-Type header — browser sets it with boundary
  });

  clearInterval(ticker);
  progBar.style.width = '100%';
  setTimeout(() => progWrap.classList.add('hidden'), 400);

  if (res.ok) {
    document.getElementById('notes-form').classList.add('hidden');
    document.getElementById('photo-notes').value = '';
    pendingFileData = null;
    showToast('Photo uploaded! 📸');
    loadPhotos();
  } else {
    showToast('Upload failed — try again');
  }
}

function cancelUpload() {
  pendingFileData = null;
  document.getElementById('notes-form').classList.add('hidden');
  document.getElementById('photo-notes').value = '';
}

function openModal(src) {
  document.getElementById('modal-img').src = src;
  document.getElementById('photo-modal').classList.add('open');
}

function closeModal() {
  document.getElementById('photo-modal').classList.remove('open');
}

async function deletePhoto(event, id) {
  event.stopPropagation();
  if (!confirm('Delete this photo?')) return;
  const res = await fetch(`/api/photos/${id}`, { method: 'DELETE' });
  if (res.ok) {
    showToast('Photo deleted');
    loadPhotos();
  }
}

// Drag and drop
const uploadArea = document.getElementById('upload-area');
uploadArea.addEventListener('dragover', e => {
  e.preventDefault();
  uploadArea.classList.add('drag-over');
});
uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('drag-over'));
uploadArea.addEventListener('drop', e => {
  e.preventDefault();
  uploadArea.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) {
    pendingFileData = file;
    document.getElementById('notes-form').classList.remove('hidden');
  }
});

// Close modal on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

document.addEventListener('DOMContentLoaded', loadPhotos);
