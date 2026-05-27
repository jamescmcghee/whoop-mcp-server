let articleData = null;
let currentPage = 1;
let todayCompleted = false;

const STORAGE_KEY = 'hard75_reading';

function todayDate() {
  return new Date().toISOString().slice(0, 10);
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

function setTopic(topic) {
  document.getElementById('topic-input').value = topic;
  loadArticle();
}

async function loadArticle() {
  const topic = document.getElementById('topic-input').value.trim();
  if (!topic) return;

  document.getElementById('loading').classList.remove('hidden');
  document.getElementById('no-article').classList.add('hidden');
  document.getElementById('article-area').classList.add('hidden');

  try {
    const res = await fetch(`/api/reading/article?topic=${encodeURIComponent(topic)}`);
    if (!res.ok) {
      const err = await res.json();
      showToast(err.error || 'Article not found');
      document.getElementById('loading').classList.add('hidden');
      document.getElementById('no-article').classList.remove('hidden');
      return;
    }
    articleData = await res.json();

    // Restore saved page if same topic
    const saved = getSavedProgress();
    if (saved && saved.topic === topic && !todayCompleted) {
      currentPage = saved.currentPage || 1;
    } else {
      currentPage = 1;
    }

    document.getElementById('loading').classList.add('hidden');
    renderArticle();
  } catch {
    showToast('Failed to load article');
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('no-article').classList.remove('hidden');
  }
}

function renderArticle() {
  if (!articleData) return;

  document.getElementById('article-area').classList.remove('hidden');
  document.getElementById('article-title').textContent = articleData.title;

  const page = articleData.pages[currentPage - 1];
  if (!page) return;

  // Format content as paragraphs
  const paragraphs = page.content.split('\n').filter(p => p.trim().length > 20);
  const html = paragraphs.length
    ? paragraphs.map(p => `<p>${escHtml(p.trim())}</p>`).join('')
    : `<p>${escHtml(page.content)}</p>`;
  document.getElementById('article-text').innerHTML = html;

  const total = articleData.total_pages;
  document.getElementById('page-info').textContent = `Page ${currentPage} of ${total}`;

  const prog = Math.round((currentPage / Math.max(total, 10)) * 100);
  document.getElementById('reading-prog').style.width = Math.min(100, prog) + '%';

  document.getElementById('prev-btn').disabled = currentPage <= 1;
  document.getElementById('next-btn').disabled = currentPage >= total;

  const completeBtn = document.getElementById('complete-btn');
  if (todayCompleted) {
    completeBtn.disabled = true;
    completeBtn.textContent = '✅ Reading complete for today!';
  } else if (currentPage >= 10) {
    completeBtn.disabled = false;
    completeBtn.textContent = '✅ Mark Reading Complete';
  } else {
    completeBtn.disabled = true;
    completeBtn.textContent = `Read to page 10 to complete (${currentPage}/10)`;
  }

  // Save progress
  saveProgress(articleData.title, currentPage, total);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function changePage(delta) {
  if (!articleData) return;
  const newPage = currentPage + delta;
  if (newPage < 1 || newPage > articleData.total_pages) return;
  currentPage = newPage;
  renderArticle();
}

async function markComplete() {
  if (!articleData || todayCompleted) return;
  const topic = document.getElementById('topic-input').value.trim();

  const res = await fetch('/api/reading/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      date: todayDate(),
      topic,
      article_title: articleData.title,
      pages_read: Math.max(10, currentPage)
    })
  });

  if (res.ok) {
    todayCompleted = true;
    document.getElementById('done-badge').classList.remove('hidden');
    renderArticle();
    showToast('Reading logged! 📚');
    clearSavedProgress();
  }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function saveProgress(topic, page, total) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ topic, currentPage: page, totalPages: total, date: todayDate() }));
  } catch {}
}

function getSavedProgress() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw);
    if (p.date !== todayDate()) return null;
    return p;
  } catch { return null; }
}

function clearSavedProgress() {
  try { localStorage.removeItem(STORAGE_KEY); } catch {}
}

async function checkTodayStatus() {
  const res = await fetch(`/api/reading/sessions?date=${todayDate()}`);
  const sessions = await res.json();
  if (sessions.some(s => s.completed)) {
    todayCompleted = true;
    document.getElementById('done-badge').classList.remove('hidden');
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  await checkTodayStatus();

  // Restore saved topic/progress
  const saved = getSavedProgress();
  if (saved && !todayCompleted) {
    document.getElementById('topic-input').value = saved.topic;
    await loadArticle();
  }

  // Allow Enter key in topic input
  document.getElementById('topic-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') loadArticle();
  });
});
