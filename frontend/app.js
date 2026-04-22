/**
 * CyberDashboard — Frontend Engine
 * Vanilla ES6+ • Zero dependencies • REST ↔ FastAPI
 */

'use strict';

// ─── Config ────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:8000';
const DEBOUNCE_MS = 350;
const PER_PAGE = 18;

// ─── State ─────────────────────────────────────────────
const state = {
  query: '',
  filter: 'all',
  minCvss: 0,
  page: 1,
  total: 0,
  loading: false,
  lang: 'en',   // 'en' ou 'fr'
};

// ─── DOM Refs ───────────────────────────────────────────
const $ = id => document.getElementById(id);
const grid        = $('cards-grid');
const pagination  = $('pagination');
const searchInput = $('search-input');
const cvssSlider  = $('cvss-slider');
const cvssVal     = $('cvss-val');
const resultsCount= $('results-count');
const statusDot   = $('db-status');
const statusText  = $('status-text');
const tickerContent=$('ticker-content');

// Modals
const translateOverlay  = $('translate-modal-overlay');
const btnTranslateAll   = $('btn-translate-all');
const langToggle        = $('lang-toggle');
const langFlag          = $('lang-flag');
const langLabel         = $('lang-label');
const detailOverlay     = $('modal-overlay');
const updateOverlay   = $('update-modal-overlay');
const modalTitle      = $('modal-title');
const modalBadge      = $('modal-badge');
const modalMeta       = $('modal-meta');
const modalDesc       = $('modal-description');
const modalPoc        = $('modal-poc');
const modalRemediation= $('modal-remediation');
const pocSection      = $('poc-section');
const remSection      = $('remediation-section');
const copyPocBtn      = $('copy-poc');
const btnUpdate       = $('btn-update');

// ─── Utils ──────────────────────────────────────────────

function debounce(fn, delay) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), delay); };
}

function formatDate(str) {
  if (!str) return '—';
  try { return new Date(str).toLocaleDateString('fr-FR', { year: 'numeric', month: 'short', day: 'numeric' }); }
  catch { return str.slice(0, 10); }
}

function severityColor(sev) {
  const map = { Critical: '#ff4444', High: '#ff8c00', Medium: '#f0b429', Low: '#39d353', Info: '#8b949e' };
  return map[sev] || '#8b949e';
}

function typeClass(type) {
  const map = { Vulnerability: 'badge-type-Vulnerability', Malware: 'badge-type-Malware', Phishing: 'badge-type-Phishing' };
  return map[type] || '';
}

async function apiFetch(path) {
  const res = await fetch(API_BASE + path);
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

// ─── Health / Status ─────────────────────────────────────

async function checkHealth() {
  try {
    await apiFetch('/health');
    statusDot.className = 'status-dot status-ok';
    statusText.textContent = 'Backend connected';
  } catch {
    statusDot.className = 'status-dot status-error';
    statusText.textContent = 'Backend offline — run start.bat';
  }
}

// ─── Stats (header pills) ────────────────────────────────

async function loadStats() {
  try {
    const s = await apiFetch('/stats');
    $('stat-total').querySelector('.stat-val').textContent  = s.total.toLocaleString();
    $('stat-critical').querySelector('.stat-val').textContent = (s.by_severity?.Critical || 0).toLocaleString();
    $('stat-high').querySelector('.stat-val').textContent     = (s.by_severity?.High || 0).toLocaleString();
    $('stat-malware').querySelector('.stat-val').textContent  = (s.by_type?.Malware || 0).toLocaleString();
    updateCriticalBanner(s.by_severity?.Critical || 0);
  } catch { /* silently fail */ }
}

// ─── Live Ticker ─────────────────────────────────────────

async function loadTicker() {
  try {
    const alerts = await apiFetch('/recent-alerts?limit=15');
    if (!alerts.length) return;
    const text = alerts.map(a => {
      const sev = a.severity || 'Info';
      const prefix = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🟢', Info: '⚪' }[sev] || '⚪';
      return `${prefix} [${a.type}] ${a.source_id} — ${a.title}`;
    }).join('   ·   ');
    tickerContent.textContent = text + '   ·   ';
    // Restart animation
    tickerContent.style.animation = 'none';
    tickerContent.offsetHeight; // reflow
    tickerContent.style.animation = '';
  } catch { /* silently */ }
}

// ─── Card Rendering ──────────────────────────────────────

function renderCard(item) {
  const sev    = item.severity || 'Info';
  const score  = item.cvss_score > 0 ? item.cvss_score.toFixed(1) : 'N/A';
  const hasPoc = !!item.poc_code;

  // Choisir la langue selon l'état du toggle
  const isFr    = state.lang === 'fr';
  const title   = (isFr && item.title_fr)       ? item.title_fr       : (item.title || '');
  const desc    = (isFr && item.description_fr) ? item.description_fr : (item.description || 'No description available.');
  const hasTranslation = !!(item.title_fr || item.description_fr);

  const card = document.createElement('div');
  card.className = `card ${sev}`;
  card.dataset.id = item.id;

  card.innerHTML = `
    <div class="card-header">
      <div class="card-badges">
        <span class="badge ${typeClass(item.type)}">${item.type.toUpperCase()}</span>
        <span class="badge badge-sev ${sev}">${sev.toUpperCase()}</span>
        ${hasTranslation ? '<span class="badge-fr">FR</span>' : ''}
      </div>
      <div class="card-cvss ${sev}">${score}</div>
    </div>
    <div class="card-source-id">${escHtml(item.source_id)}</div>
    <div class="card-title">${escHtml(title)}</div>
    <div class="card-desc">${escHtml(desc)}</div>
    <div class="card-footer">
      <span>${formatDate(item.published_date)}</span>
      <div style="display:flex;gap:8px;align-items:center">
        ${isFr && !hasTranslation ? '<span style="font-size:9px;color:var(--text-dim)">[EN]</span>' : ''}
        ${hasPoc ? '<span class="card-has-poc">⚡ PoC</span>' : '<span></span>'}
      </div>
    </div>
  `;

  card.addEventListener('click', () => openDetail(item.id));
  return card;
}

function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Fetch & Render List ─────────────────────────────────

async function fetchVulnerabilities() {
  if (state.loading) return;
  state.loading = true;

  grid.innerHTML = `
    <div class="loader-placeholder">
      <div class="scanner-line"></div>
      <p>Scanning threat database…</p>
    </div>`;
  pagination.innerHTML = '';
  resultsCount.textContent = 'Loading…';

  const params = new URLSearchParams({
    page:     state.page,
    per_page: PER_PAGE,
  });
  if (state.query)         params.set('q', state.query);
  if (state.filter !== 'all') params.set('type', state.filter);
  if (state.minCvss > 0)   params.set('min_cvss', state.minCvss);

  try {
    const data = await apiFetch(`/vulnerabilities?${params}`);
    state.total = data.total;

    if (!data.items.length) {
      grid.innerHTML = `
        <div class="empty-state">
          <h3>No threats found</h3>
          <p>Try adjusting your filters or run the seed script first.</p>
        </div>`;
      resultsCount.textContent = '0 results';
      state.loading = false;
      return;
    }

    grid.innerHTML = '';
    data.items.forEach(item => grid.appendChild(renderCard(item)));

    resultsCount.textContent = `${data.total.toLocaleString()} result${data.total !== 1 ? 's' : ''}`;
    renderPagination(data.total);
  } catch (err) {
    grid.innerHTML = `
      <div class="empty-state">
        <h3>⚠ Connection Error</h3>
        <p>Cannot reach the backend API.<br>Make sure <code>start.bat</code> is running.</p>
      </div>`;
    resultsCount.textContent = 'Error';
    console.error('[CyberDashboard]', err);
  }

  state.loading = false;
}

// ─── Pagination ──────────────────────────────────────────

function renderPagination(total) {
  const pages = Math.ceil(total / PER_PAGE);
  if (pages <= 1) { pagination.innerHTML = ''; return; }

  pagination.innerHTML = '';

  const mkBtn = (label, page, active = false, disabled = false) => {
    const btn = document.createElement('button');
    btn.className = `page-btn${active ? ' active' : ''}`;
    btn.textContent = label;
    btn.disabled = disabled;
    btn.addEventListener('click', () => { state.page = page; fetchVulnerabilities(); window.scrollTo(0, 200); });
    return btn;
  };

  pagination.appendChild(mkBtn('‹ Prev', state.page - 1, false, state.page === 1));

  const start = Math.max(1, state.page - 2);
  const end   = Math.min(pages, state.page + 2);

  if (start > 1) {
    pagination.appendChild(mkBtn('1', 1));
    if (start > 2) pagination.appendChild(mkBtn('…', state.page - 3, false, true));
  }

  for (let p = start; p <= end; p++) {
    pagination.appendChild(mkBtn(String(p), p, p === state.page));
  }

  if (end < pages) {
    if (end < pages - 1) pagination.appendChild(mkBtn('…', state.page + 3, false, true));
    pagination.appendChild(mkBtn(String(pages), pages));
  }

  pagination.appendChild(mkBtn('Next ›', state.page + 1, false, state.page === pages));
}

// ─── Detail Modal ─────────────────────────────────────────

async function openDetail(id) {
  try {
    const item = await apiFetch(`/vulnerabilities/${id}`);
    const isFr = state.lang === 'fr';

    // Badge
    modalBadge.className = `badge ${typeClass(item.type)}`;
    modalBadge.textContent = item.type.toUpperCase();

    // Titre : FR si dispo, sinon EN
    const title = (isFr && item.title_fr) ? item.title_fr : item.title;
    modalTitle.textContent = title;

    // Meta
    const sev = item.severity || 'Info';
    const hasTranslation = !!(item.title_fr || item.description_fr);
    modalMeta.innerHTML = `
      <div class="meta-item">SOURCE ID: <span>${escHtml(item.source_id)}</span></div>
      <div class="meta-item">CVSS: <span style="color:${severityColor(sev)}">${item.cvss_score > 0 ? item.cvss_score.toFixed(1) : 'N/A'} (${sev})</span></div>
      <div class="meta-item">TYPE: <span>${escHtml(item.type)}</span></div>
      <div class="meta-item">PUBLIÉ: <span>${formatDate(item.published_date)}</span></div>
      ${hasTranslation
        ? '<div class="meta-item">LANGUE: <span style="color:#60a5fa">🇫🇷 Traduit</span></div>'
        : '<div class="meta-item">LANGUE: <span>🇬🇧 EN</span></div>'}
    `;

    // Description FR ou EN
    const desc = (isFr && item.description_fr) ? item.description_fr : (item.description || 'No description available.');
    modalDesc.textContent = desc;

    if (item.poc_code) {
      modalPoc.textContent = item.poc_code;
      pocSection.style.display = 'block';
    } else {
      pocSection.style.display = 'none';
    }

    // Remédiation FR ou EN
    const remed = (isFr && item.remediation_fr) ? item.remediation_fr : item.remediation;
    if (remed) {
      modalRemediation.textContent = remed;
      remSection.style.display = 'block';
    } else {
      remSection.style.display = 'none';
    }

    // Bouton "Traduire cette entrée" si pas encore traduit
    const existingTransBtn = document.getElementById('btn-translate-one');
    if (existingTransBtn) existingTransBtn.remove();

    if (!hasTranslation) {
      const transBtn = document.createElement('button');
      transBtn.id = 'btn-translate-one';
      transBtn.className = 'btn-update';
      transBtn.style.cssText = 'margin:0 20px 16px;font-size:11px;padding:6px 14px;';
      transBtn.innerHTML = '🌐 Traduire cette entrée en FR';
      transBtn.addEventListener('click', async () => {
        transBtn.textContent = '⏳ Traduction…';
        transBtn.disabled = true;
        try {
          await apiFetch(`/translate/${id}`);
          closeDetail();
          await openDetail(id);  // Rouvrir avec le contenu traduit
          if (state.lang !== 'fr') toggleLang();
        } catch (e) {
          transBtn.textContent = '⚠ Erreur';
          setTimeout(() => { transBtn.innerHTML = '🌐 Traduire cette entrée en FR'; transBtn.disabled = false; }, 2000);
        }
      });
      document.querySelector('.modal-body').prepend(transBtn);
    }

    detailOverlay.classList.add('open');
    document.body.style.overflow = 'hidden';
  } catch (err) {
    console.error('[Detail]', err);
  }
}

function closeDetail() {
  detailOverlay.classList.remove('open');
  document.body.style.overflow = '';
}

// ─── Copy PoC ────────────────────────────────────────────

copyPocBtn.addEventListener('click', () => {
  const text = modalPoc.textContent;
  navigator.clipboard.writeText(text).then(() => {
    copyPocBtn.textContent = '✓ COPIED';
    copyPocBtn.classList.add('copied');
    setTimeout(() => {
      copyPocBtn.textContent = 'COPY';
      copyPocBtn.classList.remove('copied');
    }, 2000);
  });
});

// ─── Update Check ────────────────────────────────────────

async function runUpdateCheck() {
  clearUpdateBadge();
  updateOverlay.classList.add('open');
  $('update-modal-body').innerHTML = `
    <div class="update-scanning">
      <div class="spinner"></div>
      <p>Scanning external feeds…</p>
      <p style="font-size:10px;color:var(--text-dim)">NVD • PhishTank • MISP</p>
    </div>`;
  document.body.style.overflow = 'hidden';
  btnUpdate.classList.add('loading');

  try {
    const result = await apiFetch('/update-check');

    const sourcesHtml = result.sources_checked.map(s => {
      const [name, count] = s.split('(');
      return `<div class="source-item"><span>${name.trim()}</span><span class="src-count">${count ? '+' + count.replace(')', '') : '0'}</span></div>`;
    }).join('');

    $('update-modal-body').innerHTML = `
      <div class="update-result">
        <div class="new-count">${result.new_count}</div>
        <div class="new-label">new threat${result.new_count !== 1 ? 's' : ''} detected &amp; added</div>
        <div class="update-sources">${sourcesHtml}</div>
        <div class="update-ts">Last checked: ${new Date(result.last_checked).toLocaleString('fr-FR')}</div>
      </div>`;

    if (result.new_count > 0) {
      await loadStats();
      await loadTicker();
      await fetchVulnerabilities();
    }
  } catch (err) {
    $('update-modal-body').innerHTML = `
      <div class="empty-state">
        <h3>⚠ Update Failed</h3>
        <p>${err.message}</p>
      </div>`;
  }

  btnUpdate.classList.remove('loading');
}

function closeUpdateModal() {
  updateOverlay.classList.remove('open');
  document.body.style.overflow = '';
}

// ─── Toast Notification System ───────────────────────────

function showToast(message, type = 'info', duration = 6000) {
  const container = $('toast-container');
  if (!container) return null;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  const icons = { info: '📡', warning: '⚠', critical: '🚨', success: '✓' };
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || '📡'}</span>
    <span class="toast-msg">${message}</span>
    <button class="toast-close-btn">✕</button>
  `;
  toast.querySelector('.toast-close-btn').addEventListener('click', () => dismissToast(toast));
  container.appendChild(toast);
  if (type === 'critical') playAlertSound();
  setTimeout(() => dismissToast(toast), duration);
  return toast;
}

function dismissToast(toast) {
  if (!toast || !toast.parentNode) return;
  toast.classList.add('toast-out');
  setTimeout(() => toast.remove(), 280);
}

// ─── Audio Alert (Web Audio API) ─────────────────────────

function playAlertSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [[880, 0], [660, 0.18]].forEach(([freq, delay]) => {
      const osc  = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.frequency.value = freq;
      osc.type = 'square';
      const t = ctx.currentTime + delay;
      gain.gain.setValueAtTime(0.07, t);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.14);
      osc.start(t);
      osc.stop(t + 0.14);
    });
  } catch { /* AudioContext indisponible */ }
}

// ─── Critical Alert Banner ───────────────────────────────

let criticalBannerDismissed = false;

function updateCriticalBanner(criticalCount) {
  const banner = $('critical-banner');
  if (!banner || criticalBannerDismissed) return;
  if (criticalCount > 0) {
    $('critical-banner-text').textContent =
      `⚠  ${criticalCount} MENACE${criticalCount > 1 ? 'S' : ''} CRITIQUE${criticalCount > 1 ? 'S' : ''} EN BASE — CVSS ≥ 9.0 — Action immédiate requise`;
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
  }
}

$('critical-banner-close').addEventListener('click', () => {
  criticalBannerDismissed = true;
  $('critical-banner').classList.add('hidden');
});

// ─── Browser Notifications ───────────────────────────────

function sendBrowserNotification(title, body) {
  if (Notification.permission !== 'granted') return;
  try {
    new Notification(`[CyberDash] ${title}`, { body, tag: 'cyberdash-threat' });
  } catch { /* notifications bloquées */ }
}

$('btn-notify').addEventListener('click', async () => {
  if (Notification.permission === 'granted') {
    showToast('Notifications navigateur déjà activées ✓', 'success', 3000);
    return;
  }
  if (Notification.permission === 'denied') {
    showToast('Notifications bloquées — autorise-les dans les paramètres du navigateur', 'warning', 5000);
    return;
  }
  const perm = await Notification.requestPermission();
  if (perm === 'granted') {
    const btn = $('btn-notify');
    btn.textContent = '🔔 NOTIFS ON';
    btn.classList.add('notif-active');
    showToast('Notifications navigateur activées !', 'success', 3000);
  } else {
    showToast('Notifications refusées par le navigateur', 'warning', 4000);
  }
});

// Sync état bouton au chargement
(function syncNotifButton() {
  if (Notification.permission === 'granted') {
    const btn = $('btn-notify');
    if (btn) { btn.textContent = '🔔 NOTIFS ON'; btn.classList.add('notif-active'); }
  }
})();

// ─── Update Badge ─────────────────────────────────────────

let unreadThreats = 0;

function addUpdateBadge(count) {
  unreadThreats += count;
  const badge = $('update-badge');
  if (!badge) return;
  badge.textContent = unreadThreats > 99 ? '99+' : unreadThreats;
  badge.classList.remove('hidden');
}

function clearUpdateBadge() {
  unreadThreats = 0;
  const badge = $('update-badge');
  if (badge) badge.classList.add('hidden');
}

// ─── Auto-Refresh (scan toutes les 5 minutes) ────────────

const AUTO_REFRESH_SECS = 5 * 60;
let autoRefreshRemaining = AUTO_REFRESH_SECS;

function startAutoRefresh() {
  setInterval(() => {
    autoRefreshRemaining--;
    if (autoRefreshRemaining <= 0) {
      autoRefreshRemaining = AUTO_REFRESH_SECS;
      silentAutoCheck();
    }
    const el = $('auto-refresh-countdown');
    if (el) {
      const m = Math.floor(autoRefreshRemaining / 60);
      const s = autoRefreshRemaining % 60;
      el.textContent = `${m}:${s.toString().padStart(2, '0')}`;
    }
  }, 1000);
}

async function silentAutoCheck() {
  try {
    const result = await apiFetch('/update-check');
    if (result.new_count > 0) {
      const toastType = 'warning';
      showToast(
        `⚡ <strong>${result.new_count}</strong> nouvelle${result.new_count > 1 ? 's' : ''} menace${result.new_count > 1 ? 's' : ''} détectée${result.new_count > 1 ? 's' : ''} — clique sur UPDATE`,
        toastType,
        8000
      );
      addUpdateBadge(result.new_count);
      sendBrowserNotification(
        `${result.new_count} nouvelle${result.new_count > 1 ? 's' : ''} menace${result.new_count > 1 ? 's' : ''} détectée${result.new_count > 1 ? 's' : ''}`,
        result.sources_checked?.join(' · ') || 'Nouvelle activité threat intelligence'
      );
      await loadStats();
      await loadTicker();
      await fetchVulnerabilities();
    } else {
      showToast('Auto-scan terminé — aucune nouvelle menace', 'info', 3000);
    }
  } catch { /* silencieux */ }
}

// ─── Event Wiring ────────────────────────────────────────

// Search (debounced)
searchInput.addEventListener('input', debounce(e => {
  state.query = e.target.value.trim();
  state.page = 1;
  fetchVulnerabilities();
}, DEBOUNCE_MS));

// Keyboard shortcut Ctrl+K
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    searchInput.focus();
    searchInput.select();
  }
  if (e.key === 'Escape') {
    closeDetail();
    closeUpdateModal();
  }
});

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.filter = btn.dataset.filter;
    state.page = 1;
    fetchVulnerabilities();
  });
});

// CVSS slider
cvssSlider.addEventListener('input', debounce(e => {
  state.minCvss = parseFloat(e.target.value);
  cvssVal.textContent = state.minCvss.toFixed(1);
  state.page = 1;
  fetchVulnerabilities();
}, 200));

// Update button
btnUpdate.addEventListener('click', runUpdateCheck);

// ─── Toggle Langue FR/EN ─────────────────────────────────

function toggleLang() {
  state.lang = state.lang === 'en' ? 'fr' : 'en';
  const isFr = state.lang === 'fr';
  langFlag.textContent = isFr ? '🇫🇷' : '🇬🇧';
  langLabel.textContent = isFr ? 'FR' : 'EN';
  langToggle.classList.toggle('fr-active', isFr);
  fetchVulnerabilities(); // Re-render les cards avec la bonne langue
}

langToggle.addEventListener('click', toggleLang);

// ─── Traduire Tout ───────────────────────────────────────

async function runTranslateAll() {
  // Vérifier le statut d'abord
  let status;
  try { status = await apiFetch('/translation-status'); }
  catch { status = { pending: '?', engine_available: false }; }

  if (!status.engine_available) {
    $('translate-modal-body').innerHTML = `
      <div class="empty-state">
        <h3>⚠ Module manquant</h3>
        <p>Lance <code>start.bat</code> pour installer <strong>deep-translator</strong> automatiquement.</p>
        <p style="margin-top:8px;font-size:11px;color:var(--text-dim)">Ou manuellement : python -m pip install deep-translator</p>
      </div>`;
    translateOverlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    return;
  }

  translateOverlay.classList.add('open');
  document.body.style.overflow = 'hidden';
  btnTranslateAll.classList.add('loading');

  let totalTranslated = 0;
  let remaining = status.pending;

  const showProgress = (done, left, msg) => {
    $('translate-modal-body').innerHTML = `
      <div class="update-scanning">
        <div class="spinner"></div>
        <p style="font-weight:700;color:var(--accent-green)">${done} entrée(s) traduite(s)</p>
        <p style="font-size:11px;color:var(--text-muted)">${left} restante(s) — ${msg}</p>
        <p style="font-size:10px;color:var(--text-dim);margin-top:8px">Les termes techniques restent en anglais (CVE, protocoles, malwares…)</p>
      </div>`;
  };

  showProgress(0, remaining, 'Démarrage…');

  // Boucle de traduction par batch de 10
  while (remaining > 0) {
    try {
      const result = await apiFetch('/translate-all?batch=10');
      totalTranslated += result.translated;
      remaining = result.remaining;
      showProgress(totalTranslated, remaining, result.message);
      if (result.translated === 0) break; // Sécurité
    } catch (err) {
      $('translate-modal-body').innerHTML = `
        <div class="empty-state"><h3>⚠ Erreur</h3><p>${err.message}</p></div>`;
      break;
    }
  }

  // Résultat final
  if (remaining === 0) {
    $('translate-modal-body').innerHTML = `
      <div class="update-result">
        <div class="new-count" style="color:var(--accent-cyan)">✓</div>
        <div class="new-label">Traduction terminée !</div>
        <div class="update-sources">
          <div class="source-item">
            <span>Entrées traduites cette session</span>
            <span class="src-count">+${totalTranslated}</span>
          </div>
          <div class="source-item">
            <span>Restant à traduire</span>
            <span class="src-count">0</span>
          </div>
        </div>
        <div class="update-ts">Active le toggle 🇫🇷 FR pour voir les traductions</div>
      </div>`;
    // Activer FR automatiquement si pas encore actif
    if (state.lang !== 'fr') toggleLang();
    else fetchVulnerabilities();
  }

  btnTranslateAll.classList.remove('loading');
}

btnTranslateAll.addEventListener('click', runTranslateAll);
$('translate-modal-close').addEventListener('click', () => {
  translateOverlay.classList.remove('open');
  document.body.style.overflow = '';
});
translateOverlay.addEventListener('click', e => {
  if (e.target === translateOverlay) { translateOverlay.classList.remove('open'); document.body.style.overflow = ''; }
});

// Close modals
$('modal-close').addEventListener('click', closeDetail);
$('update-modal-close').addEventListener('click', closeUpdateModal);
detailOverlay.addEventListener('click', e => { if (e.target === detailOverlay) closeDetail(); });
updateOverlay.addEventListener('click', e => { if (e.target === updateOverlay) closeUpdateModal(); });

// ─── Boot ────────────────────────────────────────────────

async function boot() {
  await checkHealth();
  await Promise.all([
    loadStats(),
    loadTicker(),
    fetchVulnerabilities(),
  ]);

  // Démarrer l'auto-refresh (scan toutes les 5 minutes)
  startAutoRefresh();

  // Auto-check au démarrage (non bloquant)
  setTimeout(async () => {
    try {
      const result = await apiFetch('/update-check');
      if (result.new_count > 0) {
        showToast(
          `⚡ <strong>${result.new_count}</strong> nouvelle${result.new_count > 1 ? 's' : ''} menace${result.new_count > 1 ? 's' : ''} détectée${result.new_count > 1 ? 's' : ''} — clique sur UPDATE`,
          'warning',
          8000
        );
        addUpdateBadge(result.new_count);
        sendBrowserNotification(
          `${result.new_count} nouvelle${result.new_count > 1 ? 's' : ''} menace${result.new_count > 1 ? 's' : ''}`,
          result.sources_checked?.join(' · ') || 'Nouvelle activité détectée'
        );
        await loadStats();
        await loadTicker();
        await fetchVulnerabilities();
      }
    } catch { /* serveur non disponible, ignorer */ }
  }, 1500);
}

boot();
