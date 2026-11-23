'use strict';

const STORAGE_KEY = 'cybershield-ai-scan-history-v1';
const MAX_HISTORY = 200;
const views = ['dashboard', 'url-scanner', 'message-analyzer', 'threat-monitor', 'awareness', 'history', 'about'];
const labels = {
  dashboard: 'Dashboard', 'url-scanner': 'URL Scanner', 'message-analyzer': 'Message Analyzer',
  'threat-monitor': 'Threat Monitor', awareness: 'Security Awareness', history: 'Scan History', about: 'About AI'
};
let scanHistory = loadHistory();
let activeView = 'dashboard';
let scanInProgress = false;
let feedTimer = null;
let feedRunning = false;
let quizIndex = 0;
let quizScore = 0;
let quizAnswered = false;

const samples = {
  urgent: 'URGENT: Your account will be suspended today. Verify your password and send the one-time code to restore access: http://secure-account-check.example.com/login',
  safe: 'Hi Alex, our team meeting is at 2:30 PM in the usual room. Please bring the draft agenda. Thanks!',
  prize: 'Congratulations! You have won a free gift card. Claim your reward now before it expires. Provide your bank details to receive your prize!'
};

const simulatedEvents = [
  { name: 'Multiple failed login attempts', source: '198.51.100.24', severity: 'high', note: '5 failures in 2 minutes · threshold exceeded', category: 'failed-login' },
  { name: 'Unusual login location', source: '203.0.113.17', severity: 'medium', note: 'New fictional region · review suggested', category: 'location' },
  { name: 'Repeated access requests', source: '192.0.2.88', severity: 'medium', note: 'Request rate above simulated baseline', category: 'requests' },
  { name: 'Routine sign-in event', source: '192.0.2.41', severity: 'low', note: 'Within the fictional activity baseline', category: 'routine' },
  { name: 'Suspicious resource access', source: '203.0.113.62', severity: 'high', note: 'Restricted path pattern · simulated alert', category: 'access' },
  { name: 'Unusual network activity', source: '198.51.100.73', severity: 'medium', note: 'Unexpected volume in simulated traffic', category: 'network' },
  { name: 'Routine session refresh', source: '192.0.2.19', severity: 'low', note: 'Expected fictional session behavior', category: 'routine' }
];

const learningTopics = [
  { icon: '✉', color: 'cyan', title: 'Phishing', tag: 'EMAIL & MESSAGES', text: 'Fraudulent messages try to trick you into revealing information or clicking a harmful link. Check the sender and verify requests through a trusted channel.' },
  { icon: '⌁', color: 'red', title: 'Malware', tag: 'DEVICE SAFETY', text: 'Malware is software designed to disrupt, spy on, or gain unauthorized access to a device. Install updates and use reputable protection tools.' },
  { icon: '▣', color: 'orange', title: 'Ransomware', tag: 'DATA PROTECTION', text: 'Ransomware can lock files and demand payment. Keep separate backups and avoid opening unexpected attachments or downloads.' },
  { icon: '⚿', color: 'purple', title: 'Password security', tag: 'ACCOUNT SAFETY', text: 'Use unique, long passwords for each account. A reputable password manager can help create and store them safely.' },
  { icon: '◎', color: 'green', title: 'Social engineering', tag: 'HUMAN FACTORS', text: 'Attackers may impersonate a trusted person and create urgency. Pause, verify unusual requests independently, and do not share codes.' },
  { icon: '✧', color: 'blue', title: 'Two-factor authentication', tag: 'EXTRA PROTECTION', text: 'A second sign-in factor adds protection if a password is exposed. Prefer an authenticator app or security key where available.' },
  { icon: '◉', color: 'cyan', title: 'Safe browsing', tag: 'EVERYDAY HABITS', text: 'Check the exact domain, use secure connections, keep your browser updated, and be cautious with unexpected downloads and pop-ups.' }
];

const quizQuestions = [
  { question: 'A message says your account will close in 10 minutes and asks for your password. What is the safest next step?', options: ['Reply with your password to keep access', 'Use the message link to sign in quickly', 'Do not use the link; verify through the official app or website', 'Forward it to all your contacts'], answer: 2, explanation: 'Urgency plus a password request is a strong warning sign. Use a known, official route to check your account.' },
  { question: 'Which password habit offers the strongest protection across accounts?', options: ['Reuse one memorable password', 'Use a unique, long password for each account', 'Add an exclamation mark to your name', 'Change only one character each month'], answer: 1, explanation: 'Unique passwords help prevent a breach on one service from unlocking your other accounts.' },
  { question: 'Someone claiming to be support asks you to read out a one-time code. What should you do?', options: ['Share it if they know your name', 'Share only the first half', 'Never share it; contact support through a trusted channel', 'Post it in a support forum'], answer: 2, explanation: 'One-time codes are for you to enter during sign-in, not to disclose to another person.' },
  { question: 'What does two-factor authentication add to an account?', options: ['A second kind of verification beyond a password', 'Automatic removal of every phishing email', 'A guarantee that a device cannot get malware', 'A replacement for software updates'], answer: 0, explanation: 'A second factor can reduce the impact of a stolen password, though it does not eliminate every risk.' },
  { question: 'A link text says “trusted-bank.com,” but the actual address is unfamiliar. What is a good choice?', options: ['Click because the text looks correct', 'Hover or inspect the real address and verify independently', 'Enter your bank password to test it', 'Open it on a different device'], answer: 1, explanation: 'Displayed text can differ from a link destination. Navigate using a known bookmark or the official app instead.' }
];

function loadHistory() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) throw new Error('Stored history is not a list.');
    return parsed.filter((item) =>
      item && typeof item.id === 'string' &&
      (item.type === 'URL' || item.type === 'Message') &&
      typeof item.item === 'string' &&
      Number.isFinite(item.score) &&
      ['Low Risk', 'Medium Risk', 'High Risk'].includes(item.classification) &&
      typeof item.createdAt === 'string'
    ).slice(0, MAX_HISTORY);
  } catch (error) {
    showToast('Saved history could not be read. New scans can still be analyzed.', 'warning');
    return [];
  }
}

function saveHistory(record) {
  scanHistory.unshift(record);
  scanHistory = scanHistory.slice(0, MAX_HISTORY);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(scanHistory));
  } catch (error) {
    scanHistory.shift();
    showToast('This scan was analyzed, but browser storage could not save it.', 'error');
  }
  renderAllHistoryViews();
}

function showToast(message, type) {
  const region = document.getElementById('toastRegion');
  const toast = document.createElement('div');
  toast.className = `toast${type ? ` ${type}` : ''}`;
  toast.textContent = message;
  region.appendChild(toast);
  window.setTimeout(() => toast.remove(), 4200);
}

function navigateTo(viewName) {
  if (!views.includes(viewName)) return;
  activeView = viewName;
  document.querySelectorAll('.view').forEach((view) => {
    view.classList.toggle('active', view.id === `view-${viewName}`);
  });
  document.querySelectorAll('[data-view]').forEach((button) => {
    button.classList.toggle('active', button.dataset.view === viewName);
    if (button.classList.contains('nav-link')) {
      button.setAttribute('aria-current', button.dataset.view === viewName ? 'page' : 'false');
    }
  });
  document.getElementById('currentPageLabel').textContent = labels[viewName];
  closeMobileMenu();
  if (viewName === 'history') renderHistory();
  if (viewName === 'dashboard') renderDashboard();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openMobileMenu() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('mobileOverlay').classList.add('open');
  document.getElementById('mobileMenu').setAttribute('aria-expanded', 'true');
}

function closeMobileMenu() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('mobileOverlay').classList.remove('open');
  document.getElementById('mobileMenu').setAttribute('aria-expanded', 'false');
}

function getClassification(score) {
  if (score >= 60) return 'High Risk';
  if (score >= 30) return 'Medium Risk';
  return 'Low Risk';
}

function riskClass(classification) {
  return classification.toLowerCase().split(' ')[0];
}

function normalizeUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) return { error: 'Enter a website URL to analyze.' };
  if (/\s/.test(trimmed)) return { error: 'A URL cannot contain spaces. Check the address and try again.' };
  const withProtocol = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(withProtocol);
  } catch (error) {
    return { error: 'That address does not look like a valid URL. Try a domain such as example.com.' };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { error: 'Only http:// and https:// website addresses can be analyzed.' };
  }
  if (!parsed.hostname || !parsed.hostname.includes('.') && parsed.hostname !== 'localhost') {
    return { error: 'Enter a domain name such as example.com.' };
  }
  if (parsed.username || parsed.password) {
    return { error: 'URLs containing embedded usernames or passwords are not accepted.' };
  }
  return { parsed, value: parsed.href };
}

function analyzeUrl(value) {
  const parsed = new URL(value);
  const hostname = parsed.hostname.toLowerCase();
  const full = value.toLowerCase();
  const findings = [];
  let score = 0;
  const add = (points, finding) => { score += points; findings.push(finding); };
  const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(hostname);
  const ipv6 = hostname.includes(':');
  if (ipv4 || ipv6) add(35, 'The host is a raw IP address rather than a familiar domain name.');
  if (value.length > 120) add(15, 'The URL is unusually long, which can make its true destination harder to inspect.');
  else if (value.length > 75) add(8, 'The URL is longer than typical and deserves a closer look.');
  if (/(^|\.)((bit\.ly)|(tinyurl\.com)|(t\.co)|(goo\.gl)|(is\.gd)|(cutt\.ly)|(ow\.ly)|(buff\.ly))$/i.test(hostname)) {
    add(25, 'The hostname belongs to a commonly used URL-shortening service, which hides the final destination.');
  }
  const knownBrands = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'bankofamerica', 'netflix'];
  const brandMention = knownBrands.find((brand) => hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.net`) && !hostname.endsWith(`${brand}.org`));
  if (brandMention) add(25, `The hostname contains “${brandMention}” in a way that may imitate a trusted brand.`);
  const labels = hostname.split('.');
  if (labels.length >= 5) add(12, 'The hostname has many subdomain levels, which may obscure the actual domain.');
  if (labels.length > 2 && knownBrands.some((brand) => labels.slice(0, -2).some((part) => part.includes(brand)))) {
    if (!findings.some((finding) => finding.includes('imitate a trusted brand'))) add(20, 'A trusted brand name appears in a subdomain rather than as the main domain.');
  }
  if (parsed.protocol === 'http:') add(10, 'The link uses HTTP rather than an encrypted HTTPS connection.');
  if (/(login|log-in|verify|verification|secure|account|signin|sign-in|update|password|wallet|confirm)/i.test(full)) {
    add(10, 'The URL contains account or sign-in language that can appear in credential-harvesting links.');
  }
  const specialCount = (value.match(/[@!$%*;()[\]{}\\]/g) || []).length;
  if (specialCount >= 4) add(12, 'The URL contains an unusually high number of special characters.');
  else if (specialCount >= 2) add(6, 'The URL includes several special characters that merit closer inspection.');
  if (hostname.includes('xn--')) add(18, 'The hostname uses encoded characters that can make look-alike domains harder to recognize.');
  score = Math.min(100, score);
  return { score, classification: getClassification(score), findings };
}

function analyzeMessage(text) {
  const normalized = text.toLowerCase();
  const findings = [];
  let score = 0;
  const add = (points, finding) => { score += points; findings.push(finding); };
  const rules = [
    { points: 18, pattern: /\b(urgent|immediately|act now|right away|within \d+ (minutes?|hours?)|expires? today)\b/i, label: 'Urgent or time-pressured language' },
    { points: 24, pattern: /\b(password|passcode|one[- ]time code|otp|verification code|security code|pin number)\b/i, label: 'A request or reference to passwords, PINs, or one-time codes' },
    { points: 14, pattern: /\b(suspended|locked|closed|terminated|unusual activity|unauthorized access|will be disabled)\b/i, label: 'Threatening account or access language' },
    { points: 20, pattern: /\b(won|winner|prize|free gift|gift card|claim your reward|congratulations)\b/i, label: 'A prize or reward claim' },
    { points: 24, pattern: /\b(bank details|banking information|credit card|card number|routing number|account number|payment details)\b/i, label: 'A request for banking or payment information' },
    { points: 13, pattern: /\b(verify|confirm|restore|update|validate)\b.{0,50}\b(account|identity|details|information|password)\b/i, label: 'A request to verify or update personal account details' },
    { points: 12, pattern: /\b(click here|open the attachment|enable macros|download now|visit this link)\b/i, label: 'A prompt to click, open, or download something' },
    { points: 10, pattern: /\b(official support|security team|your bank|account department|administrator)\b/i, label: 'A message claiming authority or trusted-organization status' }
  ];
  rules.forEach((rule) => { if (rule.pattern.test(normalized)) add(rule.points, rule.label); });
  const urls = text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
  if (urls.length) {
    add(Math.min(20, 10 + (urls.length - 1) * 4), `${urls.length} link${urls.length > 1 ? 's' : ''} included; verify the destination before opening.`);
    if (urls.some((url) => /bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly/i.test(url))) {
      add(10, 'A shortened link appears, so the final destination is not obvious from the message.');
    }
  }
  if (/\b(kindly|dear customer|dear user|valued customer|congratulations dear)\b/i.test(normalized)) {
    add(7, 'Generic or unusual wording may indicate an impersonal or suspicious message.');
  }
  if (/\b(share|send|reply with|provide)\b.{0,40}\b(code|password|otp|pin)\b/i.test(normalized) &&
      !findings.some((finding) => finding.startsWith('A request or reference'))) {
    add(24, 'The message appears to ask you to share an authentication secret.');
  }
  score = Math.min(100, score);
  return { score, classification: getClassification(score), findings };
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderResult(container, emptyContainer, record, analysis, type) {
  emptyContainer.classList.add('hidden');
  container.replaceChildren();
  container.classList.remove('hidden');

  const top = makeElement('div', 'result-topline');
  top.append(makeElement('span', `classification ${riskClass(analysis.classification)}`, `● ${analysis.classification}`));
  const score = makeElement('span', 'score-label');
  score.append(document.createTextNode('Risk score '));
  score.append(makeElement('strong', '', `${analysis.score}/100`));
  top.append(score);
  container.append(top);

  const meter = makeElement('div', 'meter-wrap');
  const meterHeading = makeElement('div', 'meter-heading');
  meterHeading.append(makeElement('span', '', 'HEURISTIC RISK LEVEL'), makeElement('span', '', `${analysis.score}%`));
  const track = makeElement('div', 'meter-track');
  const fill = makeElement('div', 'meter-fill');
  fill.style.width = '0%';
  track.append(fill);
  meter.append(meterHeading, track);
  container.append(meter);
  requestAnimationFrame(() => { fill.style.width = `${analysis.score}%`; });

  if (type === 'URL') {
    const item = makeElement('p', 'result-item', record.item);
    container.append(item);
  }
  container.append(makeElement('p', 'result-section-title', analysis.findings.length ? 'OBSERVED INDICATORS' : 'OBSERVED INDICATORS'));
  const list = makeElement('ul', 'finding-list');
  if (!analysis.findings.length) {
    list.append(makeElement('li', 'no-finding', 'No indicators from this small set of rules were matched.'));
  } else {
    analysis.findings.forEach((finding) => list.append(makeElement('li', '', finding)));
  }
  container.append(list);

  const recommendation = analysis.score >= 60
    ? 'Avoid opening the link or replying. Verify the sender or destination through a known, independent channel.'
    : analysis.score >= 30
      ? 'Pause and inspect the exact sender or domain. Do not share credentials or one-time codes, and confirm unexpected requests separately.'
      : 'No strong warning signs matched these simple rules. This does not prove the item is safe; use your normal security checks.';
  container.append(makeElement('p', 'result-section-title', 'RECOMMENDED ACTION'));
  container.append(makeElement('div', 'recommendation', recommendation));
  container.append(makeElement('p', 'result-note', type === 'URL'
    ? 'This local heuristic result is not a live reputation check or a safety guarantee.'
    : 'This local phrase check may miss context or incorrectly flag ordinary language.'));
}

function createHistoryRecord(type, item, analysis) {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type,
    item: type === 'Message' ? item.replace(/\s+/g, ' ').slice(0, 180) : item,
    score: analysis.score,
    classification: analysis.classification,
    reasons: analysis.findings,
    createdAt: new Date().toISOString()
  };
}

function setScanning(container, emptyContainer, actionText) {
  emptyContainer.classList.add('hidden');
  container.replaceChildren();
  container.classList.remove('hidden');
  const state = makeElement('div', 'scanning-state');
  state.append(makeElement('div', 'scan-ring', '⌕'), makeElement('strong', '', actionText));
  const progress = makeElement('div', 'scan-progress');
  progress.append(makeElement('span'));
  state.append(progress);
  container.append(state);
}

async function handleUrlSubmit(event) {
  event.preventDefault();
  if (scanInProgress) return;
  const errorNode = document.getElementById('urlError');
  errorNode.textContent = '';
  const normalized = normalizeUrl(document.getElementById('urlInput').value);
  if (normalized.error) {
    errorNode.textContent = normalized.error;
    document.getElementById('urlInput').focus();
    return;
  }
  scanInProgress = true;
  const button = document.getElementById('urlSubmit');
  button.disabled = true;
  setScanning(document.getElementById('urlResultContent'), document.getElementById('urlEmpty'), 'Checking URL patterns locally…');
  await new Promise((resolve) => window.setTimeout(resolve, 850));
  try {
    const analysis = analyzeUrl(normalized.value);
    const record = createHistoryRecord('URL', normalized.value, analysis);
    renderResult(document.getElementById('urlResultContent'), document.getElementById('urlEmpty'), record, analysis, 'URL');
    saveHistory(record);
    showToast(`URL analysis complete · ${analysis.classification.toLowerCase()} heuristic result`, analysis.score >= 60 ? 'warning' : '');
  } catch (error) {
    document.getElementById('urlResultContent').classList.add('hidden');
    document.getElementById('urlEmpty').classList.remove('hidden');
    errorNode.textContent = 'The URL could not be analyzed. Check its format and try again.';
  } finally {
    scanInProgress = false;
    button.disabled = false;
  }
}

async function handleMessageSubmit(event) {
  event.preventDefault();
  if (scanInProgress) return;
  const errorNode = document.getElementById('messageError');
  const text = document.getElementById('messageInput').value.trim();
  errorNode.textContent = '';
  if (!text) {
    errorNode.textContent = 'Paste or type a message before starting the analysis.';
    document.getElementById('messageInput').focus();
    return;
  }
  scanInProgress = true;
  const button = document.getElementById('messageSubmit');
  button.disabled = true;
  setScanning(document.getElementById('messageResultContent'), document.getElementById('messageEmpty'), 'Reviewing message patterns locally…');
  await new Promise((resolve) => window.setTimeout(resolve, 700));
  try {
    const analysis = analyzeMessage(text);
    const record = createHistoryRecord('Message', text, analysis);
    renderResult(document.getElementById('messageResultContent'), document.getElementById('messageEmpty'), record, analysis, 'Message');
    saveHistory(record);
    showToast(`Message analysis complete · ${analysis.classification.toLowerCase()} heuristic result`, analysis.score >= 60 ? 'warning' : '');
  } catch (error) {
    document.getElementById('messageResultContent').classList.add('hidden');
    document.getElementById('messageEmpty').classList.remove('hidden');
    errorNode.textContent = 'The message could not be analyzed. Please try again.';
  } finally {
    scanInProgress = false;
    button.disabled = false;
  }
}

function formatTime(dateString, includeDate) {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return 'Unknown time';
  return new Intl.DateTimeFormat(undefined, includeDate
    ? { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { hour: '2-digit', minute: '2-digit' }).format(date);
}

function renderHistory() {
  const body = document.getElementById('historyRows');
  body.replaceChildren();
  document.getElementById('historyTotal').textContent = String(scanHistory.length);
  document.getElementById('historyThreats').textContent = String(scanHistory.filter((item) => item.score >= 30).length);
  document.getElementById('historyLast').textContent = scanHistory.length ? formatTime(scanHistory[0].createdAt, false) : '—';
  if (!scanHistory.length) {
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 5;
    cell.append(makeEmptyState('No scan history yet', 'Analyze a URL or message to create your first local record.'));
    return;
  }
  scanHistory.forEach((item) => {
    const row = body.insertRow();
    const typeCell = row.insertCell();
    const type = makeElement('span', `type-label${item.type === 'Message' ? ' message' : ''}`);
    type.append(makeElement('span', '', item.type === 'URL' ? '↗' : '✉'));
    type.append(document.createTextNode(item.type));
    typeCell.append(type);
    row.insertCell().append(makeElement('span', 'item-cell', item.item));
    row.insertCell().append(makeElement('span', `classification ${riskClass(item.classification)}`, item.classification));
    row.insertCell().append(makeElement('span', 'score-cell', `${item.score}/100`));
    row.insertCell().append(makeElement('span', 'time-cell', formatTime(item.createdAt, true)));
  });
}

function makeEmptyState(title, message) {
  const empty = makeElement('div', 'empty-state compact');
  empty.append(makeElement('span', '', '◷'), makeElement('strong', '', title), makeElement('small', '', message));
  return empty;
}

function renderDashboard() {
  const total = scanHistory.length;
  const threats = scanHistory.filter((item) => item.score >= 30).length;
  const safe = scanHistory.filter((item) => item.score < 30).length;
  document.getElementById('totalScans').textContent = String(total);
  document.getElementById('threatCount').textContent = String(threats);
  document.getElementById('safeCount').textContent = String(safe);
  const status = document.getElementById('securityStatus');
  const note = document.getElementById('securityStatusNote');
  const global = document.getElementById('globalStatusText');
  if (total && threats) {
    status.textContent = 'REVIEW';
    status.style.color = 'var(--orange)';
    note.textContent = `${threats} result${threats === 1 ? '' : 's'} need attention`;
    global.textContent = 'REVIEW FINDINGS';
    global.style.color = 'var(--orange)';
  } else {
    status.textContent = total ? 'NOMINAL' : 'READY';
    status.style.color = 'var(--green)';
    note.textContent = total ? 'No medium or high findings' : 'No local findings yet';
    global.textContent = 'ALL SYSTEMS NOMINAL';
    global.style.color = 'var(--green)';
  }
  renderRecentRows();
  renderActivityChart();
}

function renderRecentRows() {
  const body = document.getElementById('dashboardRecent');
  body.replaceChildren();
  const recent = scanHistory.slice(0, 4);
  if (!recent.length) {
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 5;
    cell.append(makeEmptyState('No analyses yet', 'Your local scan results will appear here.'));
    return;
  }
  recent.forEach((item) => {
    const row = body.insertRow();
    row.insertCell().append(makeElement('span', 'type-label', item.type === 'URL' ? '↗  URL' : '✉  Message'));
    row.insertCell().append(makeElement('span', 'item-cell', item.item));
    row.insertCell().append(makeElement('span', `classification ${riskClass(item.classification)}`, item.classification));
    row.insertCell().append(makeElement('span', 'score-cell', `${item.score}/100`));
    row.insertCell().append(makeElement('span', 'time-cell', formatTime(item.createdAt, false)));
  });
}

function renderActivityChart() {
  const chart = document.getElementById('activityChart');
  chart.replaceChildren();
  const records = scanHistory.slice(0, 7).reverse();
  records.forEach((item) => {
    const group = makeElement('div', 'chart-bar-group');
    const height = Math.max(4, item.score);
    const bar = makeElement('div', 'chart-bar');
    bar.style.height = `${height}%`;
    const score = makeElement('span', 'chart-score', String(item.score));
    score.style.setProperty('--bar-height', `${height}%`);
    const date = makeElement('span', 'chart-date', formatTime(item.createdAt, false));
    group.append(score, bar, date);
    group.title = `${item.type}: ${item.classification} (${item.score}/100)`;
    chart.append(group);
  });
}

function renderAllHistoryViews() {
  renderDashboard();
  renderHistory();
}

function resetApplication() {
  const confirmed = window.confirm('Reset the dashboard? This permanently clears local scan history and resets the simulated feed and quiz score.');
  if (!confirmed) return;
  scanHistory = [];
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (error) {
    showToast('Browser storage could not be cleared. The current view has been reset.', 'warning');
  }
  if (feedTimer) window.clearInterval(feedTimer);
  feedTimer = null;
  feedRunning = false;
  eventList = createInitialEvents();
  updateFeedButton();
  resetQuiz();
  renderEvents();
  renderAllHistoryViews();
  document.getElementById('urlInput').value = '';
  document.getElementById('messageInput').value = '';
  document.getElementById('urlResultContent').classList.add('hidden');
  document.getElementById('messageResultContent').classList.add('hidden');
  document.getElementById('urlEmpty').classList.remove('hidden');
  document.getElementById('messageEmpty').classList.remove('hidden');
  showToast('Dashboard data and local scan history have been reset.');
}

function createInitialEvents() {
  const initial = [
    simulatedEvents[0],
    { ...simulatedEvents[0], name: 'Additional failed login burst', note: '3 failures in 1 minute · same fictional source' },
    ...simulatedEvents.slice(1, 4)
  ];
  return initial.map((event, index) => ({
    ...event,
    id: `seed-${index}`,
    time: new Date(Date.now() - (index + 1) * 4 * 60 * 1000)
  }));
}

let eventList = createInitialEvents();

function renderEvents() {
  const body = document.getElementById('eventRows');
  body.replaceChildren();
  const recent = eventList.slice(0, 12);
  recent.forEach((event) => {
    const row = body.insertRow();
    row.insertCell().append(makeElement('span', 'event-name', event.name));
    row.insertCell().append(makeElement('span', 'event-source', event.source));
    row.insertCell().append(makeElement('span', `severity-pill ${event.severity}`, event.severity));
    row.insertCell().append(makeElement('span', 'time-cell', formatTime(event.time.toISOString(), false)));
    row.insertCell().append(makeElement('span', 'event-note', event.note));
  });
  document.getElementById('eventCountLabel').textContent = `${eventList.length} fictional events`;
  updateEventStatistics();
}

function updateEventStatistics() {
  const counts = { high: 0, medium: 0, low: 0 };
  eventList.forEach((event) => { counts[event.severity] += 1; });
  document.getElementById('highEvents').textContent = String(counts.high);
  document.getElementById('mediumEvents').textContent = String(counts.medium);
  document.getElementById('lowEvents').textContent = String(counts.low);
  const failedBySource = {};
  eventList.filter((event) => event.category === 'failed-login').forEach((event) => {
    failedBySource[event.source] = (failedBySource[event.source] || 0) + 1;
  });
  const repeated = Object.entries(failedBySource).find(([, count]) => count >= 2);
  document.getElementById('anomalySummary').textContent = repeated ? 'Repeated login pattern flagged' : 'No threshold crossed';
  document.getElementById('anomalyDetail').textContent = repeated
    ? `${repeated[1]} failed-login events from fictional source ${repeated[0]} meet the demo threshold.`
    : 'Repeated failed logins from the same source trigger a simple count threshold.';

  const maximum = Math.max(counts.high, counts.medium, counts.low, 1);
  const bars = document.getElementById('severityBars');
  bars.replaceChildren();
  ['high', 'medium', 'low'].forEach((level) => {
    const row = makeElement('div', 'severity-row');
    row.append(makeElement('span', '', `${level[0].toUpperCase()}${level.slice(1)} risk`));
    const track = makeElement('div', 'severity-track');
    const fill = makeElement('span', `bar-${level}`);
    fill.style.width = `${Math.max(3, (counts[level] / maximum) * 100)}%`;
    track.append(fill);
    row.append(track, makeElement('strong', '', String(counts[level])));
    bars.append(row);
  });
}

function addSimulatedEvent() {
  const event = simulatedEvents[Math.floor(Math.random() * simulatedEvents.length)];
  const item = {
    ...event,
    id: `generated-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
    time: new Date()
  };
  eventList.unshift(item);
  eventList = eventList.slice(0, 30);
  renderEvents();
  showToast(`Fictional ${event.severity}-severity event added to the simulation.`, event.severity === 'high' ? 'warning' : '');
}

function updateFeedButton() {
  const status = document.querySelector('.feed-status');
  const label = document.getElementById('feedStatus');
  const button = document.getElementById('feedToggle');
  status.classList.toggle('running', feedRunning);
  label.textContent = feedRunning ? 'RUNNING' : 'PAUSED';
  button.textContent = feedRunning ? 'Ⅱ Pause feed' : '▶ Start feed';
}

function toggleFeed() {
  feedRunning = !feedRunning;
  if (feedRunning) {
    feedTimer = window.setInterval(addSimulatedEvent, 12000);
  } else if (feedTimer) {
    window.clearInterval(feedTimer);
    feedTimer = null;
  }
  updateFeedButton();
  showToast(feedRunning ? 'Simulated event feed started.' : 'Simulated event feed paused.');
}

function renderLearningCards() {
  const container = document.getElementById('learningCards');
  learningTopics.forEach((topic) => {
    const card = makeElement('article', 'panel learning-card');
    const head = makeElement('div', 'learning-card-head');
    head.append(makeElement('span', `learning-icon ${topic.color}`, topic.icon), makeElement('span', 'learn-tag', topic.tag));
    card.append(head, makeElement('h2', '', topic.title), makeElement('p', '', topic.text));
    container.append(card);
  });
}

function renderQuiz() {
  const container = document.getElementById('quizContent');
  const counter = document.getElementById('quizCounter');
  container.replaceChildren();
  if (quizIndex >= quizQuestions.length) {
    counter.textContent = 'COMPLETE';
    const complete = makeElement('div', 'quiz-complete');
    complete.append(makeElement('div', 'quiz-score-ring', `${quizScore}/${quizQuestions.length}`));
    complete.append(makeElement('h3', '', 'Quiz complete'));
    complete.append(makeElement('p', '', quizScore === quizQuestions.length
      ? 'Excellent work—you spotted every safer choice.'
      : 'Keep practicing these habits; awareness gets stronger with repetition.'));
    const restart = makeElement('button', 'button button-primary', '↻ Try again');
    restart.type = 'button';
    restart.addEventListener('click', resetQuiz);
    complete.append(restart);
    container.append(complete);
    return;
  }
  const question = quizQuestions[quizIndex];
  counter.textContent = `QUESTION ${quizIndex + 1} / ${quizQuestions.length}`;
  container.append(makeElement('p', 'quiz-question', question.question));
  const options = makeElement('div', 'quiz-options');
  question.options.forEach((option, index) => {
    const button = makeElement('button', 'quiz-option');
    button.type = 'button';
    button.append(makeElement('span', 'option-letter', String.fromCharCode(65 + index)), document.createTextNode(option));
    button.addEventListener('click', () => answerQuiz(index));
    options.append(button);
  });
  container.append(options);
  container.append(makeElement('div', 'quiz-feedback', ''));
  const controls = makeElement('div', 'quiz-controls');
  const next = makeElement('button', 'button button-primary hidden', quizIndex === quizQuestions.length - 1 ? 'See final score →' : 'Next question →');
  next.type = 'button';
  next.addEventListener('click', () => { quizIndex += 1; quizAnswered = false; renderQuiz(); });
  controls.append(next);
  container.append(controls);
}

function answerQuiz(selectedIndex) {
  if (quizAnswered) return;
  quizAnswered = true;
  const question = quizQuestions[quizIndex];
  const correct = selectedIndex === question.answer;
  if (correct) quizScore += 1;
  const buttons = document.querySelectorAll('.quiz-option');
  buttons.forEach((button, index) => {
    button.disabled = true;
    if (index === question.answer) button.classList.add('correct');
    else if (index === selectedIndex) button.classList.add('incorrect');
  });
  const feedback = document.querySelector('.quiz-feedback');
  feedback.classList.add('visible');
  if (!correct) feedback.classList.add('wrong');
  feedback.append(makeElement('strong', '', correct ? 'Correct.' : 'Not quite.'), document.createTextNode(question.explanation));
  document.querySelector('.quiz-controls .button').classList.remove('hidden');
}

function resetQuiz() {
  quizIndex = 0;
  quizScore = 0;
  quizAnswered = false;
  renderQuiz();
}

function initialize() {
  document.getElementById('todayLabel').textContent = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'short', day: 'numeric' }).format(new Date()).toUpperCase();
  document.querySelectorAll('[data-view]').forEach((button) => {
    button.addEventListener('click', () => navigateTo(button.dataset.view));
  });
  document.querySelectorAll('[data-go]').forEach((button) => {
    button.addEventListener('click', () => navigateTo(button.dataset.go));
  });
  document.getElementById('mobileMenu').addEventListener('click', () => {
    if (document.getElementById('sidebar').classList.contains('open')) closeMobileMenu();
    else openMobileMenu();
  });
  document.getElementById('mobileOverlay').addEventListener('click', closeMobileMenu);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeMobileMenu();
  });
  document.getElementById('urlForm').addEventListener('submit', handleUrlSubmit);
  document.getElementById('messageForm').addEventListener('submit', handleMessageSubmit);
  document.querySelectorAll('[data-url-example]').forEach((button) => {
    button.addEventListener('click', () => {
      document.getElementById('urlInput').value = button.dataset.urlExample;
      document.getElementById('urlError').textContent = '';
      document.getElementById('urlInput').focus();
    });
  });
  document.querySelectorAll('[data-message-sample]').forEach((button) => {
    button.addEventListener('click', () => {
      document.getElementById('messageInput').value = samples[button.dataset.messageSample] || '';
      document.getElementById('charCount').textContent = String(document.getElementById('messageInput').value.length);
      document.getElementById('messageError').textContent = '';
      document.getElementById('messageInput').focus();
    });
  });
  document.getElementById('messageInput').addEventListener('input', (event) => {
    document.getElementById('charCount').textContent = String(event.target.value.length);
  });
  document.getElementById('resetDashboard').addEventListener('click', resetApplication);
  document.getElementById('clearHistory').addEventListener('click', () => {
    if (!scanHistory.length) {
      showToast('There is no scan history to clear.', 'warning');
      return;
    }
    if (!window.confirm('Clear all saved scan history from this browser? This cannot be undone.')) return;
    scanHistory = [];
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      showToast('Browser storage could not be cleared.', 'error');
      return;
    }
    renderAllHistoryViews();
    showToast('Local scan history cleared.');
  });
  document.getElementById('feedToggle').addEventListener('click', toggleFeed);
  document.getElementById('addEvent').addEventListener('click', addSimulatedEvent);
  document.querySelector('.notice-close').addEventListener('click', () => {
    document.querySelector('.notice-banner').remove();
  });
  renderLearningCards();
  renderQuiz();
  renderEvents();
  updateFeedButton();
  renderAllHistoryViews();
}

initialize();
