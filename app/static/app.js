'use strict';
let isRunning = false;
let currentReport = null;

async function startAnalysis() {
  if (isRunning) return;
  isRunning = true;

  setStatus('running', 'Analysing…');
  setButtonState(true);
  clearRisksGrid();
  showProgressPanel(true);
  clearProgressLog();
  hideStats();

  try {
    await runWithSSE();
  } catch (err) {
    console.error('Analysis failed:', err);
    showToast('❌ ' + (err.message || 'Analysis failed'), 'error');
    setStatus('ready', 'Error — retry');
  } finally {
    isRunning = false;
    setButtonState(false);
  }
}

function runWithSSE() {
  return new Promise((resolve, reject) => {
    const es = new EventSource('/api/analyze/stream');

    es.onmessage = (evt) => {
      let payload;
      try { payload = JSON.parse(evt.data); }
      catch { return; }

      if (payload.type === 'progress') {
        appendLog(payload.message);
      } else if (payload.type === 'result') {
        es.close();
        showProgressPanel(false);
        renderReport(payload.data);
        resolve(payload.data);
      } else if (payload.type === 'error') {
        es.close();
        showProgressPanel(false);
        reject(new Error(payload.message));
      }
    };

    es.onerror = (err) => {
      es.close();
      reject(new Error('Connection lost — is the server running?'));
    };
  });
}

function renderReport(report) {
  currentReport = report;

  document.getElementById('stat-assets').textContent = report.total_assets;
  document.getElementById('stat-vulns').textContent = report.total_vulnerabilities;
  document.getElementById('stat-intel').textContent = report.total_threat_intel;
  document.getElementById('stat-duration').textContent = report.pipeline_duration_seconds;
  showStats(true);

  const ts = document.getElementById('gen-time');
  ts.textContent = formatDate(report.generated_at);
  document.getElementById('timestamp-badge').style.display = 'flex';

  document.getElementById('risks-header').style.display = 'flex';
  document.getElementById('empty-state').style.display = 'none';

  const grid = document.getElementById('risks-grid');
  grid.innerHTML = '';

  report.top_risks.forEach(entry => {
    const card = buildRiskCard(entry);
    grid.appendChild(card);
    requestAnimationFrame(() => {
      const bar = card.querySelector('.score-bar-fill');
      if (bar) bar.style.width = entry.risk_score + '%';
    });
  });

  setStatus('ready', `Analysis complete — ${report.top_risks.length} risks ranked`);
  showToast('✅ Risk analysis complete', 'success');

  if (report.errors && report.errors.length > 0) {
    report.errors.forEach(e => appendLog('⚠ ' + e));
    showProgressPanel(true);
  }
}

function buildRiskCard(entry) {
  const severity = getSeverity(entry.risk_score);

  const article = document.createElement('article');
  article.className = `risk-card severity-${severity}`;
  article.setAttribute('role', 'listitem');
  article.setAttribute('aria-label', `Risk ${entry.rank}: ${entry.vuln_name}`);

  article.innerHTML = `
    <div class="card-header">
      <div class="card-rank-block">
        <div class="rank-badge ${severity}" aria-label="Rank ${entry.rank}">#${entry.rank}</div>
        <div class="card-title-block">
          <h3>${escHtml(entry.vuln_name)}</h3>
          <div class="card-subtitle">
            <span class="code" style="font-family:var(--font-mono);color:var(--text-code)">${escHtml(entry.cve)}</span>
            <span class="dot-sep">·</span>
            <span>${escHtml(entry.asset_name)}</span>
            <span class="dot-sep">·</span>
            <span>${escHtml(entry.environment)}</span>
          </div>
        </div>
      </div>
      <div class="score-block">
        <div class="score-value ${severity}" aria-label="Risk score ${entry.risk_score} out of 100">
          ${entry.risk_score}
        </div>
        <div class="score-label">Risk Score / 100</div>
        <div class="score-bar" role="progressbar" aria-valuenow="${entry.risk_score}" aria-valuemin="0" aria-valuemax="100" aria-label="Risk score bar">
          <div class="score-bar-fill" style="width:0%"></div>
        </div>
      </div>
    </div>

    <div class="tags" aria-label="Risk tags">
      ${entry.internet_exposed ? '<span class="tag tag-internet">🌐 Internet Exposed</span>' : ''}
      ${entry.exploit_available ? '<span class="tag tag-exploit">💥 Active Exploit</span>' : ''}
      ${entry.has_ransomware ? '<span class="tag tag-ransomware">🔒 Ransomware Campaign</span>' : ''}
      ${entry.kev_confirmed ? '<span class="tag tag-kev">⚠ CISA KEV</span>' : ''}
      ${!entry.edr_installed ? '<span class="tag tag-no-edr">🚫 No EDR</span>' : ''}
      ${entry.bs_compliance_scope.includes('PCI DSS') ? '<span class="tag tag-pci">💳 PCI DSS</span>' : ''}
      ${entry.bs_compliance_scope.includes('GDPR') ? '<span class="tag tag-gdpr">🇪🇺 GDPR</span>' : ''}
    </div>

    <div class="info-grid">
      <div class="info-item">
        <div class="info-item-label">Asset</div>
        <div class="info-item-value">${escHtml(entry.asset_name)}</div>
      </div>
      <div class="info-item">
        <div class="info-item-label">Asset Type</div>
        <div class="info-item-value">${escHtml(entry.asset_type)} &mdash; ${escHtml(entry.location)}</div>
      </div>
      <div class="info-item">
        <div class="info-item-label">CVSS Score</div>
        <div class="info-item-value code">${entry.cvss} &mdash; ${cvssLabel(entry.cvss)}</div>
      </div>
      <div class="info-item">
        <div class="info-item-label">Days Open</div>
        <div class="info-item-value code" style="color:${entry.days_open > 60 ? '#f87171' : 'var(--text-primary)'}">${entry.days_open} days</div>
      </div>
      <div class="info-item">
        <div class="info-item-label">Business Service</div>
        <div class="info-item-value">${escHtml(entry.business_service)}</div>
      </div>
      <div class="info-item">
        <div class="info-item-label">Revenue Impact / RTO</div>
        <div class="info-item-value">${escHtml(entry.bs_revenue_impact)} &mdash; ${entry.bs_rto_hours}h RTO</div>
      </div>
      ${entry.threat_actors && entry.threat_actors.length > 0 ? `
      <div class="info-item">
        <div class="info-item-label">Threat Actor(s)</div>
        <div class="info-item-value" style="color:#fca5a5">${entry.threat_actors.map(escHtml).join(', ')}</div>
      </div>
      <div class="info-item">
        <div class="info-item-label">Campaign</div>
        <div class="info-item-value" style="color:#fdba74">${entry.campaigns.map(escHtml).join(', ')}</div>
      </div>
      ` : `
      <div class="info-item">
        <div class="info-item-label">Threat Intel Match</div>
        <div class="info-item-value" style="color:var(--text-muted)">No matched campaign</div>
      </div>
      `}
    </div>

    <div class="narrative-block">
      <div class="narrative-label">
        🎯 Why This Ranks #${entry.rank}
      </div>
      <div class="narrative-text">${escHtml(entry.ranking_reason || '—')}</div>
    </div>

    ${entry.nist_control_id ? `
    <div class="nist-block">
      <div class="nist-header">
        <span class="nist-badge">${escHtml(entry.nist_control_id)}</span>
        <span class="nist-title">${escHtml(entry.nist_control_title)}</span>
        ${entry.nist_family ? `<span class="nist-family">${escHtml(entry.nist_family)}</span>` : ''}
      </div>
      <div class="narrative-label" style="color: #c4b5fd; border: none; margin: 0 0 6px;">
        📖 NIST SP 800-53 Control Guidance (retrieved)
      </div>
      <div class="nist-prose">${escHtml(entry.nist_prose || '').slice(0, 1200)}${entry.nist_prose && entry.nist_prose.length > 1200 ? '…' : ''}</div>
      ${entry.nist_application ? `
      <div class="nist-application">💡 ${escHtml(entry.nist_application)}</div>
      ` : ''}
    </div>
    ` : `
    <div class="nist-block" style="text-align:center;color:var(--text-muted);font-size:13px;">
      No NIST control retrieved for this entry.
    </div>
    `}

    <button
      class="breakdown-toggle"
      id="toggle-${entry.rank}"
      onclick="toggleBreakdown(${entry.rank})"
      aria-expanded="false"
      aria-controls="breakdown-${entry.rank}"
    >
      Show score breakdown ▾
    </button>
    <div class="breakdown-panel" id="breakdown-${entry.rank}" role="region" aria-label="Score breakdown for risk ${entry.rank}">
      ${buildBreakdown(entry.score_breakdown)}
    </div>
  `;

  return article;
}

function buildBreakdown(breakdown) {
  if (!breakdown) return '<em style="color:var(--text-muted);font-size:12px">No breakdown available</em>';

  const dims = [
    { key: 'internet_exposure', label: 'Internet Exposure', w: '25%' },
    { key: 'active_exploit', label: 'Active Exploit', w: '20%' },
    { key: 'ransomware_campaign', label: 'Ransomware Campaign', w: '20%' },
    { key: 'business_criticality', label: 'Business Criticality', w: '15%' },
    { key: 'cvss_normalised', label: 'CVSS (normalised)', w: '10%' },
    { key: 'controls_gap', label: 'Controls Gap', w: '10%' },
  ];

  return `
    <div class="breakdown-grid">
      ${dims.map(d => `
        <div class="breakdown-item">
          <div class="breakdown-dim">${d.label} <span style="color:var(--text-muted)">(${d.w})</span></div>
          <div class="breakdown-bar-wrap">
            <div class="breakdown-bar">
              <div class="breakdown-fill" style="width:${(breakdown[d.key] || 0) * 10}%"></div>
            </div>
            <div class="breakdown-num">${(breakdown[d.key] || 0).toFixed(1)}</div>
          </div>
        </div>
      `).join('')}
    </div>
    <div style="margin-top:10px;font-size:11px;color:var(--text-muted)">
      Risk Appetite Multiplier: ×${(breakdown.risk_appetite_multiplier || 1).toFixed(2)} &nbsp;|&nbsp;
      Raw weighted: ${(breakdown.raw_weighted || 0).toFixed(3)} → Score: ${(breakdown.raw_weighted * 10 * (breakdown.risk_appetite_multiplier || 1)).toFixed(1)}/100
    </div>
  `;
}

function toggleBreakdown(rank) {
  const panel = document.getElementById('breakdown-' + rank);
  const btn = document.getElementById('toggle-' + rank);
  const isOpen = panel.classList.contains('open');
  panel.classList.toggle('open', !isOpen);
  btn.setAttribute('aria-expanded', !isOpen);
  btn.textContent = isOpen ? 'Show score breakdown ▾' : 'Hide score breakdown ▴';
}

function setStatus(state, text) {
  const dot = document.getElementById('status-dot');
  const txt = document.getElementById('status-text');
  dot.className = 'status-dot' + (state === 'running' ? ' running' : '');
  txt.textContent = text;
}

function setButtonState(running) {
  const btn = document.getElementById('btn-analyze');
  const icon = document.getElementById('btn-icon');
  const txt = document.getElementById('btn-text');
  btn.disabled = running;
  icon.innerHTML = running ? '<span class="spin">⟳</span>' : '⚡';
  txt.textContent = running ? 'Analysing…' : 'Run Risk Analysis';
}

function showProgressPanel(show) {
  document.getElementById('progress-panel').classList.toggle('visible', show);
}

function clearProgressLog() {
  document.getElementById('progress-log').innerHTML = '';
}

function appendLog(msg) {
  const log = document.getElementById('progress-log');
  const line = document.createElement('div');
  line.className = 'log-line' + (msg.startsWith('   ✓') || msg.startsWith('✅') ? ' highlight' : '');
  line.textContent = msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function clearRisksGrid() {
  const grid = document.getElementById('risks-grid');
  grid.innerHTML = '<div class="empty-state" id="empty-state" role="status"><span class="emoji">⚙️</span><h3>Analysis in progress…</h3><p>Watch the pipeline log above.</p></div>';
  document.getElementById('risks-header').style.display = 'none';
}

function showStats(show) {
  document.getElementById('stats-bar').style.display = show ? 'grid' : 'none';
}

function hideStats() {
  showStats(false);
}

function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = `toast ${type}`;
  toast.style.display = 'block';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.style.display = 'none'; }, 4000);
}

function getSeverity(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  return 'medium';
}

function cvssLabel(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return 'N/A';
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
    });
  } catch { return iso; }
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
