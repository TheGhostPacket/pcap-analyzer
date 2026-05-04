let selectedFile = null;
let analysisResults = null;

// ── DRAG AND DROP ──
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');

uploadZone.addEventListener('click', () => fileInput.click());
uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('dragover'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) setFile(file);
});

fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) setFile(fileInput.files[0]);
});

function setFile(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['pcap', 'pcapng', 'cap'].includes(ext)) {
        showError('Invalid file type. Please upload a .pcap, .pcapng, or .cap file.');
        return;
    }
    if (file.size > 50 * 1024 * 1024) {
        showError('File too large. Maximum size is 50MB.');
        return;
    }
    selectedFile = file;
    document.getElementById('selectedFileName').textContent = file.name;
    document.getElementById('selectedFile').style.display = 'flex';
}

// ── ANALYSIS ──
async function startAnalysis() {
    if (!selectedFile) return;

    document.querySelector('.hero-section').style.display = 'none';
    document.getElementById('loadingSection').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';

    animateLoadingSteps();

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok || data.error) {
            throw new Error(data.error || 'Analysis failed');
        }

        analysisResults = data;
        renderResults(data);

    } catch (err) {
        document.querySelector('.hero-section').style.display = 'block';
        document.getElementById('loadingSection').style.display = 'none';
        showError(err.message);
    }
}

function animateLoadingSteps() {
    const steps = ['step1', 'step2', 'step3', 'step4'];
    let i = 0;
    const interval = setInterval(() => {
        if (i > 0) {
            document.getElementById(steps[i - 1]).classList.remove('active');
            document.getElementById(steps[i - 1]).classList.add('done');
        }
        if (i < steps.length) {
            document.getElementById(steps[i]).classList.add('active');
            i++;
        } else {
            clearInterval(interval);
        }
    }, 800);
}

// ── RENDER RESULTS ──
function renderResults(data) {
    document.getElementById('loadingSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'block';

    const { filename, findings, stats, summary } = data;

    // Header
    document.getElementById('reportFilename').textContent = filename;

    // Risk banner
    const banner = document.getElementById('riskBanner');
    banner.className = `risk-banner ${summary.risk_level}`;
    const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', CLEAN: '🟢' };
    document.getElementById('riskIcon').textContent = icons[summary.risk_level] || '⚪';
    document.getElementById('riskValue').textContent = summary.risk_level;

    // Summary cards
    document.getElementById('sumPackets').textContent = stats.total_packets?.toLocaleString() ?? '—';
    document.getElementById('sumDuration').textContent = stats.duration_seconds ?? '—';
    document.getElementById('sumFindings').textContent = summary.total_findings;
    document.getElementById('sumHosts').textContent = stats.unique_src_ips ?? '—';

    // Severity bars
    renderSeverityBars(summary);

    // Protocol bars
    renderProtocolBars(stats.protocols || {});

    // Top talkers
    renderTalkers(stats.top_talkers || []);

    // Findings
    renderFindings(findings);
}

function renderSeverityBars(summary) {
    const container = document.getElementById('severityBars');
    const levels = [
        { key: 'critical', label: 'Critical', cls: 'CRITICAL' },
        { key: 'high',     label: 'High',     cls: 'HIGH' },
        { key: 'medium',   label: 'Medium',   cls: 'MEDIUM' },
        { key: 'low',      label: 'Low',      cls: 'LOW' },
    ];
    const max = Math.max(...levels.map(l => summary[l.key] || 0), 1);

    container.innerHTML = levels.map(l => {
        const count = summary[l.key] || 0;
        const pct = Math.round((count / max) * 100);
        return `
            <div class="sev-bar-row">
                <div class="sev-bar-label">
                    <span>${l.label}</span><span>${count}</span>
                </div>
                <div class="sev-bar-track">
                    <div class="sev-bar-fill ${l.cls}" style="width:${count > 0 ? Math.max(pct, 4) : 0}%"></div>
                </div>
            </div>`;
    }).join('');
}

function renderProtocolBars(protocols) {
    const container = document.getElementById('protocolBars');
    const total = Object.values(protocols).reduce((a, b) => a + b, 0) || 1;
    const sorted = Object.entries(protocols).sort((a, b) => b[1] - a[1]);

    const colors = { TCP: '#0052CC', UDP: '#7C3AED', ICMP: '#DC2626', ARP: '#D97706', Other: '#6B7280' };

    container.innerHTML = sorted.map(([proto, count]) => {
        const pct = Math.round((count / total) * 100);
        return `
            <div class="sev-bar-row">
                <div class="sev-bar-label">
                    <span>${proto}</span><span>${pct}%</span>
                </div>
                <div class="sev-bar-track">
                    <div class="sev-bar-fill" style="width:${Math.max(pct,2)}%;background:${colors[proto]||'#6B7280'}"></div>
                </div>
            </div>`;
    }).join('');
}

function renderTalkers(talkers) {
    const container = document.getElementById('talkersList');
    if (!talkers.length) {
        container.innerHTML = '<p style="font-size:0.82rem;color:var(--muted);">No IP data available</p>';
        return;
    }
    const max = talkers[0].count || 1;
    container.innerHTML = talkers.map((t, i) => `
        <div class="talker-row">
            <span style="font-size:0.72rem;color:var(--muted);font-weight:700;width:16px;">${i + 1}</span>
            <span class="talker-ip">${t.ip}</span>
            <span class="talker-count">${t.count.toLocaleString()} pkts</span>
        </div>`).join('');
}

function renderFindings(findings) {
    const container = document.getElementById('findingsList');
    const noFindings = document.getElementById('noFindings');

    if (!findings.length) {
        container.innerHTML = '';
        noFindings.style.display = 'block';
        return;
    }

    noFindings.style.display = 'none';
    container.innerHTML = findings.map(f => `
        <div class="finding-item" data-severity="${f.severity}">
            <div>
                <span class="sev-badge ${f.severity}">${f.severity}</span>
            </div>
            <div>
                <div class="finding-cat">${f.category}</div>
                <div class="finding-title">${f.title}</div>
                <div class="finding-desc">${f.description}</div>
                ${f.indicator ? `<div class="finding-indicator">${f.indicator}</div>` : ''}
            </div>
        </div>`).join('');

    // Filter buttons
    document.querySelectorAll('#findingsFilter .filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#findingsFilter .filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const sev = btn.dataset.sev;
            document.querySelectorAll('.finding-item').forEach(item => {
                item.classList.toggle('hidden', sev !== 'all' && item.dataset.severity !== sev);
            });
        });
    });
}

// ── EXPORT ──
async function exportCSV() {
    if (!analysisResults) return;
    const response = await fetch('/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings: analysisResults.findings })
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pcap_analysis_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── RESET ──
function resetAnalyzer() {
    selectedFile = null;
    analysisResults = null;
    document.getElementById('selectedFile').style.display = 'none';
    document.getElementById('selectedFileName').textContent = '';
    fileInput.value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('loadingSection').style.display = 'none';
    document.querySelector('.hero-section').style.display = 'block';

    // Reset loading steps
    ['step1','step2','step3','step4'].forEach((id, i) => {
        const el = document.getElementById(id);
        el.classList.remove('active', 'done');
        if (i === 0) el.classList.add('active');
    });
}

// ── ERROR ──
function showError(msg) {
    document.getElementById('errorMessage').textContent = msg;
    document.getElementById('errorToast').style.display = 'flex';
    setTimeout(hideError, 6000);
}
function hideError() {
    document.getElementById('errorToast').style.display = 'none';
}
