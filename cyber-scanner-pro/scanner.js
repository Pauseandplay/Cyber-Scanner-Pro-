/**
 * Cyber Scanner Pro — scanner.js
 * Educational / demonstration scanner simulation.
 * No real network requests are made.
 */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────

let scanning  = false;
let logLines  = [];
let startTime = 0;

// ── Vulnerability Database ───────────────────────────────────────────────────

const VULN_DB = [
  { sev: 'critical', title: 'Remote Code Execution via Log4Shell',        detail: 'CVE-2021-44228 — Apache Log4j JNDI injection',              cve: 'CVE-2021-44228' },
  { sev: 'critical', title: 'SQL Injection — /api/users endpoint',         detail: 'Unsanitized input allows database exfiltration',             cve: 'CWE-89'         },
  { sev: 'high',     title: 'OpenSSL Heartbleed Vulnerability',            detail: 'CVE-2014-0160 — Memory leak exposes private keys',           cve: 'CVE-2014-0160'  },
  { sev: 'high',     title: 'Outdated SSH version (OpenSSH 7.2)',          detail: 'Multiple known CVEs; upgrade to 9.x recommended',           cve: 'CVE-2023-38408' },
  { sev: 'high',     title: 'HTTP Strict Transport Security missing',      detail: 'Site accessible over plain HTTP, MitM risk',                cve: 'CWE-16'         },
  { sev: 'medium',   title: 'SSL/TLS: TLS 1.0 and 1.1 enabled',           detail: 'Deprecated protocols with known weaknesses',                cve: 'CVE-2011-3389'  },
  { sev: 'medium',   title: 'X-Frame-Options header absent',              detail: 'Clickjacking attack vector present',                        cve: 'CWE-693'        },
  { sev: 'medium',   title: 'Directory listing enabled on /uploads/',      detail: 'Allows enumeration of file system contents',               cve: 'CWE-548'        },
  { sev: 'low',      title: 'Server version disclosure in headers',        detail: 'Apache/2.4.41 banner in HTTP response',                    cve: 'CWE-200'        },
  { sev: 'low',      title: 'Cookie missing Secure flag',                  detail: 'Session cookies transmittable over HTTP',                  cve: 'CWE-614'        },
  { sev: 'info',     title: 'Robots.txt reveals admin paths',              detail: '/admin, /cms, /backup exposed via robots.txt',             cve: 'INFO'           },
  { sev: 'info',     title: 'CDN detected: Cloudflare',                   detail: 'Origin IP may be hidden behind CDN proxy',                 cve: 'INFO'           },
];

// ── Port Database ────────────────────────────────────────────────────────────

const PORT_DB = [
  { port: 22,   proto: 'TCP', service: 'SSH',       version: 'OpenSSH 7.2',  state: 'open'     },
  { port: 25,   proto: 'TCP', service: 'SMTP',      version: 'Postfix 3.4',  state: 'open'     },
  { port: 53,   proto: 'UDP', service: 'DNS',       version: 'BIND 9.16',    state: 'open'     },
  { port: 80,   proto: 'TCP', service: 'HTTP',      version: 'Apache 2.4.41',state: 'open'     },
  { port: 110,  proto: 'TCP', service: 'POP3',      version: 'Dovecot',      state: 'open'     },
  { port: 143,  proto: 'TCP', service: 'IMAP',      version: 'Dovecot',      state: 'open'     },
  { port: 443,  proto: 'TCP', service: 'HTTPS',     version: 'TLS 1.2/1.3', state: 'open'     },
  { port: 445,  proto: 'TCP', service: 'SMB',       version: 'Samba 4.11',   state: 'filtered' },
  { port: 3306, proto: 'TCP', service: 'MySQL',     version: '8.0.28',       state: 'open'     },
  { port: 3389, proto: 'TCP', service: 'RDP',       version: 'Windows RDP',  state: 'closed'   },
  { port: 8080, proto: 'TCP', service: 'HTTP-ALT',  version: 'Nginx 1.18',   state: 'open'     },
  { port: 8443, proto: 'TCP', service: 'HTTPS-ALT', version: '',             state: 'filtered' },
];

// ── Scan Phases ──────────────────────────────────────────────────────────────

const SCAN_PHASES = [
  { label: 'RESOLVING HOST',    duration: 600  },
  { label: 'PORT DISCOVERY',   duration: 1200 },
  { label: 'SERVICE DETECTION',duration: 900  },
  { label: 'VULN ANALYSIS',    duration: 1400 },
  { label: 'SSL/TLS AUDIT',    duration: 700  },
  { label: 'FINALIZING',       duration: 400  },
];

// ── Log Script (simulated real-time output) ───────────────────────────────────

const LOG_SCRIPT = [
  [ 200,  'ok',   '→ Resolving target hostname...'                    ],
  [ 400,  'ok',   '→ Host resolved: 93.184.216.34'                    ],
  [ 600,  'info', '→ Starting TCP SYN scan on 1-65535'                ],
  [ 900,  'ok',   '→ Port 22/tcp  OPEN (SSH)'                         ],
  [ 1000, 'ok',   '→ Port 80/tcp  OPEN (HTTP)'                        ],
  [ 1100, 'ok',   '→ Port 443/tcp OPEN (HTTPS)'                       ],
  [ 1250, 'ok',   '→ Port 3306/tcp OPEN (MySQL)'                      ],
  [ 1400, 'warn', '→ Port 445/tcp FILTERED (SMB)'                     ],
  [ 1600, 'info', '→ Running service fingerprinting...'               ],
  [ 1900, 'warn', '⚠ OpenSSH 7.2 detected — CVE-2023-38408'          ],
  [ 2100, 'info', '→ SSL/TLS handshake analysis...'                   ],
  [ 2300, 'warn', '⚠ TLS 1.0 accepted — deprecated protocol'         ],
  [ 2500, 'err',  '✗ CRITICAL: Log4Shell pattern detected'            ],
  [ 2700, 'err',  '✗ SQL Injection potential in /api/users'           ],
  [ 2900, 'warn', '⚠ Missing HSTS header on HTTPS endpoint'          ],
  [ 3200, 'info', '→ Running vulnerability correlation...'            ],
  [ 3500, 'ok',   '→ Scan complete. Generating report...'             ],
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function timestamp() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0'))
    .join(':');
}

function addLog(msg, type = '') {
  logLines.push({ ts: timestamp(), msg, type });
  renderLog();
}

function renderLog() {
  const area = document.getElementById('logArea');
  area.innerHTML = logLines
    .map(l => `<div class="log-line"><span class="log-time">${l.ts}</span><span class="log-${l.type || 'dim'}">${escHtml(l.msg)}</span></div>`)
    .join('');
  area.scrollTop = area.scrollHeight;
}

function escHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function toggleOpt(el) {
  el.classList.toggle('active');
}

function switchTab(name) {
  const names = ['overview', 'vulns', 'ports', 'log'];
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', names[i] === name);
  });
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
}

// ── Export ────────────────────────────────────────────────────────────────────

function exportReport() {
  const target = document.getElementById('targetInput').value.trim() || 'unknown';
  const risk   = document.getElementById('mRisk').textContent;
  const vulns  = document.getElementById('mVulns').textContent;
  const ports  = document.getElementById('mPorts').textContent;

  const lines = [
    '=== CYBER SCANNER PRO — SCAN REPORT ===',
    `Date    : ${new Date().toISOString()}`,
    `Target  : ${target}`,
    `Risk    : ${risk}/100`,
    `Vulns   : ${vulns}`,
    `Ports   : ${ports} open`,
    '',
    '--- VULNERABILITIES ---',
    ...VULN_DB.slice(0, 9).map(v => `[${v.sev.toUpperCase().padEnd(8)}] ${v.title} (${v.cve})`),
    '',
    '--- OPEN PORTS ---',
    ...PORT_DB.filter(p => p.state === 'open').map(p => `${String(p.port).padStart(5)}/tcp  ${p.service.padEnd(12)} ${p.version}`),
    '',
    '--- SCAN LOG ---',
    ...logLines.map(l => `${l.ts}  ${l.msg}`),
    '',
    'NOTE: This report is for educational and authorised use only.',
  ];

  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `scan-report-${target.replace(/[^a-z0-9]/gi, '_')}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Core Scan ─────────────────────────────────────────────────────────────────

function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  if (!target || scanning) return;

  scanning  = true;
  logLines  = [];
  startTime = Date.now();

  // Reset UI
  document.getElementById('scanBtn').disabled    = true;
  document.getElementById('scanBtn').textContent = 'SCANNING...';
  document.getElementById('progressWrap').style.display = 'block';
  document.getElementById('idleState').style.display    = 'none';
  document.getElementById('overviewContent').style.display = 'none';
  document.getElementById('vulnsEmpty').style.display   = 'block';
  document.getElementById('portsEmpty').style.display   = 'block';
  document.getElementById('vulnsList').innerHTML  = '';
  document.getElementById('portsList').innerHTML  = '';
  document.getElementById('mPorts').textContent   = '—';
  document.getElementById('mVulns').textContent   = '—';
  document.getElementById('mRisk').textContent    = '—';
  document.getElementById('mTime').textContent    = '—';
  document.getElementById('vulnCount').textContent = '0';
  document.getElementById('portCount').textContent = '0';

  addLog(`→ Scan initiated: ${target}`, 'info');
  addLog('→ Loading threat intelligence database...', 'dim');

  // Build stage indicators
  const stagesEl = document.getElementById('progressStages');
  stagesEl.innerHTML = SCAN_PHASES.map(() => '<div class="stage-item"></div>').join('');
  const stageEls = stagesEl.querySelectorAll('.stage-item');

  // Schedule log events
  LOG_SCRIPT.forEach(([delay, type, msg]) => {
    setTimeout(() => addLog(msg, type), delay);
  });

  // Animate phases
  const totalDur = SCAN_PHASES.reduce((a, p) => a + p.duration, 0);
  let elapsed = 0;

  function runPhase(i) {
    if (i >= SCAN_PHASES.length) { finalizeScan(); return; }
    if (i > 0) stageEls[i - 1].classList.remove('active');
    stageEls[i].classList.add('active');
    document.getElementById('progressPhase').textContent = SCAN_PHASES[i].label;

    const dur   = SCAN_PHASES[i].duration;
    const steps = 20;
    let   step  = 0;

    const interval = setInterval(() => {
      step++;
      elapsed += (dur / steps);
      const pct = Math.min(99, Math.round(elapsed / totalDur * 100));
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressPct').textContent  = pct + '%';

      if (step >= steps) {
        clearInterval(interval);
        stageEls[i].classList.remove('active');
        stageEls[i].classList.add('done');
        runPhase(i + 1);
      }
    }, dur / steps);
  }

  runPhase(0);
}

// ── Finalize & Render Results ─────────────────────────────────────────────────

function finalizeScan() {
  const elapsed    = ((Date.now() - startTime) / 1000).toFixed(1);
  const vulns      = VULN_DB.slice(0, 9 + Math.floor(Math.random() * 3));
  const openPorts  = PORT_DB.filter(p => p.state === 'open').length;
  const critCount  = vulns.filter(v => v.sev === 'critical').length;
  const highCount  = vulns.filter(v => v.sev === 'high').length;
  const risk       = Math.min(98, critCount * 18 + highCount * 8 + 32);

  document.getElementById('progressFill').style.width      = '100%';
  document.getElementById('progressPct').textContent       = '100%';
  document.getElementById('progressPhase').textContent     = 'COMPLETE';

  setTimeout(() => {
    document.getElementById('progressWrap').style.display  = 'none';

    // Metrics
    document.getElementById('mPorts').textContent = openPorts;
    document.getElementById('mVulns').textContent = vulns.length;
    document.getElementById('mRisk').textContent  = risk;
    document.getElementById('mTime').textContent  = elapsed + 's';
    document.getElementById('vulnCount').textContent = vulns.length;
    document.getElementById('portCount').textContent = PORT_DB.length;

    // Risk ring
    const ringOffset = 157 - (157 * (risk / 100));
    const ringColor  = risk > 70 ? '#ff3b5c' : risk > 40 ? '#ffb800' : '#00ff9d';
    const ring = document.getElementById('scoreRing');
    ring.style.strokeDashoffset = ringOffset;
    ring.style.stroke           = ringColor;
    const ringScore = document.getElementById('ringScore');
    ringScore.textContent  = risk;
    ringScore.style.color  = ringColor;

    // Score breakdown bars
    const cats = [
      { label: 'Network Exposure',    val: Math.round(openPorts / PORT_DB.length * 100),                                              color: '#00b4ff' },
      { label: 'Vulnerability Index', val: Math.round(vulns.filter(v => ['critical','high'].includes(v.sev)).length / vulns.length * 100), color: '#ff3b5c' },
      { label: 'Config Hygiene',      val: Math.max(0, Math.round(100 - vulns.filter(v => v.sev === 'medium').length * 12)),          color: '#ffb800' },
      { label: 'SSL/TLS Posture',     val: 72,                                                                                        color: '#00ff9d' },
    ];

    document.getElementById('scoreBreakdown').innerHTML = cats.map(c => `
      <div class="score-row">
        <span class="score-row-label">${escHtml(c.label)}</span>
        <div class="score-track"><div class="score-bar" style="width:${c.val}%;background:${c.color}"></div></div>
        <span style="font-size:10px;color:${c.color};min-width:28px;text-align:right;font-family:var(--rfont)">${c.val}%</span>
      </div>`).join('');

    // Finding summary
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const summary  = sevOrder.map(s => {
      const n = vulns.filter(v => v.sev === s).length;
      if (!n) return '';
      return `<div class="finding-row ${s} fade-in">
        <span class="sev-badge ${s}">${s.toUpperCase()}</span>
        <div class="finding-info">
          <div class="finding-title">${n} ${s} finding${n > 1 ? 's' : ''} detected</div>
          <div class="finding-detail">review vulnerabilities tab for details</div>
        </div>
      </div>`;
    }).join('');

    document.getElementById('findingSummary').innerHTML = summary;
    document.getElementById('overviewContent').style.display = 'block';

    // Vulnerabilities list
    document.getElementById('vulnsEmpty').style.display = 'none';
    document.getElementById('vulnsList').innerHTML = vulns.map(v => `
      <div class="finding-row ${v.sev} fade-in">
        <span class="sev-badge ${v.sev}">${v.sev.toUpperCase()}</span>
        <div class="finding-info">
          <div class="finding-title">${escHtml(v.title)}</div>
          <div class="finding-detail">${escHtml(v.detail)} &nbsp;|&nbsp; ${escHtml(v.cve)}</div>
        </div>
      </div>`).join('');

    // Ports table
    document.getElementById('portsEmpty').style.display = 'none';
    document.getElementById('portsList').innerHTML = `
      <table class="port-table">
        <thead>
          <tr>
            <th>PORT</th><th>PROTO</th><th>STATE</th><th>SERVICE</th><th>VERSION</th>
          </tr>
        </thead>
        <tbody>
          ${PORT_DB.map(p => `
          <tr>
            <td style="color:var(--text)">${p.port}</td>
            <td style="color:var(--muted)">${p.proto}</td>
            <td class="port-${p.state}">${p.state.toUpperCase()}</td>
            <td style="font-family:var(--rfont)">${escHtml(p.service)}</td>
            <td style="color:var(--muted);font-family:var(--rfont)">${escHtml(p.version)}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;

    addLog(`✓ Report generated — ${vulns.length} findings, risk score ${risk}/100`, 'ok');

    document.getElementById('scanBtn').disabled    = false;
    document.getElementById('scanBtn').textContent = '▶ SCAN';
    scanning = false;
  }, 400);
}
