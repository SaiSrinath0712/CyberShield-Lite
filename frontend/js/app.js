// Global chart references to destroy and rebuild cleanly
let distChart = null;
let barChart = null;

document.addEventListener("DOMContentLoaded", () => {
    // Load default dashboard panel
    switchTab("overview");
    setupFormHandlers();
});

// Switch panels in single-page dashboard
function switchTab(tabId) {
    document.querySelectorAll(".sidebar-btn").forEach(btn => {
        btn.classList.remove("active");
    });
    
    // Find matching button
    const btn = Array.from(document.querySelectorAll(".sidebar-btn")).find(b => 
        b.getAttribute("onclick") === `switchTab('${tabId}')`
    );
    if (btn) btn.classList.add("active");

    // Toggles panel visibility
    document.querySelectorAll(".tab-panel").forEach(panel => {
        panel.classList.remove("active");
    });
    document.getElementById(tabId).classList.add("active");

    // Header adjustments
    const pageTitle = document.getElementById("page-title");
    const titleMap = {
        "overview": "Security Command Console",
        "email-scanner": "Email Spam & Phishing Scanner",
        "url-scanner": "Malicious URL Scanner",
        "file-scanner": "Suspicious File Analyzer",
        "ids-scanner": "Intrusion Detection System (IDS)",
        "injection-scanner": "Injection Script Detector",
        "login-scanner": "Login Attack Audit Monitor",
        "history-logs": "Platform Scans History Log"
    };
    pageTitle.textContent = titleMap[tabId] || "CyberShield AI Lite";

    // Refresh specific telemetry data
    if (tabId === "overview") {
        loadDashboardStats();
    } else if (tabId === "history-logs") {
        loadHistoryLogs();
    }
}

// ==========================================
// 1. DASHBOARD TELEMETRY STATS & CHARTS
// ==========================================
async function loadDashboardStats() {
    try {
        const response = await fetch("/dashboard");
        const stats = await response.json();
        
        // Update stats widgets
        document.getElementById("cnt-total-scans").textContent = stats.total_scans;
        document.getElementById("cnt-total-threats").textContent = stats.total_threats;
        document.getElementById("cnt-blocked-urls").textContent = stats.blocked_urls;
        document.getElementById("cnt-network-attacks").textContent = stats.network_attacks;

        // Render Alerts list
        renderRecentAlertsTable(stats.recent_alerts);

        // Compute overall scan categories count (Safe vs Suspicious vs Dangerous)
        // We will sum them up by fetching history logs, or summarize them dynamically.
        // Let's create a beautiful threat distribution pie chart and module-threats comparison bar chart.
        renderCharts(stats.distribution);

    } catch (err) {
        console.error("Failed to load dashboard stats:", err);
    }
}

function renderRecentAlertsTable(alerts) {
    const tbody = document.querySelector("#recent-alerts-table tbody");
    tbody.innerHTML = "";

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No threat alerts logged. Platform is secure.</td></tr>`;
        return;
    }

    alerts.forEach(alert => {
        const tr = document.createElement("tr");
        let badgeClass = "badge-safe";
        if (alert.risk_level.toLowerCase() === "medium") badgeClass = "badge-suspicious";
        if (alert.risk_level.toLowerCase() === "high" || alert.risk_level.toLowerCase() === "critical") badgeClass = "badge-dangerous";

        tr.innerHTML = `
            <td><strong>${alert.threat_type}</strong></td>
            <td><span class="badge ${badgeClass}">${alert.risk_level}</span></td>
            <td style="font-size: 0.8rem; color: var(--text-secondary);">${alert.description}</td>
            <td style="font-family: monospace; font-size: 0.8rem;"><code>${alert.payload_sample}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderCharts(distribution) {
    // 1. Threat Distribution Pie Chart
    const pieCtx = document.getElementById("threatPieChart").getContext("2d");
    if (distChart) distChart.destroy();

    const labels = Object.keys(distribution);
    const values = Object.values(distribution);
    const hasData = values.some(v => v > 0);

    distChart = new Chart(pieCtx, {
        type: "pie",
        data: {
            labels: hasData ? labels : ["No Threats Flagged"],
            datasets: [{
                data: hasData ? values : [1],
                backgroundColor: hasData ? ["#9b51e0", "#ff005b", "#00f2fe", "#ff7b00", "#39ff14", "#82ca9d", "#8884d8"] : ["rgba(255,255,255,0.04)"],
                borderWidth: 1,
                borderColor: "rgba(0,0,0,0.5)"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "bottom", labels: { color: "#9ca3af", font: { size: 10 } } }
            }
        }
    });

    // 2. Bar Chart: Threat volume comparing modules
    const barCtx = document.getElementById("threatBarChart").getContext("2d");
    if (barChart) barChart.destroy();

    barChart = new Chart(barCtx, {
        type: "bar",
        data: {
            labels: labels.map(l => l.split(" ")[0]), // short labels
            datasets: [{
                label: "Threat Count",
                data: values,
                backgroundColor: "rgba(0, 242, 254, 0.4)",
                borderColor: "#00f2fe",
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: "#9ca3af", font: { size: 9 } }, grid: { color: "rgba(255,255,255,0.03)" } },
                y: { ticks: { color: "#9ca3af", stepSize: 1 }, grid: { color: "rgba(255,255,255,0.03)" } }
            }
        }
    });
}


// ==========================================
// 2. SCANNER FORM SUBMISSIONS & TOASTS
// ==========================================
function setupFormHandlers() {
    // EMAIL
    document.getElementById("email-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        toggleScannerLoader("email", true);
        const subject = document.getElementById("email-subject-input").value;
        const body = document.getElementById("email-body-input").value;
        
        try {
            const response = await fetch("/predict/email", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ subject, body })
            });
            const data = await response.json();
            renderScannerResults("email", data.verdict, data.explanation);
        } catch (err) {
            handleScannerError("email", err);
        }
    });

    // URL
    document.getElementById("url-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        toggleScannerLoader("url", true);
        const url = document.getElementById("url-input").value;

        try {
            const response = await fetch("/predict/url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });
            const data = await response.json();
            renderScannerResults("url", data.verdict, data.explanation);
        } catch (err) {
            handleScannerError("url", err);
        }
    });

    // FILE
    document.getElementById("file-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        toggleScannerLoader("file", true);
        const filename = document.getElementById("file-name-input").value;
        const extension = document.getElementById("file-ext-input").value;

        try {
            const response = await fetch("/predict/file", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ filename, extension })
            });
            const data = await response.json();
            renderScannerResults("file", data.verdict, data.explanation);
        } catch (err) {
            handleScannerError("file", err);
        }
    });

    // IDS
    document.getElementById("ids-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        toggleScannerLoader("ids", true);
        
        const payload = {
            duration: parseFloat(document.getElementById("ids-duration").value),
            protocol_type: document.getElementById("ids-protocol").value,
            service: document.getElementById("ids-service").value,
            flag: document.getElementById("ids-flag").value,
            src_bytes: parseInt(document.getElementById("ids-srcbytes").value),
            dst_bytes: parseInt(document.getElementById("ids-dstbytes").value),
            count: parseInt(document.getElementById("ids-count").value),
            serror_rate: parseFloat(document.getElementById("ids-serror").value),
            num_failed_logins: parseInt(document.getElementById("ids-logins").value)
        };

        try {
            const response = await fetch("/predict/intrusion", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            renderScannerResults("ids", data.verdict, data.explanation);
        } catch (err) {
            handleScannerError("ids", err);
        }
    });

    // INJECTIONS (SQLi / XSS)
    document.getElementById("injection-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        toggleScannerLoader("injection", true);
        
        const type = document.getElementById("inj-type").value;
        const payloadVal = document.getElementById("inj-payload-input").value;
        const endpoint = type === "sqli" ? "/predict/sql" : "/predict/xss";
        const bodyKey = type === "sqli" ? "query_text" : "payload_text";

        try {
            const response = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ [bodyKey]: payloadVal })
            });
            const data = await response.json();
            renderScannerResults("injection", data.verdict, data.explanation);
        } catch (err) {
            handleScannerError("injection", err);
        }
    });

    // LOGIN MONITOR
    document.getElementById("login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        toggleScannerLoader("login", true);
        
        const username = document.getElementById("log-user").value;
        const ip_address = document.getElementById("log-ip").value;
        const failed_logins_count = parseInt(document.getElementById("log-count").value);

        try {
            const response = await fetch("/predict/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, ip_address, failed_logins_count })
            });
            const data = await response.json();
            renderScannerResults("login", data.verdict, data.explanation);
        } catch (err) {
            handleScannerError("login", err);
        }
    });
}

function toggleScannerLoader(prefix, isLoading) {
    const placeholder = document.getElementById(`${prefix}-placeholder`);
    const results = document.getElementById(`${prefix}-results`);
    
    if (isLoading) {
        placeholder.style.display = "flex";
        placeholder.innerHTML = `<i class="fa-solid fa-spinner fa-spin fa-2x" style="margin-bottom: 8px; color: var(--neon-cyan);"></i><p>Executing threat scanner logic...</p>`;
        results.style.display = "none";
    } else {
        placeholder.style.display = "none";
    }
}

function renderScannerResults(prefix, verdict, explanation) {
    toggleScannerLoader(prefix, false);
    
    const results = document.getElementById(`${prefix}-results`);
    results.style.display = "block";

    // Verdict Badge mapping
    const badge = document.getElementById(`${prefix}-verdict-badge`);
    badge.textContent = verdict;
    badge.className = `badge badge-${verdict.toLowerCase()}`;

    // Confidence / Risk score indicator
    const bar = document.getElementById(`${prefix}-confidence-bar`);
    const valText = document.getElementById(`${prefix}-confidence-val`);
    const confidence = explanation.confidence || 0;
    
    bar.style.width = `${confidence}%`;
    valText.textContent = `${confidence}% Probability`;
    
    // Set bar color based on verdict
    if (verdict === "Dangerous") bar.style.backgroundColor = "var(--neon-red)";
    else if (verdict === "Suspicious") bar.style.backgroundColor = "var(--neon-orange)";
    else bar.style.backgroundColor = "var(--neon-green)";

    // Set Risk level text
    document.getElementById(`${prefix}-risk-level`).innerHTML = `Severity level: <strong>${explanation.risk_level}</strong>`;

    // Explainable Reasons (XAI features)
    const reasonsUl = document.getElementById(`${prefix}-reasons`);
    reasonsUl.innerHTML = "";
    explanation.reasons.forEach(r => {
        const li = document.createElement("li");
        li.className = `reason-item ${verdict}`;
        li.innerHTML = `<i class="fa-solid fa-circle-info"></i> ${r}`;
        reasonsUl.appendChild(li);
    });

    // Prevention Tips
    const tipsUl = document.getElementById(`${prefix}-tips`);
    tipsUl.innerHTML = "";
    explanation.suggestions.forEach(s => {
        const li = document.createElement("li");
        li.textContent = s;
        tipsUl.appendChild(li);
    });

    // Trigger dynamic notifications toast if suspicious/dangerous
    if (verdict !== "Safe") {
        showToast(
            `Threat Flagged: ${explanation.threat_type}`,
            `Severity Rating: ${explanation.risk_level}`,
            verdict
        );
    }
}

function handleScannerError(prefix, error) {
    const placeholder = document.getElementById(`${prefix}-placeholder`);
    placeholder.style.display = "flex";
    placeholder.innerHTML = `<i class="fa-solid fa-triangle-exclamation fa-2x" style="margin-bottom: 8px; color: var(--neon-red);"></i><p style="color: var(--neon-red);">Scanner timeout or endpoint error.</p>`;
    console.error(error);
}

// Show slide in Toast Notifications
function showToast(title, desc, verdict) {
    const container = document.getElementById("toast-notifications-container");
    const toast = document.createElement("div");
    toast.className = `toast-message ${verdict}`;
    
    toast.innerHTML = `
        <div>
            <div class="toast-title"><i class="fa-solid fa-triangle-exclamation"></i> ${title}</div>
            <div class="toast-desc">${desc}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()"><i class="fa-solid fa-xmark"></i></button>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}


// ==========================================
// 3. AUDIT TRANSACTION HISTORY LOGS
// ==========================================
async function loadHistoryLogs() {
    const queryVal = document.getElementById("history-search-input").value;
    const filterType = document.getElementById("history-filter-module").value;
    const filterVerdict = document.getElementById("history-filter-verdict").value;

    let url = "/history?";
    if (queryVal) url += `query=${encodeURIComponent(queryVal)}&`;
    if (filterType) url += `threat_type=${encodeURIComponent(filterType)}&`;
    if (filterVerdict) url += `verdict=${encodeURIComponent(filterVerdict)}&`;

    try {
        const response = await fetch(url);
        const logs = await response.json();
        
        const tbody = document.querySelector("#history-table tbody");
        tbody.innerHTML = "";

        if (!logs || logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No scan transaction records found matching filters.</td></tr>`;
            return;
        }

        logs.forEach(log => {
            const tr = document.createElement("tr");
            const timeStr = log.created_at.replace("T", " ").split(".")[0];
            
            let labelClass = "badge-safe";
            if (log.prediction_verdict === "Dangerous") labelClass = "badge-dangerous";
            if (log.prediction_verdict === "Suspicious") labelClass = "badge-suspicious";

            const payloadEscaped = log.input_payload.replace(/</g, "&lt;").replace(/>/g, "&gt;").substring(0, 80) + (log.input_payload.length > 80 ? "..." : "");

            tr.innerHTML = `
                <td style="font-family: monospace; font-size: 0.8rem;">${timeStr}</td>
                <td><strong>${log.threat_type}</strong></td>
                <td style="font-family: monospace; font-size: 0.8rem;"><code>${payloadEscaped}</code></td>
                <td><span class="badge ${labelClass}">${log.prediction_verdict}</span></td>
                <td>${log.risk_level}</td>
                <td>${log.confidence_score.toFixed(1)}%</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load history logs database:", err);
    }
}

// Print / PDF view helper
function printReport() {
    window.print();
}

// Redirects for database csv/json downloads
function exportCSV() {
    window.location.href = "/history/export/csv";
}

function exportJSON() {
    window.location.href = "/history/export/json";
}

// Safe Telemetry Refresh Button implementation
async function triggerTelemetryRefresh() {
    const btn = document.querySelector(".page-header button");
    if (btn) {
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Syncing...`;
    }
    
    try {
        await loadDashboardStats();
    } catch (e) {
        console.warn("Failed to load dashboard metrics:", e);
    }
    
    try {
        await loadHistoryLogs();
    } catch (e) {
        console.warn("Failed to load history logs database:", e);
    }
    
    if (btn) {
        btn.innerHTML = `<i class="fa-solid fa-rotate"></i> Refresh Telemetry`;
    }
}

// ==========================================
// 4. IDS SUB-TAB/MODE CONTROLLERS
// ==========================================
function toggleIdsInputMode(mode) {
    // Hide all panels
    document.getElementById("ids-mode-manual").style.display = "none";
    document.getElementById("ids-mode-csv").style.display = "none";
    document.getElementById("ids-mode-sniffer").style.display = "none";
    
    // De-activate all segment buttons
    document.getElementById("btn-ids-manual").style.borderColor = "var(--border-color)";
    document.getElementById("btn-ids-manual").style.color = "var(--text-secondary)";
    document.getElementById("btn-ids-csv").style.borderColor = "var(--border-color)";
    document.getElementById("btn-ids-csv").style.color = "var(--text-secondary)";
    document.getElementById("btn-ids-sniffer").style.borderColor = "var(--border-color)";
    document.getElementById("btn-ids-sniffer").style.color = "var(--text-secondary)";

    // Show active panel & highlight button
    if (mode === "manual") {
        document.getElementById("ids-mode-manual").style.display = "block";
        document.getElementById("btn-ids-manual").style.borderColor = "var(--neon-cyan)";
        document.getElementById("btn-ids-manual").style.color = "white";
    } else if (mode === "csv") {
        document.getElementById("ids-mode-csv").style.display = "block";
        document.getElementById("btn-ids-csv").style.borderColor = "var(--neon-cyan)";
        document.getElementById("btn-ids-csv").style.color = "white";
    } else if (mode === "sniffer") {
        document.getElementById("ids-mode-sniffer").style.display = "block";
        document.getElementById("btn-ids-sniffer").style.borderColor = "var(--neon-cyan)";
        document.getElementById("btn-ids-sniffer").style.color = "white";
    }
}

// ==========================================
// 5. IDS CSV BATCH DRAG & DROP
// ==========================================
function handleIdsCsvDrop(event) {
    event.preventDefault();
    const zone = document.getElementById("ids-drop-zone");
    zone.style.borderColor = "var(--border-color)";
    zone.style.background = "transparent";
    
    const files = event.dataTransfer.files;
    if (files.length > 0 && files[0].name.endsWith(".csv")) {
        processIdsCsvFile(files[0]);
    } else {
        alert("Anomaly Rejected: Please import a valid .csv file.");
    }
}

function handleIdsCsvSelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        processIdsCsvFile(files[0]);
    }
}

function processIdsCsvFile(file) {
    const statusDiv = document.getElementById("ids-csv-status");
    statusDiv.style.display = "block";
    statusDiv.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Reading file: ${file.name}...`;

    const reader = new FileReader();
    reader.onload = async function(e) {
        const text = e.target.result;
        statusDiv.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Ingesting packet flow rows...`;
        await parseAndScanIdsCsv(text);
    };
    reader.readAsText(file);
}

async function parseAndScanIdsCsv(text) {
    const statusDiv = document.getElementById("ids-csv-status");
    const lines = text.split("\n").map(line => line.trim()).filter(line => line.length > 0);
    
    if (lines.length <= 1) {
        statusDiv.innerHTML = `<span style="color: var(--neon-red);"><i class="fa-solid fa-triangle-exclamation"></i> Error: CSV is empty or missing data rows.</span>`;
        return;
    }
    
    // Extract headers: duration, protocol_type, service, flag, src_bytes, dst_bytes, count, serror_rate, num_failed_logins
    const headers = lines[0].toLowerCase().split(",").map(h => h.trim().replace(/^["']|["']$/g, ""));
    
    let parsedCount = 0;
    let threatsCount = 0;
    
    // Batch promises
    const promises = [];
    
    for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].split(",").map(c => c.trim().replace(/^["']|["']$/g, ""));
        if (cols.length < headers.length) continue;
        
        // Build payload mapping column index based on header key names
        const packet = {
            duration: parseFloat(cols[headers.indexOf("duration")] || 0.0),
            protocol_type: cols[headers.indexOf("protocol_type")] || "tcp",
            service: cols[headers.indexOf("service")] || "http",
            flag: cols[headers.indexOf("flag")] || "SF",
            src_bytes: parseInt(cols[headers.indexOf("src_bytes")] || 0),
            dst_bytes: parseInt(cols[headers.indexOf("dst_bytes")] || 0),
            count: parseInt(cols[headers.indexOf("count")] || 1),
            serror_rate: parseFloat(cols[headers.indexOf("serror_rate")] || 0.0),
            num_failed_logins: parseInt(cols[headers.indexOf("num_failed_logins")] || 0)
        };
        
        parsedCount++;
        
        // Create async task
        const task = fetch("/predict/intrusion", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(packet)
        }).then(res => res.json())
          .then(data => {
              if (data.verdict !== "Safe") threatsCount++;
          }).catch(err => console.error("Batch scan row error:", err));
          
        promises.push(task);
        
        // Process in chunks of 10 to avoid backend connection congestion
        if (promises.length >= 10 || i === lines.length - 1) {
            await Promise.all(promises);
            promises.length = 0; // reset chunk
            statusDiv.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanned ${parsedCount} / ${lines.length - 1} records...`;
        }
    }
    
    // Complete
    statusDiv.innerHTML = `
        <span style="color: var(--neon-green); font-weight: 700;"><i class="fa-solid fa-circle-check"></i> Ingestion Scan Complete!</span>
        <div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-secondary);">
            Parsed Rows: ${parsedCount}<br>
            Threats Intercepted: <strong style="color: var(--neon-red);">${threatsCount}</strong>
        </div>
    `;
    
    // Refresh stats
    loadDashboardStats();
}

// ==========================================
// 6. AUTO TRAFFIC SNIFFER CONTROL
// ==========================================
let snifferInterval = null;
let sniffedPackets = [];

function startTrafficSniffer() {
    const startBtn = document.getElementById("btn-sniffer-start");
    const stopBtn = document.getElementById("btn-sniffer-stop");
    const consoleDiv = document.getElementById("sniffer-console");
    
    startBtn.disabled = true;
    stopBtn.disabled = false;
    
    consoleDiv.innerHTML = `<div style="color: var(--neon-cyan);">[SYSTEM] Sniffing raw socket interface interface... [ACTIVE]</div>`;
    
    // Interval loop (every 2.5 seconds)
    snifferInterval = setInterval(async () => {
        const protocols = ["tcp", "udp", "icmp"];
        const services = ["http", "smtp", "ftp", "private", "other"];
        
        // 30% chance of threat injection
        const injectThreat = Math.random() < 0.3;
        let packet = {};
        
        if (injectThreat) {
            if (Math.random() < 0.5) {
                // DoS Anomaly
                packet = {
                    duration: 0.0,
                    protocol_type: "tcp",
                    service: "private",
                    flag: "S0",
                    src_bytes: 0,
                    dst_bytes: 0,
                    count: Math.floor(Math.random() * 200) + 120,
                    serror_rate: 1.0,
                    num_failed_logins: 0
                };
            } else {
                // Brute-force Login Anomaly
                packet = {
                    duration: Math.random() * 12.0,
                    protocol_type: "tcp",
                    service: "http",
                    flag: "SF",
                    src_bytes: Math.floor(Math.random() * 400),
                    dst_bytes: Math.floor(Math.random() * 400),
                    count: 1,
                    serror_rate: 0.0,
                    num_failed_logins: Math.floor(Math.random() * 6) + 4
                };
            }
        } else {
            // Normal flow
            packet = {
                duration: Math.random() * 1.5,
                protocol_type: protocols[Math.floor(Math.random() * 3)],
                service: services[Math.floor(Math.random() * 3)],
                flag: "SF",
                src_bytes: Math.floor(Math.random() * 4000) + 200,
                dst_bytes: Math.floor(Math.random() * 6000) + 200,
                count: Math.floor(Math.random() * 6) + 1,
                serror_rate: 0.0,
                num_failed_logins: 0
            };
        }

        try {
            const response = await fetch("/predict/intrusion", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(packet)
            });
            const data = await response.json();
            
            const timestamp = new Date().toLocaleTimeString();
            const logLine = document.createElement("div");
            
            if (data.verdict === "Dangerous") {
                logLine.style.color = "var(--neon-red)";
                logLine.innerHTML = `[${timestamp}] 🔴 INTRUSION ALERT: ${data.attack_type.toUpperCase()} | Confidence: ${data.explanation.confidence}%`;
            } else if (data.verdict === "Suspicious") {
                logLine.style.color = "var(--neon-orange)";
                logLine.innerHTML = `[${timestamp}] 🟡 WARNING: Anomalous flow | Flag: ${packet.flag}`;
            } else {
                logLine.style.color = "var(--neon-green)";
                logLine.innerHTML = `[${timestamp}] 🟢 PASS: flow capture safe | Service: ${packet.service.toUpperCase()}`;
            }
            
            consoleDiv.appendChild(logLine);
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
            
            // Cache record for CSV download
            sniffedPackets.push({
                time: timestamp,
                protocol_type: packet.protocol_type,
                service: packet.service,
                src_bytes: packet.src_bytes,
                dst_bytes: packet.dst_bytes,
                count: packet.count,
                serror_rate: packet.serror_rate,
                num_failed_logins: packet.num_failed_logins,
                verdict: data.verdict,
                attack_type: data.attack_type || "normal"
            });
            
            // Enable download btn
            document.getElementById("btn-sniffer-download").disabled = false;

        } catch (err) {
            console.error("Traffic capture exception:", err);
        }
    }, 2500);
}

function stopTrafficSniffer() {
    const startBtn = document.getElementById("btn-sniffer-start");
    const stopBtn = document.getElementById("btn-sniffer-stop");
    const consoleDiv = document.getElementById("sniffer-console");
    
    if (snifferInterval) {
        clearInterval(snifferInterval);
        snifferInterval = null;
    }
    
    startBtn.disabled = false;
    stopBtn.disabled = true;
    
    const line = document.createElement("div");
    line.style.color = "var(--text-muted)";
    line.innerHTML = `[SYSTEM] Interface capture paused. Total session packets sniffed: ${sniffedPackets.length}`;
    consoleDiv.appendChild(line);
    consoleDiv.scrollTop = consoleDiv.scrollHeight;
}

function downloadSniffedCsv() {
    if (sniffedPackets.length === 0) return;
    
    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "Timestamp,Protocol,Service,SrcBytes,DstBytes,Count,SerrorRate,FailedLogins,Verdict,AttackType\n";
    
    sniffedPackets.forEach(p => {
        csvContent += `"${p.time}","${p.protocol_type}","${p.service}",${p.src_bytes},${p.dst_bytes},${p.count},${p.serror_rate},${p.num_failed_logins},"${p.verdict}","${p.attack_type}"\n`;
    });
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `sniffer_session_capture_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// ==========================================
// 7. DRAG & DROP FILE INGESTION CONTROLLERS (ALL SCANNERS)
// ==========================================

// 1. Email Scanner
function handleEmailDrop(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processEmailFile(files[0]);
    }
}
function handleEmailSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processEmailFile(files[0]);
    }
}
function processEmailFile(file) {
    const reader = new FileReader();
    reader.onload = function(evt) {
        const text = evt.target.result;
        let subject = file.name.replace(/\.[^/.]+$/, ""); 
        let body = text;
        if (text.startsWith("Subject:")) {
            const lines = text.split("\n");
            subject = lines[0].replace("Subject:", "").trim();
            body = lines.slice(1).join("\n").trim();
        }
        document.getElementById("email-subject-input").value = subject;
        document.getElementById("email-body-input").value = body;
        showLoadedFileInfo("email", file.name);
        document.getElementById("email-form").dispatchEvent(new Event("submit"));
    };
    reader.readAsText(file);
}

// 2. URL Scanner
function handleUrlDrop(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processUrlFile(files[0]);
    }
}
function handleUrlSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processUrlFile(files[0]);
    }
}
function processUrlFile(file) {
    const reader = new FileReader();
    reader.onload = function(evt) {
        const text = evt.target.result.trim();
        document.getElementById("url-input").value = text;
        showLoadedFileInfo("url", file.name);
        document.getElementById("url-form").dispatchEvent(new Event("submit"));
    };
    reader.readAsText(file);
}

// 3. File Extension Scanner
function handleFileDrop(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processFileExt(files[0]);
    }
}
function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processFileExt(files[0]);
    }
}
function processFileExt(file) {
    const filename = file.name;
    const dotIndex = filename.lastIndexOf(".");
    const ext = dotIndex !== -1 ? filename.substring(dotIndex + 1) : "";
    
    document.getElementById("file-name-input").value = filename;
    document.getElementById("file-ext-input").value = ext;
    showLoadedFileInfo("file", file.name);
    document.getElementById("file-form").dispatchEvent(new Event("submit"));
}

// 4. Injection Scanner
function handleInjectionDrop(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processInjectionFile(files[0]);
    }
}
function handleInjectionSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processInjectionFile(files[0]);
    }
}
function processInjectionFile(file) {
    const reader = new FileReader();
    reader.onload = function(evt) {
        const text = evt.target.result.trim();
        document.getElementById("inj-payload-input").value = text;
        
        const ext = file.name.split('.').pop().toLowerCase();
        if (ext === 'sql') {
            document.getElementById("inj-type").value = "sqli";
        } else if (ext === 'js' || ext === 'html') {
            document.getElementById("inj-type").value = "xss";
        }
        showLoadedFileInfo("injection", file.name);
        document.getElementById("injection-form").dispatchEvent(new Event("submit"));
    };
    reader.readAsText(file);
}

// 5. Login Monitor
function handleLoginDrop(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processLoginFile(files[0]);
    }
}
function handleLoginSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processLoginFile(files[0]);
    }
}
function processLoginFile(file) {
    const reader = new FileReader();
    reader.onload = function(evt) {
        const text = evt.target.result.trim();
        let user = "admin";
        let ip = "127.0.0.1";
        let count = 3;
        
        try {
            const data = JSON.parse(text);
            user = data.username || data.user || user;
            ip = data.ip || data.ip_address || ip;
            count = data.count || data.failed_attempts || count;
        } catch (e) {
            const parts = text.split(",");
            if (parts.length >= 1) user = parts[0].trim();
            if (parts.length >= 2) ip = parts[1].trim();
            if (parts.length >= 3) count = parseInt(parts[2].trim()) || count;
        }
        
        document.getElementById("log-user").value = user;
        document.getElementById("log-ip").value = ip;
        document.getElementById("log-count").value = count;
        showLoadedFileInfo("login", file.name);
        document.getElementById("login-form").dispatchEvent(new Event("submit"));
    };
    reader.readAsText(file);
}

// Helper to render file details info tag below dropzone cards
function showLoadedFileInfo(prefix, filename) {
    const el = document.getElementById(`${prefix}-file-info`);
    if (el) {
        el.style.display = "block";
        el.querySelector(".filename-span").textContent = filename;
    }
}

