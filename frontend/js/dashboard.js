/**
 * PhishRadar Dashboard — CSS-only charts, no Chart.js
 */

const API_BASE = '/api/v1';
const API_KEY = localStorage.getItem('api_key') || 'dev-api-key';
const REFRESH_INTERVAL = 30000;

let refreshTimer = null;

async function apiFetch(endpoint, options = {}) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
            'X-API-Key': API_KEY,
            'Content-Type': 'application/json',
            ...options.headers,
        },
    });
    if (!response.ok) throw new Error(`API Error: ${response.status}`);
    return response.json();
}

function getTimeAgo(date) {
    // Normalize: strip microseconds, force UTC
    let d = typeof date === 'string' ? date.replace(/\.\d+/, '') : date;
    if (!d.endsWith('Z') && !d.includes('+')) d = d + 'Z';
    const seconds = Math.floor((new Date() - new Date(d)) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

// Update stat cards
function updateStats(summary) {
    const total = summary.total_scans || 0;
    const phishing = summary.phishing_detected || 0;
    const safe = summary.safe_urls || 0;
    const suspicious = summary.suspicious_urls || 0;

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-phishing').textContent = phishing;
    document.getElementById('stat-safe').textContent = safe;
    document.getElementById('stat-suspicious').textContent = suspicious;

    const t = total || 1;
    document.getElementById('stat-phishing-pct').textContent = `${Math.round(phishing / t * 100)}%`;
    document.getElementById('stat-safe-pct').textContent = `${Math.round(safe / t * 100)}%`;
    document.getElementById('stat-suspicious-pct').textContent = `${Math.round(suspicious / t * 100)}%`;
}

// CSS horizontal bars for verdict distribution
function updateVerdictBars(distribution) {
    if (!distribution || distribution.length === 0) return;

    const counts = { safe: 0, phishing: 0, suspicious: 0 };
    distribution.forEach(d => { counts[d.verdict] = d.count; });

    const max = Math.max(counts.safe, counts.phishing, counts.suspicious, 1);

    document.getElementById('bar-safe').style.width = `${(counts.safe / max) * 100}%`;
    document.getElementById('bar-phishing').style.width = `${(counts.phishing / max) * 100}%`;
    document.getElementById('bar-suspicious').style.width = `${(counts.suspicious / max) * 100}%`;

    document.getElementById('count-safe').textContent = counts.safe;
    document.getElementById('count-phishing').textContent = counts.phishing;
    document.getElementById('count-suspicious').textContent = counts.suspicious;
}

// CSS vertical bars for scan trend (last 7 days)
function updateTrendBars(trendsData) {
    const container = document.getElementById('trend-bars');
    if (!trendsData || !trendsData.data || trendsData.data.length === 0) {
        container.innerHTML = '<div style="font-size:12px;color:#888;width:100%;text-align:center;">No trend data</div>';
        return;
    }

    // Group by date
    const dateGroups = {};
    trendsData.data.forEach(point => {
        if (!dateGroups[point.date]) dateGroups[point.date] = 0;
        dateGroups[point.date] += point.count;
    });

    const dates = Object.keys(dateGroups).sort().slice(-7);
    if (dates.length === 0) return;

    const maxCount = Math.max(...dates.map(d => dateGroups[d]), 1);
    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const today = new Date().toISOString().slice(0, 10);

    container.innerHTML = dates.map(date => {
        const count = dateGroups[date];
        const heightPx = Math.max(Math.round((count / maxCount) * 110), 6); // use 110px max (container is 120px)
        const isToday = date === today;
        const dayLabel = dayNames[new Date(date + 'T12:00:00').getDay()];

        return `
            <div class="bar-v-wrap" style="flex:1;">
                <div style="font-size:10px;color:#888;margin-bottom:4px;">${count}</div>
                <div class="bar-v ${isToday ? 'today' : ''}" style="height:${heightPx}px;"></div>
                <div style="font-size:11px;color:${isToday ? '#185FA5' : '#888'};margin-top:6px;">${dayLabel}</div>
            </div>
        `;
    }).join('');
}

// Feed status list
function updateFeedStatus(feeds) {
    const container = document.getElementById('feed-status');

    if (!feeds || feeds.length === 0) {
        container.innerHTML = '<div style="font-size:13px;color:#888;">No feed data available</div>';
        return;
    }

    container.innerHTML = feeds.map(feed => {
        let pillClass = 'pill-blue';
        let statusText = 'Unknown';
        if (feed.status === 'live') { pillClass = 'pill-green'; statusText = 'Live'; }
        else if (feed.status === 'not_configured') { pillClass = 'pill-blue'; statusText = 'Not configured'; }
        else if (feed.status === 'healthy') { pillClass = 'pill-green'; statusText = 'Online'; }
        else if (feed.status === 'degraded') { pillClass = 'pill-amber'; statusText = 'Degraded'; }
        else if (feed.status === 'error') { pillClass = 'pill-red'; statusText = 'Offline'; }

        const lastUpdate = feed.last_update ? getTimeAgo(feed.last_update) : '—';

        return `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:0.5px solid rgba(0,0,0,0.06);">
                <span style="font-size:13px;">${feed.source}</span>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="font-size:11px;color:#888;">${lastUpdate}</span>
                    <span class="pill ${pillClass}">${statusText}</span>
                </div>
            </div>
        `;
    }).join('');
}

// Recent scans table
function updateRecentScans(scans) {
    const container = document.getElementById('scans-table');
    const emptyState = document.getElementById('empty-state');

    if (!scans || scans.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }

    emptyState.style.display = 'none';

    const verdictPill = (v) => {
        const cls = { safe: 'pill-green', phishing: 'pill-red', suspicious: 'pill-amber' }[v] || 'pill-blue';
        return `<span class="pill ${cls}">${v}</span>`;
    };

    container.innerHTML = scans.map(scan => {
        const url = scan.url.length > 50 ? scan.url.substring(0, 50) + '...' : scan.url;
        const timeAgo = getTimeAgo(scan.created_at);

        return `
            <div class="scan-row" onclick="window.location.href='/analyze?url=${encodeURIComponent(scan.url)}'"
                 style="display:grid; grid-template-columns:1fr 100px 80px; padding:10px 12px; border-bottom:0.5px solid rgba(0,0,0,0.06); font-size:13px; align-items:center;">
                <span class="url-text" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${scan.url}">${url}</span>
                <span>${verdictPill(scan.verdict)}</span>
                <span style="text-align:right;color:#888;font-size:12px;">${timeAgo}</span>
            </div>
        `;
    }).join('');
}

// Fetch all dashboard data
async function fetchDashboardData() {
    try {
        const dashboardData = await apiFetch('/stats/dashboard?days=7');
        updateStats(dashboardData.summary);
        updateVerdictBars(dashboardData.verdict_distribution);
        updateFeedStatus(dashboardData.feed_status);

        const scansData = await apiFetch('/scans/recent?limit=10');
        updateRecentScans(scansData.scans);

        try {
            const trendsData = await apiFetch('/stats/trends?days=7');
            updateTrendBars(trendsData);
        } catch (e) {
            console.log('Trends data not available');
        }
    } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
    }
}

// Auto-refresh
function startAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(fetchDashboardData, REFRESH_INTERVAL);
}

document.addEventListener('DOMContentLoaded', () => {
    fetchDashboardData();
    startAutoRefresh();
});
