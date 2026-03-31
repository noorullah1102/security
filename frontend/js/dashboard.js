/**
 * PhishRadar Dashboard JavaScript
 * Handles API calls, Chart.js integration, and real-time updates
 */

// Configuration
const API_BASE = '/api/v1';
const API_KEY = localStorage.getItem('api_key') || 'dev-api-key';
const REFRESH_INTERVAL = 30000; // 30 seconds

// Chart instances
let verdictChart = null;
let trendsChart = null;
let refreshTimer = null;

// API Helper
async function apiFetch(endpoint, options = {}) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
            'X-API-Key': API_KEY,
            'Content-Type': 'application/json',
            ...options.headers,
        },
    });

    if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
    }

    return response.json();
}

// Update Stats Cards
function updateStats(summary) {
    document.getElementById('stat-total').textContent = summary.total_scans || 0;
    document.getElementById('stat-phishing').textContent = summary.phishing_detected || 0;
    document.getElementById('stat-safe').textContent = summary.safe_urls || 0;
    document.getElementById('stat-suspicious').textContent = summary.suspicious_urls || 0;

    const total = summary.total_scans || 1;
    document.getElementById('stat-phishing-pct').textContent =
        `${Math.round((summary.phishing_detected || 0) / total * 100)}% of total`;
    document.getElementById('stat-safe-pct').textContent =
        `${Math.round((summary.safe_urls || 0) / total * 100)}% of total`;
    document.getElementById('stat-suspicious-pct').textContent =
        `${Math.round((summary.suspicious_urls || 0) / total * 100)}% of total`;
}

// Update Verdict Chart
function updateVerdictChart(distribution) {
    const ctx = document.getElementById('verdict-chart').getContext('2d');

    if (verdictChart) {
        verdictChart.destroy();
    }

    const data = {
        labels: distribution.map(d => d.verdict.charAt(0).toUpperCase() + d.verdict.slice(1)),
        datasets: [{
            data: distribution.map(d => d.count),
            backgroundColor: [
                '#EF4444', // Red for phishing
                '#10B981', // Green for safe
                '#F59E0B', // Yellow for suspicious
            ],
            borderWidth: 0,
        }]
    };

    verdictChart = new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                }
            }
        }
    });
}

// Update Trends Chart
function updateTrendsChart(trendsData) {
    const ctx = document.getElementById('trends-chart').getContext('2d');

    if (trendsChart) {
        trendsChart.destroy();
    }

    // Group by date
    const dateGroups = {};
    trendsData.data.forEach(point => {
        if (!dateGroups[point.date]) {
            dateGroups[point.date] = { phishing: 0, safe: 0, suspicious: 0 };
        }
        dateGroups[point.date][point.verdict] = point.count;
    });

    const labels = Object.keys(dateGroups).sort();

    trendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels.map(d => {
                const date = new Date(d);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            }),
            datasets: [
                {
                    label: 'Phishing',
                    data: labels.map(d => dateGroups[d].phishing),
                    borderColor: '#EF4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                },
                {
                    label: 'Safe',
                    data: labels.map(d => dateGroups[d].safe),
                    borderColor: '#10B981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                },
                {
                    label: 'Suspicious',
                    data: labels.map(d => dateGroups[d].suspicious),
                    borderColor: '#F59E0B',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                },
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                }
            }
        }
    });
}

// Update Feed Status
function updateFeedStatus(feeds) {
    const container = document.getElementById('feed-status');

    if (!feeds || feeds.length === 0) {
        container.innerHTML = '<div class="text-gray-400 text-sm">No feed data available</div>';
        return;
    }

    container.innerHTML = feeds.map(feed => {
        const statusColor = {
            healthy: 'bg-green-500',
            degraded: 'bg-yellow-500',
            error: 'bg-red-500',
        }[feed.status] || 'bg-gray-500';

        const statusText = feed.status.charAt(0).toUpperCase() + feed.status.slice(1);
        const lastUpdate = feed.last_update
            ? new Date(feed.last_update).toLocaleTimeString()
            : 'Never';

        return `
            <div class="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
                <div class="flex items-center space-x-3">
                    <div class="w-2 h-2 rounded-full ${statusColor}"></div>
                    <span class="font-medium text-gray-700">${feed.source}</span>
                </div>
                <div class="text-right">
                    <div class="text-xs text-gray-500">${statusText}</div>
                    <div class="text-xs text-gray-400">${feed.indicator_count} indicators</div>
                </div>
            </div>
        `;
    }).join('');
}

// Update Recent Scans Table
function updateRecentScans(scans) {
    const tbody = document.getElementById('scans-table');

    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-gray-400 py-4">No recent scans</td></tr>';
        return;
    }

    tbody.innerHTML = scans.map(scan => {
        const verdictClass = `verdict-${scan.verdict}`;
        const url = scan.url.length > 40
            ? scan.url.substring(0, 40) + '...'
            : scan.url;

        const timeAgo = getTimeAgo(new Date(scan.created_at));

        return `
            <tr class="border-b border-gray-50 hover:bg-gray-50">
                <td class="py-3">
                    <div class="font-medium text-gray-800" title="${scan.url}">${url}</div>
                    ${scan.target_brand ? `<div class="text-xs text-gray-400">Target: ${scan.target_brand}</div>` : ''}
                </td>
                <td class="py-3">
                    <span class="verdict-badge ${verdictClass}">${scan.verdict}</span>
                </td>
                <td class="py-3 text-gray-600">${Math.round(scan.confidence * 100)}%</td>
                <td class="py-3 text-gray-400 text-xs">${timeAgo}</td>
            </tr>
        `;
    }).join('');
}

// Helper: Time ago
function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);

    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

// Fetch all dashboard data
async function fetchDashboardData() {
    try {
        // Fetch combined dashboard stats
        const dashboardData = await apiFetch('/stats/dashboard?days=7');

        updateStats(dashboardData.summary);
        updateVerdictChart(dashboardData.verdict_distribution);
        updateFeedStatus(dashboardData.feed_status);

        // Fetch recent scans
        const scansData = await apiFetch('/scans/recent?limit=10');
        updateRecentScans(scansData.scans);

        // Fetch trends (separate endpoint)
        try {
            const trendsData = await apiFetch('/stats/trends?days=7');
            updateTrendsChart(trendsData);
        } catch (e) {
            console.log('Trends data not available');
        }

    } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
        showError('Failed to load dashboard data. Check API connection.');
    }
}

// Show error message
function showError(message) {
    // Could implement a toast notification here
    console.error(message);
}

// Start auto-refresh
function startAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }
    refreshTimer = setInterval(fetchDashboardData, REFRESH_INTERVAL);
}

// Refresh button handler
document.getElementById('refresh-btn').addEventListener('click', async () => {
    const refreshText = document.getElementById('refresh-text');
    const refreshLoading = document.getElementById('refresh-loading');

    refreshText.classList.add('hidden');
    refreshLoading.classList.remove('hidden');

    await fetchDashboardData();

    refreshText.classList.remove('hidden');
    refreshLoading.classList.add('hidden');
});

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    fetchDashboardData();
    startAutoRefresh();
});
