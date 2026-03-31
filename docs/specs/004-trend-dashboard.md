# SPEC-004: Trend Dashboard

## Metadata
| Field | Value |
|-------|-------|
| Module | Trend Dashboard |
| Version | 1.0.0 |
| Status | Draft |
| Priority | P2 (Enhancement) |

## Overview
A web-based dashboard that visualizes trending phishing threats, recent scans, and aggregate statistics from the PhishRadar system.

## Functional Requirements

### FR-001: Recent Scans Display
- Show list of most recent URL scans
- Display: URL, verdict, severity, timestamp
- Support pagination (20 per page)
- Click to view full analysis details

### FR-002: Statistics Overview
Display key metrics:
- Total scans (today/week/month)
- Phishing detected count
- Safe URLs count
- Average confidence score
- Top targeted brands

### FR-003: Trend Visualization
- Line chart: Scans over time (hourly/daily)
- Pie chart: Verdict distribution
- Bar chart: Top targeted brands
- Trending threat keywords from Reddit

### FR-004: Threat Feed Status
- Show status of each feed source
- Last successful update time
- Number of indicators per source
- Error indicators if feed is failing

### FR-005: Search and Filter
- Search scans by URL substring
- Filter by verdict (phishing/safe/suspicious)
- Filter by date range
- Filter by severity level

### FR-006: Real-time Updates
- Poll for new scans every 30 seconds
- Update statistics without full page reload
- Show notification for new critical threats

## Non-Functional Requirements

### NFR-001: Performance
- Initial page load < 2 seconds
- Dashboard updates < 500ms
- Support 10+ concurrent users

### NFR-002: Browser Support
- Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- Mobile responsive design

### NFR-003: Accessibility
- WCAG 2.1 AA compliance
- Keyboard navigation support
- Screen reader compatible

## UI Components

### Page Layout
```
+------------------------------------------+
|  PhishRadar Dashboard                    |
+------------------------------------------+
| Stats Cards (4 cards in row)             |
+------------------------------------------+
| Recent Scans      |    Trends Chart      |
| (table)           |    (line chart)      |
+------------------------------------------+
| Feed Status       |    Top Brands        |
| (status list)     |    (bar chart)       |
+------------------------------------------+
```

### Component: Stats Card
```html
<div class="stat-card">
  <span class="stat-icon">🔍</span>
  <div class="stat-content">
    <span class="stat-value">1,234</span>
    <span class="stat-label">Total Scans</span>
  </div>
</div>
```

### Component: Scan Table
```html
<table class="scan-table">
  <thead>
    <tr>
      <th>URL</th>
      <th>Verdict</th>
      <th>Severity</th>
      <th>Confidence</th>
      <th>Time</th>
    </tr>
  </thead>
  <tbody>
    <!-- Populated via JavaScript -->
  </tbody>
</table>
```

## API Endpoints Required

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/scans/recent` | GET | Get recent scans |
| `/api/v1/stats/summary` | GET | Get aggregate statistics |
| `/api/v1/stats/trends` | GET | Get time-series data |
| `/api/v1/stats/brands` | GET | Get top targeted brands |
| `/api/v1/feeds/status` | GET | Get feed source status |

## Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| HTML | HTML5 + Tailwind CSS | Rapid styling, no build step |
| JavaScript | Vanilla ES6+ | No framework overhead |
| Charts | Chart.js | Lightweight, well-documented |
| Icons | Heroicons | SVG icons, Tailwind-compatible |

## File Structure

```
frontend/
├── index.html          # Main dashboard page
├── css/
│   └── dashboard.css   # Custom styles (Tailwind CDN for base)
├── js/
│   ├── app.js          # Main application logic
│   ├── api.js          # API client
│   ├── charts.js       # Chart.js configurations
│   └── utils.js        # Utility functions
└── assets/
    └── favicon.ico     # Dashboard icon
```

## Acceptance Criteria

| ID | Criteria |
|----|----------|
| AC-001 | Dashboard loads and displays recent scans |
| AC-002 | Statistics cards show correct counts |
| AC-003 | Line chart displays scan trends |
| AC-004 | Pie chart shows verdict distribution |
| AC-005 | Bar chart shows top targeted brands |
| AC-006 | Feed status shows source health |
| AC-007 | Search filters scans by URL |
| AC-008 | Date range filter works |
| AC-009 | Page updates every 30 seconds |
| AC-010 | Mobile layout is responsive |

## Test Cases

1. **UI Tests**
   - Dashboard renders without errors
   - All components display correctly
   - Responsive layout works on mobile

2. **Integration Tests**
   - API endpoints return expected data
   - Charts render with mock data
   - Search/filter functionality works

3. **Performance Tests**
   - Page load time under 2 seconds
   - No memory leaks on long sessions
