
## Design system

### Color palette

| Purpose | Color | Hex |
|---|---|---|
| Primary accent / logo | Red | `#E24B4A` |
| Phishing / danger | Red bg | `#FCEBEB` / text `#A32D2D` |
| Suspicious / warning | Amber bg | `#FAEEDA` / text `#854F0B` |
| Safe / success | Green bg | `#EAF3DE` / text `#3B6D11` |
| Info / neutral | Blue bg | `#E6F1FB` / text `#185FA5` |
| Borders | Subtle | `rgba(0,0,0,0.1)` or `#E5E5E5` |
| Surface | White | `#FFFFFF` |
| Page background | Off-white | `#F7F7F5` |

### Typography
- Font: System sans-serif stack (Inter or system-ui)
- Body: 14px / line-height 1.6
- Labels: 12px, muted color
- Stats: 22–24px, weight 500
- Headings: weight 500 only (never 700/bold)

### Component rules
- Card border-radius: 10–12px
- All borders: `0.5px solid` (thin, subtle)
- No box shadows, no gradients
- Verdict pills: small, rounded, colored bg + matching dark text
- Monospace font for URLs everywhere
- Status dots: 6px filled circles for live indicators

### Navigation
- Top navbar, horizontal
- Logo: red 28×28px square icon (shield shape) + app name "PhishGuard"
- Nav links: text buttons, active state = light gray bg
- "Live" badge on Threat Feed link: small red pill

---

## Pages to build

### 1. Dashboard (refine existing)

Keep all existing data. Improve layout to match this structure:

**Top row — 4 stat cards in a grid:**
- Total Scans (blue dot)
- Phishing Detected (red dot) — show detection rate % as subtitle
- Safe URLs (green dot) — show % of total as subtitle
- Suspicious (amber dot) — "needs review" subtitle

**Middle row — 3 cards side by side:**

1. **Verdict Distribution** — horizontal bar chart (CSS bars, no library needed)
   - Three bars: Safe (green), Phishing (red), Suspicious (amber)
   - Show count on the right of each bar

2. **Scan Trend** — last 7 days bar chart
   - Simple vertical bars with day labels (Mon–Sun)
   - Today's bar slightly more saturated/darker blue to highlight it
   - No chart library needed, just CSS flexbox bars

3. **Feed Status** — list of API sources with online/offline pill
   - PhishTank, URLhaus, Reddit, WHOIS
   - Show "X min ago" for last successful ping
   - Green pill = online, red pill = offline, amber = degraded

**Bottom — Recent Scans table:**
- Columns: URL (monospace, truncated), Verdict pill, Time ago
- Show last 10 scans
- Clicking a row navigates to URL Checker with that URL pre-filled

---

### 2. URL Checker (improve existing)

**Input section:**
- Full-width monospace text input for the URL
- "Scan URL" primary button (red background, white text)
- Below input: small text "Supports http/https URLs — results pulled from live threat feeds"

**Results section (shown after scan):**

*If phishing/suspicious:*
- Result block with colored border matching verdict (red or amber bg)
- Header: verdict icon + "Phishing detected" or "Suspicious" label + Risk Score badge (e.g. "94/100")

*Signal grid — 2×3 or 3×2 grid of small cards, one per data source:*

| Signal | Source |
|---|---|
| PhishTank | Confirmed phish / Not listed |
| URLhaus | Malware host / Clean |
| Reddit | N reports found / No reports |
| Domain age | X days old |
| WHOIS country | Country code + mismatch warning if relevant |
| SSL certificate | Valid / Invalid / Missing |

Each signal card: source name (small muted label) + verdict value (colored text, green/amber/red).

*AI explanation block:*
- Small purple/indigo 12px square icon labeled "AI explanation"
- Paragraph of natural language explaining WHY this URL is flagged
- White card, subtle border
- Use existing AI explanation API call — just restyle the output container

*If safe:*
- Green result block
- Same signal grid but all green
- Shorter AI explanation confirming it's clean

---

### 3. Threat Feed (NEW PAGE)

**Purpose:** Show a live scrolling list of threats coming in from the connected APIs. Makes the live integrations visible.

**Nav label:** "Threat Feed" with a small red "live" badge

**Filter tabs:** All threats | PhishTank | URLhaus | Reddit
- Tab click filters the list to that source only

**Feed list:**
- Each row: URL (monospace, flex 1, truncated) + Source pill (colored by source) + Time ago
- Source pill colors: PhishTank = red, URLhaus = red, Reddit = amber
- Rows separated by thin border
- List auto-refreshes every 5 minutes (or on manual "Refresh" button click)
- Show a "Last updated X seconds ago" timestamp above the list

**How to populate:**
- Pull from existing URLhaus and PhishTank feed data that the backend already fetches
- Reddit: show URLs that were flagged in Reddit scan results
- Cache results, refresh on interval
- If no live feed data is available yet, show the most recent scan results grouped by source as a fallback

---

### 4. Bulk Scan (NEW PAGE)

**Purpose:** Let users scan multiple URLs at once. Shows production-grade thinking.

**Input section:**
- Large textarea (monospace font, ~8 rows)
- Placeholder: "Paste one URL per line..."
- Helper text: "Up to 50 URLs per batch"
- "Scan All" primary button

**Results section (shown after scan):**
- Summary bar: X Phishing | X Suspicious | X Safe — with colored counts
- Results table:
  - Columns: # | URL | Verdict pill | Risk Score | Time
  - Sortable by verdict (phishing first by default)
  - Each row clickable → opens that URL in URL Checker page

**Export buttons (shown after scan):**
- "Export JSON" — downloads results as `.json`
- "Export CSV" — downloads results as `.csv`
- Both buttons: secondary style (light bg, dark text, thin border)

**Rate limiting:**
- Process URLs sequentially or in small batches (3 at a time) to avoid hammering APIs
- Show a progress bar or "Scanning X of Y..." counter while processing

---

## What NOT to build

- **No user accounts or auth** — this is a public portfolio demo, login adds friction with no benefit
- **No historical analytics beyond 7 days** — data won't be rich enough to look impressive
- **No browser extension** — separate project scope
- **No dark mode toggle** — ship a clean light theme only, don't split effort
- **No paid API tier features** — stay within free tier limits of all connected APIs
- **No database** — use in-memory or simple JSON file storage for scan history; persistence isn't needed for a portfolio demo

---

## UX details to get right

1. **URLs must always be monospace** (`font-family: monospace`) everywhere — in inputs, tables, results, feed rows
2. **Truncate long URLs** with `text-overflow: ellipsis` — never let them break layout
3. **Verdict pills** must be small (11–12px), with matching background + dark text of same color family. Never black text on colored pill.
4. **Loading state** on URL Checker: show a spinner or animated "Scanning..." state while the API calls are in flight. Don't leave the button inactive with no feedback.
5. **Empty states**: if no scan history yet, show a centered message like "No scans yet — try the URL Checker" with a link
6. **Error handling**: if an API is down, show that signal card in amber/muted state with "Unavailable" rather than crashing the whole result
7. **Recent scans on Dashboard** should be clickable rows that navigate to URL Checker with the URL pre-filled


