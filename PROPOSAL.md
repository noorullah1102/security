# PhishRadar — AI-Powered Phishing Threat Monitor

> "91% of breaches still start with phishing. AI is making it worse. This tool fights AI with AI."

## Background

In early 2026, Reddit's cybersecurity communities (r/cybersecurity, r/netsec, r/blueteam) are dominated by a recurring theme: **AI-generated phishing is bypassing traditional filters at an alarming rate.**

### The Conversations Happening Right Now

#### 1. AI-Powered Phishing Has Exploded

An [analysis of all r/cybersecurity discussions in January 2026](https://elnion.com/2026/01/27/from-phishing-to-ai-chaos-what-my-analysis-of-all-reddit-cybersecurity-discussions-so-far-in-2026-revealed/) found AI-generated phishing as the dominant theme. Reddit users are reporting:

- LLMs crafting emails tailored to a target's LinkedIn history and leaked data
- Deepfake audio clones tricking helpdesks into resetting passwords
- Finance teams wiring funds after a "CEO" video call using synthetic voice
- QR codes on fake parking fines leading to malware

The numbers back it up:
- Malware-carrying phishing campaigns rose **204%**, with a malicious email stopped every 19 seconds ([Cofense](https://www.strongestlayer.com/blog/ai-generated-phishing-enterprise-threat))
- Voice phishing attacks increased **442%** year-over-year
- IBM found AI needed only **5 prompts and 5 minutes** to build a phishing attack as effective as one that took human experts 16 hours
- Spammers save **95% on campaign costs** using LLMs

#### 2. CISA Chief Uploaded Classified Docs to ChatGPT

In January 2026, [it was revealed](https://techcrunch.com/2026/01/28/trumps-acting-cybersecurity-chief-uploaded-sensitive-government-docs-to-chatgpt/) that CISA Acting Director Madhu Gottumukkala uploaded at least four "For Official Use Only" documents to public ChatGPT. He had personally requested special access when other DHS employees were blocked. One official stated: *"He forced CISA's hand into making them give him ChatGPT, and then he abused it."*

This became the poster child for **"shadow AI"** — r/cybersecurity threads were [marinated in frustration](https://elnion.com/2026/01/27/from-phishing-to-ai-chaos-what-my-analysis-of-all-reddit-cybersecurity-discussions-so-far-in-2026-revealed/) over tools adopted bottom-up, evading oversight until data leaks surface in logs.

- 65% of employees use AI tools; **43% share sensitive info with AI** without employer knowledge ([CybSafe](https://www.informationweek.com/machine-learning-ai/shadow-ai-when-everyone-becomes-a-data-leak-waiting-to-happen))
- Shadow AI breaches cost **$670,000 more** than traditional incidents on average
- 88% of organizations cannot distinguish personal AI accounts from corporate ones ([Netskope](https://www.infosecurity-magazine.com/news/personal-llm-accounts-drive-shadow/))

#### 3. SOC Analysts Are Drowning

An L1 SOC analyst at an MSSP [posted to r/cybersecurity](https://www.cmdzero.io/blog-posts/the-l1-soc-analyst-crisis-reddit-thread-reveals-whats-really-breaking-security-operations): *"L1 SOC analyst here — drowning in false positives."* The thread described thousands of alerts per day, 90%+ false positives, and no structured tuning. Another commenter wrote: *"I dread opening my SIEM. It's like trying to drink from a firehose while everyone blames you for getting wet."*

- **71% of SOC analysts** report burnout (SANS Institute)
- 70% of analysts with 5 years or less experience **leave within 3 years**
- Average SOC handles **11,000 alerts daily**, only 19% worth investigating
- Investigating one day's alerts fully would take **61 days** ([CyberDefenders](https://cyberdefenders.org/blog/soc-alert-fatigue/))

#### 4. ShinyHunters Went on a Rampage

[ShinyHunters launched a massive Okta SSO vishing campaign](https://www.securityweek.com/over-100-organizations-targeted-in-shinyhunters-phishing-campaign/) in early 2026, voice-phishing employees at 300-400 companies. Confirmed breaches include:

| Victim | Records Exposed | Date |
|--------|----------------|------|
| SoundCloud | 29.8M accounts | Jan 2026 |
| Panera Bread | 5.1M accounts | Jan 2026 |
| Match Group (Tinder/Hinge) | Undisclosed | Jan 2026 |
| Betterment | 1.4M accounts | Jan 2026 |
| Harvard University | 115K records | Feb 2026 |
| Figure Technology | 1M records | Feb 2026 |
| Aura | 900K records | Mar 2026 |

They [weaponized a Mandiant security audit tool](https://stateofsurveillance.org/news/shinyhunters-salesforce-aura-400-companies-security-tool-weaponized-2026/) to exploit Salesforce Experience Cloud — a security tool turned into an attack vector.

#### 5. AI Skills Are Now Required, Not Optional

- **67% of cybersecurity roles** now require AI tool proficiency
- AI-experienced positions command salaries **up to 15% higher**
- Gartner predicts by 2028, GenAI will remove specialized education requirements from **50% of entry-level cybersecurity positions**
- A viral Reddit post described an [80-person cybersecurity team being replaced by AI](https://purplesec.us/learn/ai-replacing-cybersecurity-jobs/) after two years of training the system
- 4.8 million unfilled cybersecurity positions globally — but the skills expected are shifting fast

**The gap:** Plenty of tools detect phishing. Very few explain *why* something is dangerous in plain English — which is what non-technical teams and junior analysts actually need.

## What PhishRadar Does

### Core Modules

| # | Module | Description | Key Tech |
|---|--------|-------------|----------|
| 1 | **Threat Feed Aggregator** | Pulls live phishing data from PhishTank, URLhaus, abuse.ch + Reddit r/cybersecurity chatter | Python, PRAW (Reddit API), scheduled jobs |
| 2 | **URL Analyzer** | Extracts features (domain age, SSL info, redirect chains, typosquatting detection), classifies as safe/phishing | scikit-learn, whois, requests |
| 3 | **AI Threat Explainer** | Sends findings to Claude API, generates plain-English threat reports — *why* it's dangerous, severity rating, recommended action | Claude API (Anthropic SDK) |
| 4 | **Trend Dashboard** | Shows what types of phishing are trending this week based on aggregated feed data | FastAPI + simple HTML/JS frontend |
| 5 | **REST API** | Full API with Swagger docs — other tools/teams can plug into PhishRadar | FastAPI |

### Example Flow

```
User submits URL: https://app1e-id-verify.sketchy-domain.com/login

PhishRadar responds:
{
  "verdict": "phishing",
  "confidence": 0.94,
  "features": {
    "typosquat_target": "apple.com",
    "domain_age_days": 3,
    "ssl_valid": false,
    "redirect_chain": 2,
    "suspicious_path": true
  },
  "ai_explanation": "This URL impersonates Apple's login page using a
    typosquatted domain (app1e vs apple). The domain was registered 3
    days ago, has no valid SSL certificate, and redirects through 2
    intermediate servers — a classic credential harvesting pattern.
    Do not enter any credentials.",
  "severity": "high",
  "action": "Block and report to IT security team"
}
```

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Python 3.11+ | Industry standard for security tooling |
| API Framework | FastAPI | Auto-generated Swagger docs, async support, great for portfolio |
| ML Model | scikit-learn | Lightweight phishing URL classifier, easy to train and explain |
| AI | Claude API (Anthropic SDK) | Threat explanation, report generation |
| Database | SQLite (MVP) → PostgreSQL (later) | Scan history, trend tracking |
| Threat Feeds | PhishTank, URLhaus, abuse.ch | Real-world phishing data |
| Reddit Integration | PRAW | Monitor r/cybersecurity for trending threats |
| Frontend | HTML + Tailwind + vanilla JS | Simple dashboard, no framework overhead |

## Build Plan

### Phase 1 — Foundation
- [ ] Project structure, virtual environment, dependencies
- [ ] FastAPI skeleton with health check endpoint
- [ ] URL feature extraction module (domain age, SSL, redirects, typosquatting)
- [ ] Basic rule-based phishing detection

### Phase 2 — ML Classifier
- [ ] Download and prepare phishing URL dataset (PhishTank + legitimate URLs)
- [ ] Feature engineering pipeline
- [ ] Train scikit-learn classifier (Random Forest or Gradient Boosting)
- [ ] Evaluation metrics (precision, recall, F1)
- [ ] Integrate model into FastAPI endpoint

### Phase 3 — AI Threat Explainer
- [ ] Claude API integration via Anthropic SDK
- [ ] Prompt engineering for threat explanation (structured output)
- [ ] Severity rating and recommended action generation
- [ ] Scan history storage (SQLite)

### Phase 4 — Threat Feeds & Reddit
- [ ] PhishTank API integration
- [ ] URLhaus / abuse.ch feed parser
- [ ] Reddit r/cybersecurity monitor (PRAW) — extract trending threat keywords
- [ ] Trend aggregation and scoring

### Phase 5 — Dashboard & Polish
- [ ] Simple HTML dashboard (recent scans, trends, stats)
- [ ] API documentation and examples
- [ ] README with architecture diagram, setup guide, screenshots
- [ ] Write tests for core modules

## Target LinkedIn Post

> **I built an open-source AI phishing detector. Here's why.**
>
> After reading hundreds of threads on r/cybersecurity about AI-generated phishing bypassing traditional filters, I decided to build something about it.
>
> **PhishRadar** is a Python + FastAPI tool that:
> - Pulls live threat data from PhishTank, URLhaus, and Reddit
> - Classifies suspicious URLs using a trained ML model
> - Uses Claude AI to explain *why* something is dangerous — in plain English
>
> 91% of breaches still start with phishing. The tools to detect it exist. What's missing is tools that *explain* it — so non-technical teams can actually act on alerts instead of ignoring them.
>
> 3 things I learned building this:
> 1. [Technical insight about feature engineering for URL classification]
> 2. [Insight about prompt engineering for security analysis]
> 3. [Insight about the gap between detection and actionable intelligence]
>
> GitHub: [link]
>
> #cybersecurity #python #AI #opensource #freshgrad

## What This Demonstrates to Employers

| Skill | Evidence |
|-------|----------|
| Python proficiency | Full backend, ML pipeline, API integrations |
| API design | FastAPI with documented endpoints, structured responses |
| Machine learning | Trained and evaluated a classifier on real data |
| AI integration | Claude API for practical threat intelligence |
| Security fundamentals | Threat feeds, phishing patterns, IOC extraction |
| Software engineering | Project structure, tests, documentation, version control |
| Communication | README, architecture docs, LinkedIn writeup |

## Resources & References

### APIs & Datasets
- [PhishTank API](https://phishtank.org/developer_info.php)
- [URLhaus API](https://urlhaus-api.abuse.ch/)
- [abuse.ch Threat Intelligence](https://abuse.ch/)
- [Anthropic Claude API Docs](https://docs.anthropic.com/)
- [UCI Phishing Websites Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites)
- [PRAW — Reddit API Wrapper](https://praw.readthedocs.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

### Reddit & Community Sources That Inspired This

#### The Big Picture
- [From Phishing to AI Chaos: What My Analysis of All Reddit CyberSecurity Discussions So Far in 2026 Revealed](https://elnion.com/2026/01/27/from-phishing-to-ai-chaos-what-my-analysis-of-all-reddit-cybersecurity-discussions-so-far-in-2026-revealed/) — Elnion, Jan 27 2026. Meta-analysis of r/cybersecurity themes.
- [Confusion and fear send people to Reddit for cybersecurity advice](https://www.helpnetsecurity.com/2026/01/20/reddit-cybersecurity-help-questions/) — Help Net Security, Jan 20 2026. Google/UCL study of 1.1B Reddit posts: 100K+ monthly help requests, scams #1 concern.
- [What Goes on in the CyberSecurity Reddit is Wild](https://www.franksworld.com/2026/03/11/what-goes-on-in-the-cybersecurity-reddit-is-wild/) — Frank's World, Mar 11 2026.

#### AI Phishing
- [AI-Generated Phishing: The Top Enterprise Threat of 2026](https://www.strongestlayer.com/blog/ai-generated-phishing-enterprise-threat) — StrongestLayer
- [AI Phishing Attacks: How Big is the Threat?](https://hoxhunt.com/blog/ai-phishing-attacks) — Hoxhunt
- [AI is driving a new kind of phishing at scale](https://www.helpnetsecurity.com/2026/02/05/ai-driven-phishing-threats-increase/) — Help Net Security, Feb 5 2026
- [Phishing trends in 2026: The rise of AI, MFA exploits and polymorphic attacks](https://managedservicesjournal.com/articles/phishing-trends-in-2026-the-rise-of-ai-mfa-exploits-and-polymorphic-attacks/) — Managed Services Journal

#### CISA ChatGPT Incident
- [Trump's acting cybersecurity chief uploaded sensitive government docs to ChatGPT](https://techcrunch.com/2026/01/28/trumps-acting-cybersecurity-chief-uploaded-sensitive-government-docs-to-chatgpt/) — TechCrunch, Jan 28 2026
- [CISA chief uploaded sensitive government files to public ChatGPT](https://www.csoonline.com/article/4124320/cisa-chief-uploaded-sensitive-government-files-to-public-chatgpt.html) — CSO Online
- [The CISA ChatGPT incident: A watershed moment for cybersecurity leadership](https://tyfone.com/news/op-ed/the-cisa-chatgpt-incident-a-watershed-moment-for-cybersecurity-leadership/) — Tyfone

#### Shadow AI & Data Leakage
- [Shadow AI: When everyone becomes a data leak waiting to happen](https://www.informationweek.com/machine-learning-ai/shadow-ai-when-everyone-becomes-a-data-leak-waiting-to-happen) — InformationWeek
- [12 Critical Shadow AI Security Risks in 2026](https://netwrix.com/en/resources/blog/shadow-ai-security-risks/) — Netwrix
- [Personal LLM Accounts Drive Shadow AI Data Leak Risks](https://www.infosecurity-magazine.com/news/personal-llm-accounts-drive-shadow/) — Infosecurity Magazine
- [77% of Employees Leak Data via ChatGPT](https://www.esecurityplanet.com/news/shadow-ai-chatgpt-dlp/) — eSecurity Planet

#### SOC Alert Fatigue & Burnout
- [The L1 SOC Analyst Crisis: Reddit Thread Reveals What's Really Breaking Security Operations](https://www.cmdzero.io/blog-posts/the-l1-soc-analyst-crisis-reddit-thread-reveals-whats-really-breaking-security-operations) — CmdZero (analysis of a viral r/cybersecurity post)
- [Alert Fatigue Is Killing Your SOC. Here's What Actually Works in 2026](https://torq.io/blog/cybersecurity-alert-management-2026/) — Torq
- [SOC Alert Fatigue: Causes, Impact & AI Solutions](https://cyberdefenders.org/blog/soc-alert-fatigue/) — CyberDefenders
- [Analyst Burnout Is an Advanced Persistent Threat](https://www.darkreading.com/cybersecurity-operations/analyst-burnout-is-advanced-persistent-threat) — Dark Reading

#### ShinyHunters Campaign
- [Over 100 Organizations Targeted in ShinyHunters Phishing Campaign](https://www.securityweek.com/over-100-organizations-targeted-in-shinyhunters-phishing-campaign/) — SecurityWeek
- [ShinyHunters claims Okta customer breaches](https://www.theregister.com/2026/01/23/shinyhunters_claims_okta_customer_breaches/) — The Register, Jan 23 2026
- [Mandiant Finds ShinyHunters Using Vishing Attacks](https://thehackernews.com/2026/01/mandiant-finds-shinyhunters-using.html) — The Hacker News
- [ShinyHunters Weaponized a Security Tool to Breach 400 Companies](https://stateofsurveillance.org/news/shinyhunters-salesforce-aura-400-companies-security-tool-weaponized-2026/) — State of Surveillance
- [Harvard University ShinyHunters Data Breach Post-Mortem](https://www.infostealers.com/article/a-technical-and-ethical-post-mortem-of-the-feb-2026-harvard-university-shinyhunters-data-breach/) — InfoStealers

#### AI Skills & Cybersecurity Careers
- [Top 10 Emerging AI Security Roles 2026](https://www.practical-devsecops.com/emerging-ai-security-roles/) — Practical DevSecOps
- [Rise of AI Security Jobs in 2026: Who's Hiring](https://www.heisenberginstitute.com/ai-security/ai-security-jobs-2026-hiring/) — Heisenberg Institute
- [Will AI Replace Cybersecurity Jobs?](https://purplesec.us/learn/ai-replacing-cybersecurity-jobs/) — PurpleSec
- [SOC Analyst Career Path & Salary Guide 2026](https://www.dropzone.ai/resource-guide/soc-analyst-career-path-salary-guide-2026-ai-powered-edition) — Dropzone AI

#### Breaches & Incidents (2026)
- [Major Cyber Attacks in January 2026](https://www.cm-alliance.com/cybersecurity-blog/major-cyber-attacks-data-breaches-ransomware-attacks-in-january-2026) — CM Alliance
- [February 2026 Cyber Attacks](https://www.cm-alliance.com/cybersecurity-blog/february-2026-recent-cyber-attacks-data-breaches-ransomware-attacks) — CM Alliance
- [2026 Data Breaches](https://www.pkware.com/blog/2026-data-breaches) — PKWARE
- [The Biggest Cybersecurity Breaches of 2026 So Far](https://www.acilearning.com/blog/the-biggest-cybersecurity-breaches-of-2026-so-far-and-the-training-that-could-have-prevented-them/) — ACI Learning
- [The State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/) — BlackFog

#### Industry Trend Reports
- [The 6 Cybersecurity Trends That Will Shape 2026](https://www.isaca.org/resources/news-and-trends/industry-news/2026/the-6-cybersecurity-trends-that-will-shape-2026) — ISACA
- [10 Cybersecurity Trends to Watch in 2026](https://www.techtarget.com/searchsecurity/feature/Cybersecurity-trends-to-watch) — TechTarget
- [Cyber threats to watch in 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/) — World Economic Forum
- [5 Cybersecurity Trends to Watch in 2026](https://www.cybersecuritydive.com/news/5-cybersecurity-trends-2026/810354/) — Cybersecurity Dive
- [10 Cyber Security Trends for 2026](https://www.sentinelone.com/cybersecurity-101/cybersecurity/cyber-security-trends/) — SentinelOne
