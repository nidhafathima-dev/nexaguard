# NexaGuard: Next-Gen Security Intelligence

**NexaGuard** is a high-fidelity cybersecurity intelligence dashboard built for modern threat analysis. It leverages the power of Gemini 2.0 to identify vulnerabilities, map complex attack topologies, and provide actionable defense strategies instantly.

## 🚀 Key Features

- **Analyzer Intelligence**: Real-time vulnerability scoring with a strict deterministic rubric.
- **Pictorial Compromise Topology**: High-impact visual graphs representing breach heritage and system exposure.
- **Intelligence Fallback Chain**: Multi-model resilience engine that cycles through 5+ Gemini variants (2.0-flash, 1.5-pro, etc.) to ensure 100% uptime.
- **Deep Sync Intelligence**: Persistent scan caching and environment synchronization for maximum performance.
- **Premium Design**: Modern glassmorphic UI built with a Violet-Blue-Cyan palette and Inter typography.

## 🛠️ Technology Stack

- **AI Engine**: Google Gemini (via `google-genai`).
- **Framework**: Streamlit.
- **Visualization**: Mermaid.js (Pictorial Heritage Graphs).
- **Backend**: Python 3.11, BeautifulSoup4 (Recon Scraping).
- **Deployment**: Google Cloud Run (Containerized).

## 📦 Deployment Instructions (GCP)

1. **Clone the Repo**:
   ```bash
   git clone [your-repo-link]
   cd hackathon
   ```

2. **Setup Environment**:
   Create a `.env` file with your `GEMINI_API_KEY`.

3. **Deploy to Cloud Run**:
   ```bash
   gcloud run deploy nexaguard --source . --port 8080 --allow-unauthenticated
   ```

## 🛡️ Security Note
All scanning results are processed with strict input normalization to ensure consistent, reliable security scoring across sessions.

---
*Built for Hackathon 2026*
