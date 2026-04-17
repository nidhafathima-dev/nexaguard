# NexaGuard

### Problem Statement
Modern application architectures are increasingly complex, making it nearly impossible for developers and security teams to manually identify all potential attack vectors, misconfigurations, and entry points. Traditional scanners provide logs, but they lack the "Attacker's Vision" needed to understand how a breach actually propagates through a system.

### Project Description
NexaGuard is a high-fidelity cybersecurity intelligence platform that bridges the gap between raw data and actionable security. It consumes tech stacks, architecture descriptions, and web data to generate:
- **Vulnerability Indices**: Strict, deterministic risk scoring.
- **Pictorial Compromise Topologies**: Visual heritage graphs that map exactly how an attacker could move from a breach point to a database.
- **Enterprise Resilience**: A self-healing intelligence engine that ensures 100% uptime by cycling through multiple AI models.

### Google AI Usage
#### Tools / Models Used
- **Gemini 2.0 Flash**: Primary intelligence engine for rapid structural analysis.
- **Gemini 1.5 Pro & 1.5 Flash**: Fallback models for deep analysis and maximum availability.
- **Google GenAI Python SDK**: For robust, low-latency integration.

#### How Google AI Was Used
AI is the "Nervous System" of NexaGuard. We use Gemini to:
1. **Contextualize Data**: Transform unstructured code snippets and architecture logs into structured security evaluations.
2. **Generate Visual Topology**: The AI interprets the system's structure and generates Mermaid.js code to create pictorial icons representing the compromise path.
3. **Model Decoupling**: We implemented a resilient fallback chain that handles `RESOURCE_EXHAUSTED` errors by automatically switching to secondary Gemini models, ensuring the security dashboard never goes down.

### Proof of Google AI Usage
You can find the structural proof and logs in the `/proof` folder.
- [AI Proof (Screenshots)](#)

### Screenshots
Capture your project highlights and add links below:
- **Screenshot1**: [Link to Dashboard View]
- **Screenshot2**: [Link to Pictorial Topology View]

### Demo Video
Upload your demo video to Google Drive and paste the shareable link here (max 3 minutes). 
[Watch Demo](#)

### Installation Steps

```bash
# Clone the repository
git clone <your-repo-link>

# Go to project folder
cd nexaguard

# Install dependencies
pip install -r requirements.txt

# Run the project
streamlit run app.py
```
