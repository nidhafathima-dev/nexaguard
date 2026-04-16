import streamlit as st
import json
import os
from dotenv import load_dotenv
from google import genai
from google.genai import types
import hashlib
import time

import dotenv
dotenv.load_dotenv(override=True)

def nexa_html_card(content: str, height: int = 300):
    """
    Renders an isolated HTML block with NexaGuard themes.
    """
    styled_content = f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        body {{ 
            margin: 0; 
            padding: 0; 
            background: transparent; 
            font-family: 'Inter', sans-serif;
            color: #E5E7EB;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
    </style>
    <div class="card">
        {content}
    </div>
    """
    st.components.v1.html(styled_content, height=height, scrolling=True)

def mermaid_chart(mermaid_code: str):
    """
    Renders a high-fidelity pictorial security diagram using Mermaid.js.
    """
    html_code = f"""
    <div class="mermaid" style="display: flex; justify-content: center; background: rgba(0,0,0,0.2); border-radius: 12px; padding: 20px;">
    {mermaid_code}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({{
            startOnLoad: true,
            theme: 'dark',
            securityLevel: 'loose',
            flowchart: {{
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }},
            themeVariables: {{
                primaryColor: '#7C3AED',
                primaryTextColor: '#fff',
                primaryBorderColor: '#A78BFA',
                lineColor: '#60A5FA',
                secondaryColor: '#1E1B4B',
                tertiaryColor: '#111827',
                fontFamily: 'Inter'
            }}
        }});
    </script>
    """
    st.components.v1.html(html_code, height=520, scrolling=True)

CACHE_FILE = "scan_cache.json"

def load_persistent_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_persistent_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except:
        pass

def analyze_security(data: str, api_key: str = None):
    """
    Calls Google AI Studio (Gemini 2.5 Flash) to analyze security.
    Returns structured JSON with attack_path, analyzer_results, defense_plan.
    """
    
    prompt = f"""
    You are a sophisticated malicious hacker and malware architect. Analyze the tech stack, architecture, and code snippets provided below to perform a rigorous security assessment.
    
    DATA SOURCE:
    {data}
    
    SCORING RUBRIC (0-100):
    - 0-20: System is robust with modern defenses and no obvious entry points.
    - 21-50: Minor misconfigurations or outdated versions without direct exploitability.
    - 51-75: Valid vulnerabilities present (e.g., lack of rate limiting, missing headers).
    - 76-100: Critical failures (e.g., clear injection paths, exposed secrets, broken auth).
    
    Please return the result exactly in this strict JSON structure:
    {{
        "risk_score": "[Score based on rubric]",
        "attack_path": "A ruthless, step-by-step description of the kill chain.",
        "breach_points": [
            {{ "area": "Component name", "reason": "Specific technical flaw" }}
        ],
        "components": [
            {{ "name": "Component name", "risk": "[0-100]" }}
        ],
        "failed_tests": [
            {{ "name": "Test name", "risk": "[0-100]" }}
        ],
        "defense_plan": [
            "Actionable strategy step"
        ],
        "attacker_vision": [
            {{
                "step": "Phase identifier",
                "method": "Technical approach",
                "leverage": "Resulting advantage"
            }}
        ],
        "defender_fixes": [
            {{
                "target": "Asset name",
                "action": "Plain English fix description",
                "why": "Business/Security value"
            }}
        ],
        "mermaid_graph": "graph TD\nA{{Attacker}} -->|Exploit| B(Server)\nB -->|Infiltrate| C[(Database)]\nstyle A fill:#7C3AED,stroke:#A78BFA\nstyle B fill:#3B82F6,stroke:#60A5FA\nstyle C fill:#1E1B4B,stroke:#3B82F6"
    }}
    
    IMPORTANT: The 'mermaid_graph' MUST be a high-impact PICTORIAL diagram using node shapes ({{}}, (), [[]], [()]) and styles (colors/borders) to represent the compromise path.
    Use ONLY plain English for 'defender_fixes'. NO CODE SNIPPETS.
    Generate 2-3 breach_points, 3-5 components, 2-4 failed tests, 3-5 attacker_vision steps, and 3-5 defender_fixes.
    """
    
    client = genai.Client(api_key=api_key)
    # Extended Fallback Chain for Maximum Resilience
    models_to_try = [
        'gemini-2.0-flash', 
        'gemini-1.5-flash', 
        'gemini-flash-latest',
        'gemini-2.0-flash-lite', 
        'gemini-1.5-pro'
    ]
    
    last_error = ""
    for model_name in models_to_try:
        max_retries = 2
        retry_delay = 3
        
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.0,
                    ),
                )
                return json.loads(response.text)
            except Exception as e:
                err_str = str(e)
                last_error = err_str
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "404" in err_str or "NOT_FOUND" in err_str:
                    if attempt < max_retries - 1 and ("404" not in err_str):
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                    else:
                        break # Try next model
                return {"error": err_str}
    
    # If all models fail
    key_hint = f"...{api_key[-4:]}" if (api_key and len(api_key) > 4) else "NONE"
    trace_info = " | ".join([f"{m}:FAILED" for m in models_to_try])
    return {"error": f"Quota Exhausted across all intelligences. [Trace: {trace_info}]. Key: {key_hint}"}

# --- UI Setup ---

st.set_page_config(page_title="NexaGuard", page_icon=":shield:", layout="wide", initial_sidebar_state="expanded")

# --- Global NexaGuard Glassmorphism Theme (Dashboard Base) ---
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* Base Styles & Typography */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

[data-testid="stAppViewContainer"] {
    background-color: #0B0F1A !important;
}

[data-testid="stHeader"] {
    background-color: transparent !important;
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background-color: #0F172A !important;
    border-right: 1px solid rgba(255,255,255,0.05) !important;
}

h1, h2, h3, h4, h5, p, span, label, div {
    color: #E5E7EB;
}

/* Inputs & Textareas */
[data-testid="stTextInput"] div div, [data-testid="stTextArea"] div div {
    background-color: #111827 !important;
    border: 1px solid rgba(255, 255, 255, 0.05) !important;
    color: white !important;
    border-radius: 10px !important;
    box-shadow: 0px 4px 10px rgba(0,0,0,0.2) !important;
}
[data-testid="stTextInput"] div div:focus-within, [data-testid="stTextArea"] div div:focus-within {
    border: 1px solid #7C3AED !important;
    box-shadow: 0 0 15px rgba(124, 58, 237, 0.4) !important;
}

/* Base Primary Button for Dashboard UI (Violet to Blue Glow) */
[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #7C3AED, #3B82F6) !important;
    border: none !important;
    border-radius: 50px !important;
    color: white !important;
    font-weight: 600 !important;
    box-shadow: 0px 0px 20px rgba(124, 58, 237, 0.3) !important;
    transition: all 0.3s ease !important;
}
[data-testid="baseButton-primary"]:hover {
    transform: scale(1.02);
    box-shadow: 0px 0px 30px rgba(168, 85, 247, 0.6) !important;
}

[data-testid="baseButton-secondary"] {
    background: rgba(255, 255, 255, 0.03) !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 50px !important;
    color: #9CA3AF !important;
    transition: all 0.3s ease !important;
}
[data-testid="baseButton-secondary"]:hover {
    color: white !important;
    border: 1px solid #7C3AED !important;
}

/* Reusable Components Constraints */
.glass-card {
    background: rgba(11, 10, 26, 0.5);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 30px;
    box-shadow: 0px 10px 40px rgba(0, 0, 0, 0.4);
    margin-bottom: 24px;
    height: 100%;
}

.dashboard-section-title {
    font-size: 0.85rem;
    color: #9CA3AF;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 20px;
    font-weight: 600;
}

.safe { color: #10B981; font-weight: bold; border: 1px solid rgba(16, 185, 129, 0.2); background: rgba(16, 185, 129, 0.1); padding: 2px 8px; border-radius: 6px; }
.critical { color: #8B5CF6; font-weight: bold; border: 1px solid rgba(139, 92, 246, 0.2); background: rgba(139, 92, 246, 0.1); padding: 2px 8px; border-radius: 6px; }

/* Mode Switcher UI (Strictly Oval & Glass) */
.mode-nav-container {
    display: flex;
    justify-content: center;
    margin-bottom: 50px;
    margin-top: 10px;
}
.mode-nav {
    background: rgba(15, 23, 42, 0.4);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 100px;
    padding: 8px;
    display: flex;
    gap: 15px;
    box-shadow: 0 15px 35px rgba(0,0,0,0.5);
}
/* Violet Buttons as requested */
[data-testid="baseButton-primary"] {
    background: #7C3AED !important;
    border: none !important;
    border-radius: 100px !important;
    color: white !important;
    box-shadow: 0 4px 15px rgba(124, 58, 237, 0.4) !important;
}
[data-testid="baseButton-secondary"] {
    background: transparent !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 100px !important;
    color: #9CA3AF !important;
}

/* Swipe In Animation */
@keyframes swipeIn {
    0% { transform: translateY(20px); opacity: 0; filter: blur(10px); }
    100% { transform: translateY(0); opacity: 1; filter: blur(0); }
}
.view-container {
    animation: swipeIn 0.5s ease-out forwards;
}
</style>
""", unsafe_allow_html=True)

if 'page' not in st.session_state:
    st.session_state.page = 'Landing'
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'results_cache' not in st.session_state:
    st.session_state.results_cache = {}
if 'dashboard_mode' not in st.session_state:
    st.session_state.dashboard_mode = 'Analyzer'

def navigate_to(page):
    st.session_state.page = page


# --- Application Router ---

if st.session_state.page == 'Landing':
    
    # Hide sidebar purely on Landing page for absolute cleanliness like the inspo image!
    st.markdown("""
    <style>
    [data-testid="collapsedControl"] { display: none !important; }
    [data-testid="stSidebar"] { display: none !important; }
    
    /* Background System: deep navy to near-black indigo */
    [data-testid="stAppViewContainer"] {
        background-color: #05060A !important;
        background-image: radial-gradient(circle at top, #0B0A1A 0%, #05060A 100%) !important;
    }
    
    /* Landing Page Specific Button Overrides */
    div[data-testid="stButton"] button {
        background: #F5F5F5 !important;
        background-color: #F5F5F5 !important;
        color: #05060A !important;
        border: none !important;
        border-radius: 50px !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
        font-size: 1.15rem !important;
        padding: 16px 45px !important;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(167, 139, 250, 0.2) !important;
        transition: all 0.3s ease !important;
        display: block;
        margin: 0 auto;
    }
    div[data-testid="stButton"] button p {
        color: #05060A !important;
        font-weight: 600 !important;
    }
    div[data-testid="stButton"] button:hover {
        transform: scale(1.03) !important;
        background: #FFFFFF !important;
        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.5), 0 0 40px rgba(167, 139, 250, 0.4) !important;
    }

    .landing-title {
        font-family: 'Inter', sans-serif !important;
        font-size: 5rem;
        font-weight: 600;
        color: #F5F5F5;
        letter-spacing: -0.02em;
        margin-bottom: 20px;
        text-align: center;
        line-height: 1.1;
        text-shadow: 0px 4px 50px rgba(255, 255, 255, 0.4);
    }
    .landing-subtitle {
        font-family: 'Inter', sans-serif !important;
        font-size: 1.25rem;
        font-weight: 400;
        color: rgba(229, 229, 229, 0.85); /* #E5E5E5 softened opacity */
        letter-spacing: 0.02em; /* generous spacing */
        max-width: 650px;
        margin: 0 auto 30px auto;
        text-align: center;
        line-height: 1.6;
        text-shadow: 0px 2px 20px rgba(139, 92, 246, 0.3);
    }
    </style>
    
<div style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 0; pointer-events: none; overflow: hidden; display: flex; align-items: flex-start; justify-content: center;">
<svg viewBox="0 0 1000 500" preserveAspectRatio="none" style="width: 150vw; height: 140vh; filter: blur(120px); opacity: 0.95; mix-blend-mode: screen; transform: translateY(22vh);">
<path d="M 0 -100 Q 500 480 1000 -100 L 1000 600 Q 500 20 0 600 Z" fill="rgba(109, 40, 217, 0.4)" />
<path d="M 0 50 Q 500 440 1000 50 L 1000 450 Q 500 60 0 450 Z" fill="rgba(167, 139, 250, 0.7)" />
<path d="M 0 150 Q 500 348 1000 150 L 1000 350 Q 500 152 0 350 Z" fill="#FFFFFF" />
</svg>
</div>
    """, unsafe_allow_html=True)
    
    # Hero Section Content
    st.markdown("""
<div style="display: flex; flex-direction: column; align-items: center; justify-content: center; margin-top: 15vh; position: relative; z-index: 10;">
<h1 class="landing-title">NexaGuard</h1>
<p class="landing-subtitle">Next-gen cybersecurity layer that identifies risks, maps attack paths, and strengthens defenses instantly.</p>
</div>
    """, unsafe_allow_html=True)
    
    # Start Scan Button strictly centering
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
        # using a secondary type button specifically for the landing page so we can restyle it to the clean white pill using the CSS above, without ruining the main purple primary buttons in the UI!
        if st.button("Start Scan", type="secondary", use_container_width=True):
            navigate_to("Dashboard")
            st.rerun()

elif st.session_state.page == 'Dashboard':
    # Sidebar Navigation & Input
    st.sidebar.markdown("<h2 style='text-align: center; color: #7C3AED'>NexaGuard</h2>", unsafe_allow_html=True)
    if st.sidebar.button("← Back to Home", type="secondary", use_container_width=True):
        navigate_to("Landing")
        st.session_state.scan_results = None
        st.rerun()
        
    st.sidebar.markdown("<hr style='border: 1px solid rgba(255,255,255,0.05);'>", unsafe_allow_html=True)
    st.sidebar.markdown("<p style='color: #9CA3AF; margin-bottom: 5px; font-weight: 500;'>Recon Params</p>", unsafe_allow_html=True)
    
    website_url = st.sidebar.text_input("Analyze Website URL", placeholder="https://example.com")
    tech_stack = st.sidebar.text_input("Tech Stack", placeholder="e.g., React, Node.js, PostgreSQL")
    architecture = st.sidebar.text_area("Architecture Description", placeholder="Describe how components interact...", height=100)
    code_snippets = st.sidebar.text_area("Code Snippets", placeholder="Paste relevant code here...", height=100)
    
    st.sidebar.markdown("<br>", unsafe_allow_html=True)
    if st.sidebar.button("Run Security Scan", type="primary", use_container_width=True):
        # Deep Sync: Reload .env precisely at scan trigger
        dotenv.load_dotenv(override=True)
        
        scraped_text = ""
        if website_url:
            with st.spinner(f"Scraping {website_url}..."):
                try:
                    import requests
                    from bs4 import BeautifulSoup
                    response = requests.get(website_url, timeout=10)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    scraped_text = soup.get_text(separator=' ', strip=True)[:15000] # Limit size to prevent token explosion
                except Exception as e:
                    st.sidebar.error(f"Could not scrape {website_url}: {e}")

        combined_data = f"Tech Stack: {tech_stack}\n\nArchitecture: {architecture}\n\nCode: {code_snippets}\n\nWebsite Data: {scraped_text}"
        
        import re
        # Normalize: Remove digits (dates/stamps), extra whitespace, and truncate to ignore footer noise
        normalized_data = re.sub(r'\d+', '', combined_data)
        normalized_data = " ".join(normalized_data.split())
        
        # Consistent result mapping
        data_hash = hashlib.md5(normalized_data.strip().encode()).hexdigest()
        
        # Load persistent cache
        persistent_cache = load_persistent_cache()
        
        # Error Handling
        if len(combined_data.strip()) < 50:
            st.sidebar.warning("Input is too short. Please provide more details.")
        elif data_hash in persistent_cache:
            st.session_state.scan_results = persistent_cache[data_hash]
        else:
            with st.spinner("Analyzing vulnerabilities with NexaGuard Nexus (Gemini Flash)..."):
                # Always grab the latest key from environment
                active_api_key = os.getenv("GEMINI_API_KEY")
                results = analyze_security(combined_data, active_api_key)
                
                st.session_state.scan_results = results
                if "error" not in results:
                    st.session_state.results_cache[data_hash] = results
                    persistent_cache[data_hash] = results
                    save_persistent_cache(persistent_cache)
                elif "429" in results["error"] or "RESOURCE_EXHAUSTED" in results["error"]:
                    st.sidebar.error("**API Quota Exhausted**")
                    st.sidebar.markdown("""
                    Your current API key has hit its daily limit.
                    
                    **How to fix:**
                    1. Get a fresh key from [Google AI Studio](https://aistudio.google.dev/app/apikey).
                    2. Update the `GEMINI_API_KEY` in your `.env` file.
                    """, unsafe_allow_html=True)
    
    # Dashboard Logic
    results = st.session_state.get('scan_results')
    
    if results:
        if "error" in results:
            st.error(f"Error during analysis: {results['error']}")
        else:
            # Top Mode Navigation (Oval buttons)
            st.markdown('<div class="mode-nav-container"><div class="mode-nav">', unsafe_allow_html=True)
            m_col1, m_col2, m_col3 = st.columns([1, 1, 1])
            with m_col1:
                if st.button("ANALYZER", type="primary" if st.session_state.dashboard_mode == "Analyzer" else "secondary", use_container_width=True):
                    st.session_state.dashboard_mode = "Analyzer"
                    st.rerun()
            with m_col2:
                if st.button("ATTACKER", type="primary" if st.session_state.dashboard_mode == "Attacker" else "secondary", use_container_width=True):
                    st.session_state.dashboard_mode = "Attacker"
                    st.rerun()
            with m_col3:
                if st.button("DEFENDER", type="primary" if st.session_state.dashboard_mode == "Defender" else "secondary", use_container_width=True):
                    st.session_state.dashboard_mode = "Defender"
                    st.rerun()
            st.markdown('</div></div>', unsafe_allow_html=True)

            st.markdown('<div class="view-container">', unsafe_allow_html=True)
            
            if st.session_state.dashboard_mode == "Analyzer":
                # Data Calculations before rendering
                try:
                    risk_percent = int(results.get("risk_score", 0))
                except (ValueError, TypeError):
                    risk_percent = 0

                gauge_color = "#EF4444" if risk_percent >= 60 else ("#3B82F6" if risk_percent > 0 else "#10B981")
                risk_label = "CRITICAL RISK" if risk_percent >= 60 else ("MODERATE RISK" if risk_percent > 0 else "SYSTEM SECURE")

                failed_html = ""
                for test in results.get("failed_tests", []):
                    name = test.get("name", "Unknown")
                    try:
                        risk = int(test.get("risk", 0))
                    except (ValueError, TypeError):
                        risk = 0
                    f_color = "#9333EA" if risk >= 80 else "#3B82F6"
                    failed_html += f"""<div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 10px;">
<div style="flex-grow: 1;">
<div style="color: #E5E7EB; font-weight: 500; font-size: 0.95em; margin-bottom: 4px;">{name}</div>
<div style="width: 100%; height: 3px; background: rgba(255,255,255,0.05); border-radius: 10px;">
<div style="width: {risk}%; height: 100%; background: {f_color}; border-radius: 10px;"></div>
</div>
</div>
<div style="color: {f_color}; font-weight: 700;">{risk}</div>
</div>"""

                comp_html = ""
                for comp in results.get("components", []):
                    name = comp.get("name", "Unknown")
                    try:
                        risk = int(comp.get("risk", 0))
                    except (ValueError, TypeError):
                        risk = 0
                    grad = "linear-gradient(90deg, #7C3AED, #3B82F6)"
                    comp_html += f"""<div style="margin-bottom: 12px; padding: 2px;">
<div style="display: flex; justify-content: space-between; font-size: 0.8em; margin-bottom: 4px; color: #9CA3AF;">
<span>{name}</span> <span>{risk}%</span>
</div>
<div style="width: 100%; height: 4px; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden;">
<div style="width: {risk}%; height: 100%; background: {grad}; border-radius: 10px;"></div>
</div>
</div>"""

                st.markdown(f"<h2 style='margin-bottom: 40px; text-align: center; color: #7C3AED; font-weight: 700;'>Intelligence Readout</h2>", unsafe_allow_html=True)
                
                # Master Grid with consistent spacing
                col1, col2 = st.columns([1, 1.5], gap="large")
                
                with col1:
                    # Risk Gauge Card
                    st.markdown(f"""
                    <div class="glass-card" style="text-align: center; border-bottom: 2px solid {gauge_color}33;">
                        <div class="dashboard-section-title">Vulnerability Index</div>
                        <div style="font-size: 5rem; font-weight: 800; color: {gauge_color}; text-shadow: 0px 0px 40px {gauge_color}55; line-height: 1;">
                            {risk_percent}%
                        </div>
                        <div style="color: {gauge_color}; font-weight: 700; font-size: 1.2rem; margin-top: 15px; letter-spacing: 1px;">{risk_label}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Defense Card
                    st.markdown("<div class='glass-card'><div class='dashboard-section-title' style='color:#22D3EE;'>Defense Protocol</div>", unsafe_allow_html=True)
                    for step in results.get("defense_plan", []):
                        st.markdown(f"<div style='margin-bottom: 15px; display: flex; align-items: flex-start;'><span style='color: #7C3AED; margin-right: 12px; font-weight: bold;'>•</span> <span style='color:#E5E7EB; line-height: 1.6; font-size: 0.95rem;'>{step}</span></div>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                
                with col2:
                    # Topology Card
                    st.markdown("<div class='glass-card' style='border: 1px solid rgba(124, 58, 237, 0.2);'><div class='dashboard-section-title' style='color:#A78BFA;'>Compromise Topology</div>", unsafe_allow_html=True)
                    m_graph = results.get("mermaid_graph", "graph TD\n  A{Target} -->|Analyzing| B(NexaGuard)")
                    mermaid_chart(m_graph)
                    st.markdown("</div>", unsafe_allow_html=True)

                    # Sub-Grid for Intelligence Datasets
                    d_col1, d_col2 = st.columns([1, 1])
                    with d_col1:
                        comp_title = '<p class="dashboard-section-title" style="color: #94A3B8;">Risk Dataset</p>'
                        nexa_html_card(comp_title + comp_html, height=450)
                    with d_col2:
                        failed_title = '<p class="dashboard-section-title" style="color: #A78BFA;">Test Intel</p>'
                        nexa_html_card(failed_title + failed_html, height=450)

            elif st.session_state.dashboard_mode == "Attacker":
                col1, col2 = st.columns([1.5, 1])
                with col1:
                    st.markdown("<div class='glass-card' style='border: 1px solid rgba(139, 92, 246, 0.2);'><h3 style='margin-top:0; color:#A78BFA; font-size: 1.2rem; margin-bottom: 20px;'>Weak Points (Entry Vectors)</h3>", unsafe_allow_html=True)
                    for point in results.get("breach_points", []):
                        st.markdown(f"""
                        <div style="margin-bottom: 15px; padding: 12px; background: rgba(139, 92, 246, 0.05); border-radius: 8px;">
                            <div style="color: #A78BFA; font-weight: 700; font-size: 1rem;">TARGET: {point.get('area')}</div>
                            <div style="color: #E5E7EB; font-size: 0.9rem;">{point.get('reason')}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

                    st.markdown("<div class='glass-card'><h3 style='margin-top:0; color:#A78BFA; font-size: 1.2rem; margin-bottom: 20px;'>Kill Chain Progression</h3>", unsafe_allow_html=True)
                    for vision in results.get("attacker_vision", []):
                        st.markdown(f"""
                        <div style="margin-bottom: 25px; padding: 15px; background: rgba(124, 58, 237, 0.05); border-left: 4px solid #7C3AED; border-radius: 4px;">
                            <div style="color: #A78BFA; font-weight: 700; font-size: 1.1rem; margin-bottom: 5px;">{vision.get('step')}</div>
                            <div style="color: #E5E7EB; font-size: 0.95rem; margin-bottom: 8px;"><strong>Method:</strong> {vision.get('method')}</div>
                            <div style="color: #9CA3AF; font-size: 0.9rem; font-style: italic;"><strong>leverage:</strong> {vision.get('leverage')}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    <div class="glass-card" style="border: 1px solid rgba(139, 92, 246, 0.2); background: rgba(139, 92, 246, 0.02);">
                        <h3 style='margin-top:0; color:#8B5CF6; font-size: 1.2rem; margin-bottom: 10px;'>Compromised Assets</h3>
                        <p style="color: #6B7280; font-size: 0.85rem; margin-bottom: 20px;">System parts under total or partial adversary control.</p>
                    """, unsafe_allow_html=True)
                    for comp in results.get("components", []):
                        try:
                            risk = int(comp.get("risk", 0))
                        except (ValueError, TypeError):
                            risk = 0
                            
                        if risk > 30:
                            c_color = "#8B5CF6" if risk > 70 else "#3B82F6"
                            label = "COMPROMISED" if risk > 70 else "PARTIAL BREACH"
                            st.markdown(f"""
                            <div style="padding: 15px; background: {c_color}11; border: 1px solid {c_color}33; border-radius: 12px; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <div style="color: {c_color}; font-weight: 700; font-size: 1.1rem;">{comp.get("name")}</div>
                                    <div style="color: {c_color}; opacity: 0.7; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;">{label}</div>
                                </div>
                                <div style="color: {c_color}; font-size: 1.4rem; font-weight: 800;">{risk}%</div>
                            </div>
                            """, unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

            elif st.session_state.dashboard_mode == "Defender":
                st.markdown(f"<h2 style='margin-bottom: 30px; text-align: center; color: #10B981;'>System Protection Strategy</h2>", unsafe_allow_html=True)
                for fix in results.get("defender_fixes", []):
                    st.markdown(f"""
                    <div class="glass-card" style="border-left: 5px solid #10B981; padding: 25px;">
                        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                            <div style="background: rgba(16, 185, 129, 0.1); color: #10B981; padding: 8px 15px; border-radius: 50px; font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;">
                                {fix.get('target', 'Core System')}
                            </div>
                        </div>
                        <h3 style="color: #E5E7EB; margin-bottom: 10px; font-size: 1.25rem;">{fix.get('action')}</h3>
                        <p style="color: #9CA3AF; line-height: 1.6; font-size: 1rem;">
                            <strong style="color: #10B981;">Benefit:</strong> {fix.get('why')}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True) 
    else:
        st.markdown("<div style='text-align: center; margin-top: 100px; color: #6B7280; font-size: 1.2rem;'>Awaiting Intelligence Upload in Sidebar...</div>", unsafe_allow_html=True)
