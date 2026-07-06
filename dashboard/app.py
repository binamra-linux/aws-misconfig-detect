import sys
from pathlib import Path

# Make the project root importable regardless of the working directory
# streamlit was launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from backend.ai.groq_client import explain_finding
from backend.scanner import run_scan

st.set_page_config(page_title="AWS Misconfiguration Detector", layout="wide")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLOR = {
    "CRITICAL": "#8B0000",
    "HIGH": "#D9534F",
    "MEDIUM": "#F0AD4E",
    "LOW": "#5BC0DE",
}

st.title("AWS Cloud Misconfiguration Detector")
st.caption("Read-only scan of your AWS account, with AI-generated risk explanations and remediation steps.")

if "findings" not in st.session_state:
    st.session_state.findings = None

if st.button("Run Scan", type="primary"):
    with st.spinner("Scanning AWS account..."):
        try:
            st.session_state.findings = run_scan()
        except Exception as e:
            st.error(f"Scan failed: {e}")

findings = st.session_state.findings

if findings is None:
    st.info("Click 'Run Scan' to check your AWS account for misconfigurations.")
elif not findings:
    st.success("No misconfigurations found in the scanned services.")
else:
    st.write(f"Found **{len(findings)}** issue(s).")

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity.value if hasattr(f.severity, "value") else f.severity),
    )

    for finding in sorted_findings:
        severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
        color = SEVERITY_COLOR.get(severity, "#777777")

        with st.expander(f"[{severity}] {finding.resource_type} `{finding.resource_id}` — {finding.description}"):
            st.markdown(
                f"<span style='background-color:{color}; color:white; padding:2px 10px; "
                f"border-radius:4px; font-size:0.85em; font-weight:600'>{severity}</span>",
                unsafe_allow_html=True,
            )
            st.write("")
            st.write(finding.description)
            st.json(finding.detail)

            ai_key = f"ai_{finding.resource_id}_{finding.check_type}"
            if st.button("Get AI Explanation & Fix", key=f"btn_{ai_key}"):
                with st.spinner("Asking Groq..."):
                    try:
                        st.session_state[ai_key] = explain_finding(finding)
                    except Exception as e:
                        st.session_state[ai_key] = f"Could not get AI explanation: {e}"

            if ai_key in st.session_state:
                st.markdown("---")
                st.markdown(st.session_state[ai_key])
