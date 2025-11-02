"""Streamlit dashboard for interacting with the DoubleThink API."""
from __future__ import annotations

import json
from typing import Any, Dict, List

import altair as alt
import requests
import streamlit as st

API_URL_DEFAULT = "http://localhost:8000"


@st.cache_data(show_spinner=False)
def fetch_samples(api_base: str) -> List[Dict[str, Any]]:
    response = requests.get(f"{api_base}/samples", timeout=10)
    response.raise_for_status()
    return response.json()


def fetch_sample_payload(api_base: str, sample_id: str) -> Dict[str, Any]:
    response = requests.get(f"{api_base}/samples/{sample_id}", timeout=10)
    response.raise_for_status()
    return response.json()


def run_analysis(api_base: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(f"{api_base}/analyze", json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def _render_rule_breakdown(breakdown: List[Dict[str, Any]]) -> None:
    if not breakdown:
        st.info("No rules were triggered for this analysis.")
        return

    chart_data = [
        {
            "Rule": item.get("rule_id") or item.get("title"),
            "Weight": item.get("weight", 0),
            "Title": item.get("title", ""),
        }
        for item in breakdown
    ]

    chart = (
        alt.Chart(alt.Data(values=chart_data))
        .mark_bar()
        .encode(x="Rule:N", y="Weight:Q", tooltip=["Rule", "Title", "Weight"])
        .properties(height=300)
    )
    st.altair_chart(chart, use_container_width=True)
    st.subheader("Triggered Rules")
    st.table(breakdown)


st.set_page_config(page_title="DoubleThink Dashboard", layout="wide")
st.title("DoubleThink Interactive Dashboard")
st.caption("Analyze URLs and HTML content with explainable rule breakdowns.")

with st.sidebar:
    st.header("Configuration")
    api_base = st.text_input("API base URL", API_URL_DEFAULT)
    st.markdown(
        "Use `uvicorn webapp.api:app --reload` to start the backend before interacting here."
    )

samples: List[Dict[str, Any]] = []
try:
    samples = fetch_samples(api_base)
except Exception:
    st.sidebar.warning("Unable to load samples from the API. Ensure the backend is running.")

if "mode" not in st.session_state:
    st.session_state.mode = "url"
if "url_input" not in st.session_state:
    st.session_state.url_input = ""
if "html_input" not in st.session_state:
    st.session_state.html_input = ""

mode = st.radio("Choose analysis type", ("url", "file"), index=0 if st.session_state.mode == "url" else 1)
st.session_state.mode = mode

col1, col2 = st.columns([2, 1])

with col2:
    st.subheader("Demo samples")
    if samples:
        options = {sample["label"]: sample for sample in samples if sample["mode"] == mode}
        if options:
            selected_label = st.selectbox("Load a sample", ["None"] + list(options.keys()))
            if selected_label != "None":
                sample_info = options[selected_label]
                if st.button("Load selected sample"):
                    try:
                        payload = fetch_sample_payload(api_base, sample_info["id"])
                    except Exception as exc:  # noqa: BLE001
                        st.error(f"Failed to load sample: {exc}")
                    else:
                        if payload["mode"] == "url":
                            st.session_state.url_input = payload.get("target", "")
                        else:
                            st.session_state.html_input = payload.get("content", "")
        else:
            st.info("No samples available for this analysis mode.")
    else:
        st.caption("Samples could not be retrieved.")

with col1:
    st.subheader("Input")
    if mode == "url":
        url_value = st.text_input("URL", value=st.session_state.url_input)
        st.session_state.url_input = url_value
        origin = st.text_input("Expected origin domain (optional)")
        request_payload = {"mode": "url", "target": url_value}
        if origin:
            request_payload["origin"] = origin
    else:
        uploaded = st.file_uploader("Upload HTML", type=["html", "htm", "txt"])
        if uploaded is not None:
            try:
                content = uploaded.read().decode("utf-8")
                st.session_state.html_input = content
            except UnicodeDecodeError:
                st.error("Uploaded file must be UTF-8 encoded text.")
        html_value = st.text_area("HTML content", value=st.session_state.html_input, height=300)
        st.session_state.html_input = html_value
        origin = st.text_input("Expected origin domain (optional)")
        request_payload = {"mode": "file", "content": html_value}
        if origin:
            request_payload["origin"] = origin

result_container = st.empty()

if st.button("Run analysis", type="primary"):
    if mode == "url" and not st.session_state.url_input:
        st.warning("Please enter a URL to analyze.")
    elif mode == "file" and not st.session_state.html_input:
        st.warning("Provide HTML content or upload a file to analyze.")
    else:
        try:
            response = run_analysis(api_base, request_payload)
        except requests.HTTPError as exc:
            try:
                detail = exc.response.json().get("detail")
            except Exception:  # noqa: BLE001
                detail = str(exc)
            result_container.error(f"API error: {detail}")
        except Exception as exc:  # noqa: BLE001
            result_container.error(f"Request failed: {exc}")
        else:
            with result_container.container():
                result = response.get("result", {})
                breakdown = response.get("breakdown", [])
                st.success("Analysis completed.")
                summary_cols = st.columns(3)
                summary_cols[0].metric("Score", result.get("score"))
                summary_cols[1].metric("Severity", result.get("severity"))
                summary_cols[2].metric("Target", result.get("target"))

                st.subheader("Metadata")
                metadata = result.get("metadata") or {}
                if metadata:
                    st.json(metadata)
                else:
                    st.write("No metadata returned.")

                st.subheader("Rule breakdown")
                _render_rule_breakdown(breakdown)

                with st.expander("Raw response"):
                    st.code(json.dumps(response, indent=2))
