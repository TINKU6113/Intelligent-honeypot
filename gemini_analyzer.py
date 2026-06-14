"""
gemini_analyzer.py
------------------
Core Gemini AI analysis engine for honeypot log chunks.
Handles both SSH (cowrie) and HTTP log analysis.
"""

import os
import json
import time
from datetime import datetime

import google.generativeai as genai
from ai_engine.prompt_templates import COWRIE_PROMPT_TEMPLATE, HTTP_PROMPT_TEMPLATE

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "models/gemini-2.5-flash"
DEFAULT_CHUNK_SIZE = 60
DEFAULT_OUTPUT_DIR_COWRIE = "reports/cowrie"
DEFAULT_OUTPUT_DIR_HTTP = "reports/http"


def configure_gemini(api_key: str, preferred_model: str = DEFAULT_MODEL) -> str:
    """
    Configure the Gemini API and verify connectivity.
    Returns the model name that successfully connected.
    """
    if not api_key:
        raise ValueError("No API key provided. Get one from https://aistudio.google.com/app/apikey")

    genai.configure(api_key=api_key)

    try:
        model = genai.GenerativeModel(preferred_model)
        resp = model.generate_content("Hello Gemini — connectivity test for honeypot project.")
        print(f"✅ Connected to Gemini model: {preferred_model}")
        print("Sample response (first 200 chars):\n", resp.text[:200])
        return preferred_model

    except Exception as e:
        print(f"⚠️  Preferred model failed: {e}")
        print("\nListing available models:")

        models = list(genai.list_models())
        for i, m in enumerate(models[:80], 1):
            print(f"  {i}. {m.name}")

        # Auto-select first suitable flash model
        chosen = next(
            (m.name for m in models if "flash" in m.name.lower() and "gemini" in m.name.lower()),
            models[0].name if models else None,
        )
        if not chosen:
            raise RuntimeError("No usable Gemini model found. Check your API key and network.")

        print(f"\nAuto-selecting model: {chosen}")
        test_model = genai.GenerativeModel(chosen)
        test_model.generate_content("Connectivity test.")
        print(f"✅ Connected to {chosen}")
        return chosen


# ---------------------------------------------------------------------------
# Low-level Gemini call
# ---------------------------------------------------------------------------

def call_gemini(prompt: str, model_name: str, max_retries: int = 3, backoff: float = 2.0) -> str:
    """Send a prompt to Gemini and return the response text with retry logic."""
    model = genai.GenerativeModel(model_name)
    for attempt in range(1, max_retries + 1):
        try:
            resp = model.generate_content(prompt)
            return resp.text
        except Exception as e:
            print(f"  Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(backoff * attempt)
            else:
                raise


# ---------------------------------------------------------------------------
# Cowrie (SSH) analysis
# ---------------------------------------------------------------------------

def analyze_cowrie_chunks(
    structured_entries: list,
    model_name: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    output_dir: str = DEFAULT_OUTPUT_DIR_COWRIE,
) -> list:
    """
    Chunk and analyze cowrie log entries using Gemini.
    Saves per-chunk reports and returns (filename, text) tuples.
    """
    os.makedirs(output_dir, exist_ok=True)
    chunks = _chunk_list(structured_entries, chunk_size)
    all_reports = []

    for idx, chunk in enumerate(chunks, 1):
        print(f"\n--- Processing cowrie chunk {idx}/{len(chunks)} ({len(chunk)} entries) ---")
        payload = json.dumps(chunk, ensure_ascii=False)
        prompt = COWRIE_PROMPT_TEMPLATE.format(entries=payload)

        try:
            report_text = call_gemini(prompt, model_name)
        except Exception as e:
            report_text = f"ERROR generating report for chunk {idx}: {e}"

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(output_dir, f"cowrie_chunk{idx}_{ts}.txt")
        _write_report(out_path, report_text)
        all_reports.append((out_path, report_text))
        time.sleep(0.5)

    return all_reports


# ---------------------------------------------------------------------------
# HTTP log analysis
# ---------------------------------------------------------------------------

def analyze_http_chunks(
    structured_entries: list,
    model_name: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    output_dir: str = DEFAULT_OUTPUT_DIR_HTTP,
) -> list:
    """
    Chunk and analyze HTTP log entries using Gemini.
    Saves per-chunk reports and returns (filename, text) tuples.
    """
    os.makedirs(output_dir, exist_ok=True)
    chunks = _chunk_list(structured_entries, chunk_size)
    all_reports = []

    for idx, chunk in enumerate(chunks, 1):
        print(f"\n--- Processing HTTP chunk {idx}/{len(chunks)} ({len(chunk)} entries) ---")
        compact = _compact_http_entry(chunk)
        payload = json.dumps(compact, ensure_ascii=False)
        prompt = HTTP_PROMPT_TEMPLATE.format(entries=payload)

        try:
            report_text = call_gemini(prompt, model_name)
        except Exception as e:
            report_text = f"ERROR generating report for chunk {idx}: {e}"

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(output_dir, f"http_chunk{idx}_{ts}.txt")
        _write_report(out_path, report_text)
        all_reports.append((out_path, report_text))
        time.sleep(0.5)

    return all_reports


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate_reports(all_reports: list, output_dir: str, label: str = "honeypot") -> str:
    """Merge all chunk reports into one aggregated report file."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    agg_path = os.path.join(output_dir, f"aggregated_{label}_report_{ts}.txt")

    with open(agg_path, "w", encoding="utf-8") as f:
        f.write(f"AI Honeypot Aggregate Report [{label}] - generated {datetime.utcnow().isoformat()}Z\n\n")
        for fname, text in all_reports:
            f.write(f"--- From: {fname} ---\n\n{text}\n\n")

    print(f"Aggregated report saved to: {agg_path}")
    return agg_path


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _chunk_list(lst: list, n: int) -> list:
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def _write_report(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"  Saved → {path}")


def _compact_http_entry(chunk: list) -> list:
    """Strip HTTP entries down to fields that matter for the prompt."""
    return [
        {
            "timestamp": e.get("timestamp", ""),
            "src_ip": e.get("src_ip", ""),
            "method": e.get("method", ""),
            "path": e.get("path_normalized", e.get("path", "")),
            "status": e.get("status", ""),
            "size": e.get("size", ""),
            "referrer": e.get("referrer", ""),
            "user_agent": e.get("user_agent", ""),
            "suspicion_flags": e.get("suspicion_flags", []),
            "_line_no": e.get("_line_no"),
        }
        for e in chunk
    ]
