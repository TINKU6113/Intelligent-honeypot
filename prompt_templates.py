"""
prompt_templates.py
-------------------
All LLM prompt templates used by the Gemini analyzer.
Edit here to tune analysis focus without touching business logic.
"""

# ---------------------------------------------------------------------------
# SSH / Cowrie prompt
# ---------------------------------------------------------------------------

COWRIE_PROMPT_TEMPLATE = """
You are an expert honeypot analyst. Given the following list of attacker log entries
(each is a JSON object with: timestamp, src_ip, event, input, username, session),
produce the following labeled sections:

SUMMARY: 2-4 lines of what this chunk shows (attack type, likely intent).
TOP_IPS: Top 3 most active IPs and their counts.
TOP_COMMANDS: Top 5 most common commands/inputs and counts.
SUSPICIOUS_SEQUENCES: Any suspicious sequences (e.g., upload→chmod→exec, brute-force patterns).
RECOMMENDATIONS: One concise defensive action for defenders.

Return plain text with the labeled sections exactly as above. Keep it brief.

Entries:
{entries}
"""

# ---------------------------------------------------------------------------
# HTTP / Web honeypot prompt
# ---------------------------------------------------------------------------

HTTP_PROMPT_TEMPLATE = """
You are an expert web-honeypot analyst. Given this array of HTTP access log entries
(JSON objects with fields: timestamp, src_ip, method, path, protocol, status,
size, referrer, user_agent, suspicion_flags, _line_no), produce the following
labeled sections:

SUMMARY: 2-4 lines describing main activity and likely intent.
TOP_IPS: Top 5 source IPs and counts.
TOP_METHODS: Counts by HTTP method.
TOP_PATHS: Top 10 requested paths (normalized).
SUSPICIOUS_HITS: Entries or patterns of clear malicious behavior (mention line numbers and reasons).
RECOMMENDATIONS: Up to 3 short defensive actions (e.g., block IPs, patch endpoints, add WAF rules).

Return plain text with the labeled sections exactly as above.

Entries:
{entries}
"""
