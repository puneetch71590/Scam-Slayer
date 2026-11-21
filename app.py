"""
Scam Slayer - UPI Safety Coach (Flask backend).

What this file does:
  1. Serves the web app (index.html) at http://127.0.0.1:<PORT>/
  2. POST /ask      - forwards a described situation to the AI (Groq by default),
                      adding the secret API key on the server side. Requests that
                      contain a PIN, OTP, card/account or phone number are REFUSED
                      before they go anywhere.
                      The AI is told to answer as structured data (verdict, reason,
                      red flags, steps, with emojis). The server then:
                        - takes the verdict out of the text and returns it separately,
                          so the page shows it as the badge at the top left of the card
                          (SCAM / SUSPICIOUS / LIKELY SAFE / NOT SURE / INFO),
                        - removes any "this is a scam"-style sentence from the body,
                        - asks the AI which organisation its advice is based on, checks that it is
                          a real Indian body (RBI, NPCI, cyber police ...), takes it OUT of the
                          answer text and returns it separately for the "Source:" line,
                        - makes sure every reason, red flag and step starts with an emoji,
                        - always returns the same card layout as the built-in answers.
  3. POST /api/event, POST /api/quiz - store anonymous test data (no chat text,
                      no phone numbers): which scenario was matched, quiz results
  4. GET  /api/stats, GET /api/export.csv - team-only results for the 10-day test
                      (needs ADMIN_KEY)
"""

import collections
import csv
import hmac
import io
import json
import logging
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_file

# ---------------------------------------------------------------------------
# Configuration (read from the a.env file next to this script)
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
# Local use: keys live in a.env (or .env) next to this file. On a host such as Render, the keys come
# from the host's Environment settings instead, and these files are simply not there.
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR / "a.env")


def env_flag(name, default=False):
    """Return True if the environment variable is true/1/yes/on (or the default if unset)."""
    value = os.getenv(name, "").strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


def env_int(name, default):
    """Read an integer environment variable, falling back to a default."""
    try:
        return int(os.getenv(name, "").strip())
    except ValueError:
        return default


def env_float(name, default):
    """Read a decimal environment variable, falling back to a default."""
    try:
        return float(os.getenv(name, "").strip())
    except ValueError:
        return default


# ---- Which AI provider to use: "groq" (default) or "supabase" ----
VALID_PROVIDERS = ("groq", "supabase")
CHAT_PROVIDER = os.getenv("CHAT_PROVIDER", "groq").strip().lower()
USING_GROQ = CHAT_PROVIDER == "groq"

# ---- Groq settings ----
DEFAULT_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"

# The instructions the AI gets with every question. The AI must answer with ONE JSON
# object. The verdict is shown by the page as a badge, so the AI is told not to repeat it
# in the text. Every item starts with an emoji.
DEFAULT_SYSTEM_PROMPT = (
    "You are Scam Slayer, the UPI Safety Coach for students and families in India. "
    "The user describes a payment situation in everyday words. Decide whether it is a scam. "
    "Reply with ONE JSON object and nothing else (no markdown, no text before or after it), "
    "using exactly these keys:\n"
    '{"verdict": "...", "reason": "...", "red_flags": ["..."], "steps": ["..."], "source": "..."}\n'
    "verdict must be exactly one of: SCAM, SUSPICIOUS, LIKELY SAFE, NOT SURE, INFO. "
    "The app shows the verdict as a badge at the top of the answer, so NEVER repeat the verdict "
    "inside reason, red_flags or steps (do not write 'This is a scam', 'It is safe' and so on). "
    "Explain WHY instead. "
    "reason: one short sentence in simple English. "
    "red_flags: up to four short red flags, or an empty list when there are none. "
    "steps: three or four short action steps. "
    "source: the real organisation(s) your advice is based on, chosen ONLY from: RBI (rbi.org.in), "
    "NPCI (npci.org.in), National Cyber Crime Reporting Portal / I4C and the 1930 helpline "
    "(cybercrime.gov.in, Ministry of Home Affairs), SEBI (sebi.gov.in), TRAI, Sanchar Saathi "
    "(sancharsaathi.gov.in), CERT-In. Write it as a short phrase, for example: "
    "RBI awareness material (rbi.org.in) \u00b7 NPCI UPI safety tips (npci.org.in). "
    "Never invent documents, links, dates or statistics. Put the source ONLY in the source key, "
    "never inside reason, red_flags or steps, and use no emoji in it. "
    "Start reason and EVERY red flag and EVERY step with one fitting emoji, for example: "
    "\U0001F6A9 \u26A0\uFE0F \U0001F512 \U0001F4DE \U0001F3E6 \U0001F6AB \u2705 \U0001F4B8 \U0001F517. "
    "Do not use markdown or bullet characters. "
    "Rules: Use SCAM only when the situation clearly matches a known fraud pattern. Use "
    "SUSPICIOUS when some red flags are present. Use LIKELY SAFE only for ordinary payments "
    "the user started themselves, and still tell them to verify in their bank app. Use NOT "
    "SURE when details are missing and say what to check. Use INFO for general questions "
    "(answer in reason and give tips in steps). "
    "Never ask for or accept a UPI PIN, OTP, password, CVV, card number, account number or "
    "phone number. "
    "Facts you can rely on: the UPI PIN is only for sending money, never for receiving money; "
    "scanning a QR code or approving a collect request sends money out; banks and government "
    "agencies never ask for your OTP or PIN; police, CBI, ED and courts do not arrest anyone "
    "over a video call; genuine jobs do not charge you a fee to start; never install "
    "screen-sharing apps such as AnyDesk or TeamViewer because a caller asks. "
    "If the person may already have lost money or shared a PIN or OTP, the first step must "
    "be to call the national cyber fraud helpline 1930 and report at cybercrime.gov.in, then "
    "inform the bank. Do not invent statistics, laws or phone numbers other than 1930. Keep "
    "every step under 20 words."
    "If the user has asked a question rather than UPI Safety, please do not add anything "
    "extra in that answer, answer this question and don't tell him much about UPI Safety, also remind him to ask questions about UPI Safety"
)

GROQ_API_URL = os.getenv("GROQ_API_URL", DEFAULT_GROQ_URL).strip() or DEFAULT_GROQ_URL
GROQ_MODEL = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL).strip() or DEFAULT_GROQ_MODEL
GROQ_TEMPERATURE = env_float("GROQ_TEMPERATURE", 0.5)
GROQ_MAX_TOKENS = env_int("GROQ_MAX_TOKENS", 2048)
# Ask Groq to return valid JSON only. If Groq rejects this, the server retries without it.
GROQ_JSON_MODE = env_flag("GROQ_JSON_MODE", default=True)
# Instructions sent to the AI with every question. Set SYSTEM_PROMPT= (empty) to disable.
# NOTE: if your a.env still has an old SYSTEM_PROMPT line, delete it so the new default is used.
SYSTEM_PROMPT = os.getenv("SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT).strip()

# ---- Supabase settings (only used when CHAT_PROVIDER=supabase) ----
DEFAULT_API_URL = "https://wktymtbkizyeylzjnegq.supabase.co/functions/v1/chat"

CHAT_API_URL = os.getenv("CHAT_API_URL", DEFAULT_API_URL).strip() or DEFAULT_API_URL
CHAT_API_KEY = os.getenv("CHAT_API_KEY", "").strip()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
CHAT_AUTH_MODE = os.getenv("CHAT_AUTH_MODE", "x-api-key").strip().lower()
PORT = env_int("PORT", 5001)
# 127.0.0.1 = only this Mac.  0.0.0.0 = other devices on the same network too.
HOST = os.getenv("HOST", "127.0.0.1").strip() or "127.0.0.1"
# Optional shared password that people on the network must enter to chat.
ACCESS_CODE = os.getenv("ACCESS_CODE", "").strip()
# Every situation is judged on its own by default. Set SEND_HISTORY=true to let the AI see earlier messages.
SEND_HISTORY = env_flag("SEND_HISTORY", default=False)
DEBUG_RESPONSES = env_flag("DEBUG_RESPONSES")

# ---- Test data, team dashboard and fair use (for the 10-day test and a public link) ----
DATA_DIR = Path(os.getenv("DATA_DIR", "").strip() or (BASE_DIR / "data"))
ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()                 # protects /api/stats and /api/export.csv
TRUST_PROXY = env_flag("TRUST_PROXY")                          # true on Render/Railway etc. (real visitor IP)
ASK_PER_MINUTE = env_int("ASK_PER_MINUTE", 15)                 # AI questions per visitor per minute
ASK_PER_DAY = env_int("ASK_PER_DAY", 300)                      # AI questions per visitor per day
QUIZ_SIZE = 10                                                  # questions in the before/after quiz

# The URL and key that are actually used for the chosen provider.
if USING_GROQ:
    API_URL = GROQ_API_URL
    # Convenience: a Groq key (starts with gsk_) put in CHAT_API_KEY also works.
    API_KEY = GROQ_API_KEY or (CHAT_API_KEY if CHAT_API_KEY.startswith("gsk_") else "")
    KEY_NAME = "GROQ_API_KEY"
else:
    API_URL = CHAT_API_URL
    API_KEY = CHAT_API_KEY
    KEY_NAME = "CHAT_API_KEY"

VALID_AUTH_MODES = ("x-api-key", "bearer", "both", "supabase")
PLACEHOLDER_KEYS = ("", "your_api_key_here", "your-api-key-here", "your_groq_api_key_here")

MAX_QUESTION_CHARS = 4000
MAX_HISTORY_MESSAGES = 10
MAX_HISTORY_CHARS = 8000

CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 60

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024                    # refuse huge requests

# Send emojis and other non-English characters as real characters, not \uXXXX codes.
app.config["JSON_AS_ASCII"] = False
if hasattr(app, "json") and hasattr(app.json, "ensure_ascii"):
    app.json.ensure_ascii = False


# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------

def fail(message, status_code, code):
    """Build a clean JSON error response for the browser."""
    return jsonify({"ok": False, "error": message, "code": code}), status_code


def key_is_configured():
    return API_KEY.lower() not in PLACEHOLDER_KEYS


def get_lan_ip():
    """Find this Mac's address on the local network (no data is sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def check_access_code():
    """
    If ACCESS_CODE is set, the page must send the matching code in the
    X-Access-Code header. Returns an error response, or None if allowed.
    """
    if not ACCESS_CODE:
        return None
    supplied = request.headers.get("X-Access-Code", "")
    if not supplied:
        return fail("Please enter the access code.", 401, "access_code_required")
    if not hmac.compare_digest(supplied.encode("utf-8"), ACCESS_CODE.encode("utf-8")):
        return fail("That access code is not correct.", 401, "access_code_wrong")
    return None


def build_upstream_headers():
    """Create the request headers for the AI provider, including the secret key."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if USING_GROQ:
        # Groq wants:  Authorization: Bearer <key>
        headers["Authorization"] = "Bearer " + API_KEY
        return headers
    if CHAT_AUTH_MODE in ("x-api-key", "both"):
        headers["x-api-key"] = API_KEY
    if CHAT_AUTH_MODE in ("bearer", "both", "supabase"):
        headers["Authorization"] = "Bearer " + API_KEY
    if CHAT_AUTH_MODE == "supabase":
        headers["apikey"] = API_KEY
    return headers


def build_payload(messages, json_mode=False):
    """Create the JSON body for the AI provider."""
    if USING_GROQ:
        payload = {
            "model": GROQ_MODEL,
            "messages": messages,
            "temperature": GROQ_TEMPERATURE,
            "max_completion_tokens": GROQ_MAX_TOKENS,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload
    return {"messages": messages}   # the Supabase function only needs the messages


def call_ai(messages, json_mode):
    """Send one request to the AI provider and return the raw HTTP response."""
    return requests.post(
        API_URL,
        headers=build_upstream_headers(),
        json=build_payload(messages, json_mode),
        timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
    )


def clean_history(raw_history):
    """Keep only valid earlier messages sent by the page (last few only)."""
    cleaned = []
    if not isinstance(raw_history, list):
        return cleaned
    for item in raw_history[-MAX_HISTORY_MESSAGES:]:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = item.get("content")
        if role in ("user", "assistant") and isinstance(content, str) and content.strip():
            cleaned.append({"role": role, "content": content.strip()[:MAX_HISTORY_CHARS]})
    return cleaned


def describe_structure(value, depth=0):
    """
    Describe the SHAPE of data (key names and value types) without including
    any actual text. Safe to print in the terminal for debugging.
    """
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {key: describe_structure(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [describe_structure(value[0], depth + 1)] if value else []
    return type(value).__name__


# Matches a surrogate pair written as text, e.g. \ud83d\ude00 (one emoji)
PAIR_ESCAPE_RE = re.compile(r"\\u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})")
# Matches a single \uXXXX written as text
SINGLE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def repair_text(text):
    """
    Make sure emojis and special characters appear correctly. Fixes two things
    that can happen to text on its way here:
      1. Text such as "\\ud83d\\ude00" that arrived as literal escape codes
         instead of the real emoji.
      2. "Garbled" text such as "ð\x9f\x98\x80" (UTF-8 wrongly read as Latin-1).
    Normal text is returned unchanged.
    """
    # 1) literal \uXXXX escape codes -> real characters
    def pair(match):
        high = int(match.group(1), 16)
        low = int(match.group(2), 16)
        return chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))

    def single(match):
        code = int(match.group(1), 16)
        return match.group(0) if 0xD800 <= code <= 0xDFFF else chr(code)

    if "\\u" in text:
        text = PAIR_ESCAPE_RE.sub(pair, text)
        text = SINGLE_ESCAPE_RE.sub(single, text)

    # 2) garbled text (UTF-8 bytes read as Latin-1) -> real characters
    if any(ch in text for ch in "ðâÃÂ"):
        try:
            fixed = text.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            fixed = None
        if fixed:
            text = fixed

    return text


def unwrap_data(payload):
    """If the real completion is wrapped inside a "data" key, unwrap it."""
    if isinstance(payload, dict) and "choices" not in payload and isinstance(payload.get("data"), dict):
        return payload["data"]
    return payload


def get_message_content(payload):
    """Return choices[0].message.content if it exists as text, else None."""
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


def parse_streaming_text(raw_text):
    """
    Parse an OpenAI-style streaming body (Server-Sent Events). Each line looks
    like:  data: {"choices":[{"delta":{"content":"Hel"}}]}
    and the stream ends with:  data: [DONE]
    Returns all the pieces joined together.
    """
    pieces = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        chunk_text = line[5:].strip()
        if not chunk_text or chunk_text == "[DONE]":
            continue
        try:
            chunk = unwrap_data(json.loads(chunk_text))
        except ValueError:
            continue
        if not isinstance(chunk, dict):
            continue
        choices = chunk.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            continue
        first_choice = choices[0]
        delta = first_choice.get("delta")
        text = delta.get("content") if isinstance(delta, dict) else None
        if text is None:
            message = first_choice.get("message")
            text = message.get("content") if isinstance(message, dict) else None
        if isinstance(text, str):
            pieces.append(text)
    return "".join(pieces)


def extract_answer(upstream):
    """
    Turn the provider's HTTP response into (answer_text, problem_message).
    Exactly one of the two is None. The answer text is still the AI's raw reply;
    build_result() below turns it into the final card.
    """
    content_type = upstream.headers.get("Content-Type", "").lower()
    # Always read the body as UTF-8. (requests can wrongly guess Latin-1 for some
    # content types, which turns emojis into garbage characters.)
    raw_text = (upstream.content or b"").decode("utf-8-sig", errors="replace")

    if DEBUG_RESPONSES:
        app.logger.info(
            "DEBUG upstream status=%s content-type=%s length=%s",
            upstream.status_code, content_type or "(none)", len(raw_text),
        )

    # Case 1: streaming response (Server-Sent Events)
    if "text/event-stream" in content_type or raw_text.lstrip().startswith("data:"):
        answer = repair_text(parse_streaming_text(raw_text)).strip()
        if answer:
            return answer, None
        app.logger.warning("Streaming response received but no text could be extracted.")
        return None, (
            "The AI service sent a streaming response in a format this app "
            "cannot read. Streaming is only partly supported."
        )

    # Case 2: normal JSON response
    try:
        payload = json.loads(raw_text)
    except ValueError:
        app.logger.warning("Upstream response was not valid JSON (length=%s).", len(raw_text))
        return None, "The AI service returned data that is not valid JSON."

    payload = unwrap_data(payload)

    if DEBUG_RESPONSES:
        app.logger.info("DEBUG response structure: %s", json.dumps(describe_structure(payload)))

    if isinstance(payload, dict) and payload.get("error"):
        app.logger.warning("Upstream JSON contained an error field.")
        return None, "The AI service reported an error while generating the answer."

    answer = get_message_content(payload)
    if answer is None:
        app.logger.warning(
            "Could not find choices[0].message.content. Structure: %s",
            json.dumps(describe_structure(payload)),
        )
        return None, (
            "The AI service replied in an unexpected format, so no answer "
            "could be found. Set DEBUG_RESPONSES=true in a.env and check the "
            "terminal for details."
        )

    answer = repair_text(answer).strip()
    if not answer:
        return None, "The AI service returned an empty answer. Please try again."
    return answer, None


def upstream_error_detail(upstream):
    """Pull the short error message out of a Groq-style error body (safe to show)."""
    try:
        data = json.loads((upstream.content or b"").decode("utf-8-sig", errors="replace"))
        error = data.get("error") if isinstance(data, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        if isinstance(message, str) and message.strip():
            return message.strip()[:250]
    except ValueError:
        pass
    return ""


def friendly_http_error(status_code, detail=""):
    """Map an HTTP error from the AI provider to (message, status for the browser)."""
    extra = (" Details: " + detail) if detail else ""
    if status_code in (401, 403):
        if USING_GROQ:
            return (
                "Groq rejected the API key (HTTP %d). Check that GROQ_API_KEY in "
                "your a.env file is a valid key (it starts with gsk_), then "
                "restart the server." % status_code,
                502,
            )
        return (
            "The AI service rejected the API credentials (HTTP %d). Check "
            "CHAT_API_KEY and CHAT_AUTH_MODE in your a.env file, then restart "
            "the server." % status_code,
            502,
        )
    if status_code == 404:
        if USING_GROQ:
            return (
                "Groq could not find the model or endpoint (HTTP 404). Check "
                "GROQ_MODEL in your a.env file." + extra,
                502,
            )
        return (
            "The AI service endpoint or model was not found (HTTP 404). Check "
            "CHAT_API_URL in your a.env file.",
            502,
        )
    if status_code == 413:
        return "That conversation is too large for the AI. Start a New chat and try again." + extra, 502
    if status_code == 429:
        return "Too many requests (HTTP 429). Please wait a moment and try again.", 429
    if status_code in (500, 502, 503, 504):
        return (
            "The AI service is having problems or is temporarily unavailable "
            "(HTTP %d). Please try again shortly." % status_code,
            502,
        )
    if status_code == 400:
        return "The AI service did not accept the request (HTTP 400)." + extra, 502
    return "The AI service returned an unexpected error (HTTP %d)." % status_code, 502


# ---------------------------------------------------------------------------
# Turning the AI's reply into the same card the built-in answers use
#
#   AI reply (JSON)  ->  verdict badge (top left)  +  reason  +  red flags  +  steps
#
# The verdict is pulled OUT of the text and returned on its own. The body never
# repeats it. Every reason, red flag and step starts with an emoji.
# ---------------------------------------------------------------------------

VERDICTS = ("SCAM", "SUSPICIOUS", "LIKELY SAFE", "NOT SURE", "INFO")
BADGES = {
    "SCAM": "\U0001F6AB SCAM",
    "SUSPICIOUS": "\u26A0\uFE0F SUSPICIOUS",
    "LIKELY SAFE": "\u2705 LIKELY SAFE",
    "NOT SURE": "\u2753 NOT SURE",
    "INFO": "\u2139\uFE0F INFO",
}
VERDICT_ALIASES = {
    "SAFE": "LIKELY SAFE", "OK": "LIKELY SAFE", "LEGIT": "LIKELY SAFE", "LEGITIMATE": "LIKELY SAFE",
    "FRAUD": "SCAM", "PHISHING": "SCAM", "UNSAFE": "SCAM", "DANGEROUS": "SCAM",
    "RISKY": "SUSPICIOUS", "WARNING": "SUSPICIOUS", "CAUTION": "SUSPICIOUS", "DOUBTFUL": "SUSPICIOUS",
    "UNSURE": "NOT SURE", "UNKNOWN": "NOT SURE", "UNCLEAR": "NOT SURE", "MAYBE": "NOT SURE",
    "INFORMATION": "INFO", "GENERAL": "INFO", "TIP": "INFO", "TIPS": "INFO",
}
VERDICT_EMOJI = {"SCAM": "\U0001F6AB", "SUSPICIOUS": "\u26A0\uFE0F", "LIKELY SAFE": "\u2705",
                 "NOT SURE": "\U0001F914", "INFO": "\U0001F4A1"}
DEFAULT_REASONS = {
    "SCAM": "This matches a known UPI scam pattern.",
    "SUSPICIOUS": "Some parts of this look risky, so be careful.",
    "LIKELY SAFE": "This looks like an ordinary payment, but still check in your bank app.",
    "NOT SURE": "There are not enough details to be certain, so check before you pay.",
    "INFO": "Here is some general safety advice.",
}
DEFAULT_STEPS = [
    "\U0001F50E Check with your bank using the number on your card or in its official app.",
    "\U0001F512 Never share your OTP or PIN with anyone.",
    "\U0001F4DE If money is lost, call 1930 straight away.",
]
DEFAULT_SOURCE = "RBI awareness material (rbi.org.in) \u00b7 NPCI UPI safety tips (npci.org.in)"
MAX_SOURCE_CHARS = 200
# A source is only accepted if it names a real Indian body from this list (stops made-up citations).
SOURCE_OK_RE = re.compile(
    r"\b(?:rbi|npci|i4c|mha|sebi|trai|cert-in|1930)\b|reserve bank|cyber ?crime|cyber police|"
    r"ministry of home affairs|sanchar ?saathi|cyber dost", re.I)
# "Source: ..." written inside the body text (the source belongs in its own place)
SOURCE_TAIL_RE = re.compile(r"\s*[\(\[]?\s*\bsources?\s*:.*$", re.I)
HELPLINE_STEP = "\U0001F4DE Call 1930 now and report at cybercrime.gov.in, then tell your bank."

MAX_FLAGS = 4
MAX_STEPS = 5
MAX_ITEM_CHARS = 220

# One emoji (plus optional variation selector / joiner) at the start of a text.
EMOJI_CHARS = "\U0001F000-\U0001FAFF\u2600-\u27BF\u2B05-\u2B07\u2B50\u2B55\u231A\u231B\u23E9-\u23FF\u2934\u2935"
EMOJI_PREFIX_RE = re.compile("^((?:[" + EMOJI_CHARS + "][\uFE0F\u200D]*\\s*)+)(.*)$", re.S)

# Words that show the person may already have lost money or shared a secret.
LOST_RE = re.compile(
    r"\b(?:lost|deducted|debited|cheated|defrauded|got scammed|been scammed|"
    r"already (?:paid|sent|shared|gave|given|transferred|clicked|installed)|"
    r"i (?:paid|sent|shared|gave|transferred|clicked|installed))\b", re.I)

# Sentences that only state the verdict (the badge already shows it), e.g. "This is a scam."
VERDICT_LEAD_RES = [
    re.compile(r"^\W*verdict\s*[:\-\u2013\u2014]\s*[A-Za-z ]{3,14}[.!]*\s*", re.I),
    re.compile(r"^(?:this|it|that)\s+(?:is|looks|seems|appears)(?:\s+like|\s+to be)?\s+(?:a\s+|an\s+)?"
               r"(?:scam|fraud|safe|likely safe|suspicious|not sure)\s*[.!]+\s*", re.I),
    re.compile(r"^(?:scam|suspicious|likely safe|not sure|safe)\s*[:\-\u2013\u2014]+\s+", re.I),
]

STEP_EMOJI_RULES = [
    (re.compile(r"1930|helpline|cybercrime", re.I), "\U0001F4DE"),
    (re.compile(r"\bbank\b", re.I), "\U0001F3E6"),
    (re.compile(r"\b(?:pin|otp|cvv|password|never share)\b", re.I), "\U0001F512"),
    (re.compile(r"\b(?:link|click|apk|download|install|app)\b", re.I), "\U0001F4F5"),
    (re.compile(r"\b(?:block|report)\b", re.I), "\U0001F6AB"),
    (re.compile(r"\b(?:screenshot|save|keep|record|evidence)\b", re.I), "\U0001F4F8"),
    (re.compile(r"\b(?:ignore|hang up|disconnect|do not reply|don't reply|do not respond|don't respond)\b", re.I), "\u270B"),
    (re.compile(r"\b(?:verify|check|confirm)\b", re.I), "\U0001F50E"),
    (re.compile(r"^(?:do not|don't|never|avoid|stop)\b", re.I), "\U0001F6D1"),
]
FLAG_EMOJI_RULES = [
    (re.compile(r"\b(?:urgent|hurry|immediately|deadline|expire|quickly|within \d+)\b", re.I), "\u23F0"),
    (re.compile(r"\b(?:pin|otp|password|cvv)\b", re.I), "\U0001F511"),
    (re.compile(r"\b(?:link|apk|app|install|qr|scan)\b", re.I), "\U0001F517"),
    (re.compile(r"\b(?:money|pay|fee|refund|cashback|prize|lottery|reward|deposit)\b", re.I), "\U0001F4B8"),
    (re.compile(r"\b(?:call|caller|phone|officer|police|bank|agent)\b", re.I), "\U0001F4DE"),
]


def split_emoji_prefix(text):
    """Return (leading emoji or '', the rest of the text)."""
    match = EMOJI_PREFIX_RE.match(text)
    if match:
        return match.group(1).strip(), match.group(2)
    return "", text


def pick_emoji(text, rules, default):
    for pattern, emoji in rules:
        if pattern.search(text):
            return emoji
    return default


def strip_verdict_words(text):
    """Remove a leading 'This is a scam.' / 'Verdict: SCAM' / 'SCAM - ' (the badge shows it)."""
    original = text
    for _ in range(2):
        changed = False
        for pattern in VERDICT_LEAD_RES:
            new_text = pattern.sub("", text, count=1)
            if new_text != text and new_text.strip():
                text = new_text
                changed = True
        if not changed:
            break
    return text if text.strip() else original


def clean_item(text, fallback_emoji):
    """
    Clean one piece of text: no markdown, no list markers, no verdict sentence,
    no characters that would break the page's separators (; and |), and it always
    starts with an emoji.
    """
    if not isinstance(text, str):
        return ""
    text = repair_text(text)
    text = SOURCE_TAIL_RE.sub("", text)                                    # "(Source: ...)" belongs elsewhere
    text = re.sub(r"[*_`#>]+", "", text)                                   # markdown
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"^\s*(?:[-\u2022*]+|\d{1,2}[.)])\s+", "", text)         # "- ", "1. ", "2) "
    emoji, rest = split_emoji_prefix(text)
    rest = strip_verdict_words(rest.strip())
    rest = rest.replace(";", ",").replace("|", "/").strip()
    if not rest:
        return ""
    if len(rest) > MAX_ITEM_CHARS:
        rest = rest[:MAX_ITEM_CHARS - 1].rstrip() + "\u2026"
    prefix = emoji or fallback_emoji
    return (prefix + " " + rest) if prefix else rest


def as_list(value):
    """Accept a list, or a string separated by ; | or new lines, and return a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    if isinstance(value, str):
        return [part for part in re.split(r"[;|\n]", value) if part.strip()]
    return []


def normalize_verdict(raw):
    """Map whatever the AI wrote to one of the five verdicts the page knows."""
    if not isinstance(raw, str):
        return "NOT SURE"
    letters = re.sub(r"[^A-Z ]", "", raw.upper()).strip()
    letters = re.sub(r"\s+", " ", letters)
    if letters in VERDICTS:
        return letters
    if letters in VERDICT_ALIASES:
        return VERDICT_ALIASES[letters]
    for verdict in VERDICTS:                       # e.g. "SCAM - fake collect request"
        if letters.startswith(verdict):
            return verdict
    first = letters.split(" ")[0] if letters else ""
    return VERDICT_ALIASES.get(first, "NOT SURE")


def clean_source(raw):
    """Tidy the source the AI named. If it is empty or not a real known body, use the default."""
    if not isinstance(raw, str):
        return DEFAULT_SOURCE
    text = repair_text(raw)
    text = re.sub(r"[" + EMOJI_CHARS + r"\uFE0F\u200D]", "", text)         # no emojis in the source
    text = re.sub(r"[*_`#>]+", "", text)
    text = re.sub(r"^\s*sources?\s*:\s*", "", text, flags=re.I)
    text = re.sub(r"\s*[;|\n]+\s*", " \u00b7 ", text)                       # keep our ; and | separators clean
    text = re.sub(r"\s+", " ", text).strip(" \u00b7")
    if not text or not SOURCE_OK_RE.search(text):
        return DEFAULT_SOURCE
    if len(text) > MAX_SOURCE_CHARS:
        text = text[:MAX_SOURCE_CHARS - 1].rstrip() + "\u2026"
    return text


def parse_ai_json(text):
    """Find the JSON object in the AI's reply (even if it came wrapped in ``` fences)."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I).strip()
    candidates = [text]
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        candidates.append(match.group(0))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    return None


LABEL_RE_TEXT = r"(?:VERDICT|REASON|RED FLAGS|WHAT TO DO|SOURCE)"


def parse_labelled(text):
    """Fallback: read the older 'VERDICT: ... REASON: ...' plain-text format."""
    def grab(label):
        match = re.search(
            r"^\s*" + label + r"\s*:\s*([\s\S]*?)(?=^\s*" + LABEL_RE_TEXT + r"\s*:|\Z)",
            text, re.I | re.M)
        return match.group(1).strip() if match else ""

    verdict, reason = grab("VERDICT"), grab("REASON")
    if not verdict or not reason:
        return None
    return {"verdict": verdict, "reason": reason,
            "red_flags": re.sub(r"^(?:none|none found|no red flags).*$", "", grab("RED FLAGS"), flags=re.I),
            "steps": grab("WHAT TO DO"), "source": grab("SOURCE")}


def build_result(answer_text, question):
    """
    Turn the AI's raw reply into the final result:
      {"verdict", "badge", "reason", "red_flags": [...], "steps": [...], "source"}
    """
    data = parse_ai_json(answer_text) or parse_labelled(answer_text)
    if data is None:
        # The AI ignored the format: show its words as a general-information card.
        data = {"verdict": "INFO", "reason": answer_text, "red_flags": [], "steps": [], "source": ""}

    verdict = normalize_verdict(data.get("verdict"))
    reason_raw = data.get("reason") or data.get("explanation") or data.get("why") or ""
    flags_raw = data.get("red_flags") or data.get("flags") or data.get("redFlags") or []
    steps_raw = data.get("steps") or data.get("what_to_do") or data.get("actions") or []

    reason = clean_item(reason_raw if isinstance(reason_raw, str) else "", VERDICT_EMOJI[verdict])
    if not reason:
        reason = VERDICT_EMOJI[verdict] + " " + DEFAULT_REASONS[verdict]
    if len(reason) > 300:                          # a very long reply: keep the first sentences
        reason = reason[:299].rstrip() + "\u2026"

    flags = []
    for item in as_list(flags_raw):
        text = clean_item(item, "")
        if not text:
            continue
        if not EMOJI_PREFIX_RE.match(text):
            text = pick_emoji(text, FLAG_EMOJI_RULES, "\U0001F6A9") + " " + text
        flags.append(text)
    if re.match(r"^(?:none|no red flags)", " ".join(flags).replace("\U0001F6A9", "").strip(), re.I):
        flags = []
    flags = flags[:MAX_FLAGS]

    steps = []
    for item in as_list(steps_raw):
        text = clean_item(item, "")
        if not text:
            continue
        if not EMOJI_PREFIX_RE.match(text):
            text = pick_emoji(text, STEP_EMOJI_RULES, "\U0001F449") + " " + text
        steps.append(text)
    if not steps:
        steps = list(DEFAULT_STEPS)

    # If the person may already have lost money, calling 1930 must come first.
    if verdict in ("SCAM", "SUSPICIOUS", "NOT SURE") and LOST_RE.search(question) and "1930" not in steps[0]:
        steps.insert(0, HELPLINE_STEP)
    steps = steps[:MAX_STEPS]

    source = clean_source(data.get("source") or data.get("sources") or data.get("source_name") or "")

    return {"verdict": verdict, "badge": BADGES[verdict], "reason": reason, "red_flags": flags, "steps": steps,
            "source": source}


def format_for_page(result):
    """
    The plain-text form the web page reads into a card. The VERDICT line becomes the
    badge at the top left; the other lines become the reason, red flags and steps.
    """
    return (
        "VERDICT: " + result["verdict"] + "\n"
        "REASON: " + result["reason"] + "\n"
        "RED FLAGS: " + ("; ".join(result["red_flags"]) if result["red_flags"] else "none found") + "\n"
        "WHAT TO DO: " + " | ".join(result["steps"]) + "\n"
        "SOURCE: " + result["source"]
    )


# ---------------------------------------------------------------------------
# Safety: never accept PINs, OTPs, card/account numbers or phone numbers
# ---------------------------------------------------------------------------

SECRET_WORDS = r"(?:pin|otp|cvv|cvc|password|passcode|passwd|(?:verification|security|login)\s+code)"
SECRET_NEAR_NUMBER_RE = re.compile(r"\b" + SECRET_WORDS + r"\b[^\d\n]{0,20}\d{3,8}\b", re.I)       # "my pin is 1234", "OTP: 4829"
NUMBER_THEN_SECRET_RE = re.compile(r"\b\d{3,8}\b[^\d\n]{0,12}(?:is|as)?\s*(?:my\s+|the\s+)?(?:upi\s*)?(?:pin|otp|cvv|password)\b", re.I)
SECRET_VALUE_RE = re.compile(r"\b(?:pin|otp|password|passcode|cvv)\s*(?:is|=|:)\s*(?=\S*\d)\S+", re.I)   # "password is hunter22"
# phone, Aadhaar, card and account numbers: long runs of digits, or digits grouped like 4-4-4 or 5-5
LONG_NUMBER_RE = re.compile(r"(?<!\d)(?:\d{9,19}|\d{4}[\s-]\d{4}[\s-]\d{4}(?:[\s-]\d{1,7})?|\d{5}[\s-]\d{5})(?!\d)")

SENSITIVE_MESSAGE = (
    "For your safety and privacy, please don't type real PINs, OTPs, passwords, card or account "
    "numbers, or phone numbers here. Describe what happened in words instead, for example: "
    "\"a caller asked for my OTP\"."
)


def find_sensitive(text):
    """Return True if the text looks like it contains a PIN, OTP, card/account or phone number."""
    return bool(
        SECRET_NEAR_NUMBER_RE.search(text)
        or NUMBER_THEN_SECRET_RE.search(text)
        or SECRET_VALUE_RE.search(text)
        or LONG_NUMBER_RE.search(text)
    )


# ---------------------------------------------------------------------------
# Fair use: a simple per-visitor limit so a public link cannot use up the AI key
# ---------------------------------------------------------------------------

_hits = collections.defaultdict(collections.deque)
_hits_lock = threading.Lock()


def client_ip():
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limited(bucket, limit, window_seconds):
    """True if this visitor already used `limit` requests of this kind in the time window."""
    now = time.time()
    key = (client_ip(), bucket, window_seconds)
    with _hits_lock:
        hits = _hits[key]
        while hits and hits[0] <= now - window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            return True
        hits.append(now)
        if len(_hits) > 5000:                      # keep memory small
            for old_key in [k for k, v in _hits.items() if not v][:1000]:
                _hits.pop(old_key, None)
    return False


# ---------------------------------------------------------------------------
# Anonymous test data (quiz results and which scenarios were matched)
# ---------------------------------------------------------------------------

_data_lock = threading.Lock()
QUIZ_FILE = DATA_DIR / "quiz.jsonl"
EVENTS_FILE = DATA_DIR / "events.jsonl"
LABEL_RE = re.compile(r"^[A-Za-z0-9 ]{1,20}$")
SCENARIO_ID_RE = re.compile(r"^[a-z0-9_]{1,24}$")
VALID_SOURCES = ("local", "ai", "blocked", "fallback")
VALID_VERDICTS = ("SCAM", "SUSPICIOUS", "LIKELY SAFE", "NOT SURE", "INFO", "ACT NOW")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_jsonl(path, record):
    with _data_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path):
    rows = []
    with _data_lock:
        if not path.exists():
            return rows
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    return rows


def admin_ok():
    """True if the request carries the correct ADMIN_KEY."""
    if not ADMIN_KEY:
        return False
    supplied = request.headers.get("X-Admin-Key", "")
    return hmac.compare_digest(supplied.encode("utf-8"), ADMIN_KEY.encode("utf-8"))


def quiz_latest_by_person():
    """Latest pre-test and post-test for each tester label."""
    latest = {}
    for row in read_jsonl(QUIZ_FILE):
        label = str(row.get("label", "")).strip().lower()
        phase = row.get("phase")
        if label and phase in ("pre", "post") and isinstance(row.get("correct"), list):
            latest[(label, phase)] = row
    return latest


def build_stats():
    latest = quiz_latest_by_person()
    labels = sorted({key[0] for key in latest})
    pre_rows = {l: latest[(l, "pre")] for l in labels if (l, "pre") in latest}
    post_rows = {l: latest[(l, "post")] for l in labels if (l, "post") in latest}
    paired = [l for l in labels if l in pre_rows and l in post_rows]

    def score(row):
        return sum(1 for c in row["correct"] if c)

    improved = same = lower = learned_new = 0
    for l in paired:
        pre_c, post_c = pre_rows[l]["correct"], post_rows[l]["correct"]
        a, b = score(pre_rows[l]), score(post_rows[l])
        improved += b > a
        same += b == a
        lower += b < a
        if any((not pre_c[i]) and post_c[i] for i in range(min(len(pre_c), len(post_c)))):
            learned_new += 1

    def average(values):
        return round(sum(values) / len(values), 2) if values else None

    def per_question(rows):
        out = []
        for i in range(QUIZ_SIZE):
            have = [r["correct"][i] for r in rows.values() if len(r["correct"]) > i]
            out.append(round(100 * sum(1 for h in have if h) / len(have)) if have else None)
        return out

    quiz_times = [r.get("ts") for r in read_jsonl(QUIZ_FILE) if r.get("ts")]
    events = read_jsonl(EVENTS_FILE)
    event_times = [e.get("ts") for e in events if e.get("ts")]
    all_times = sorted(quiz_times + event_times)
    days = None
    if all_times:
        try:
            first = datetime.strptime(all_times[0], "%Y-%m-%dT%H:%M:%SZ")
            last = datetime.strptime(all_times[-1], "%Y-%m-%dT%H:%M:%SZ")
            days = (last.date() - first.date()).days + 1
        except ValueError:
            days = None

    by_source = collections.Counter(e.get("source") for e in events)
    by_verdict = collections.Counter(e.get("verdict") for e in events)
    by_scenario = collections.Counter(e.get("scenario") for e in events if e.get("scenario") not in (None, "none"))
    by_day = collections.Counter((e.get("ts") or "")[:10] for e in events if e.get("ts"))

    return {
        "ok": True,
        "quiz": {
            "people": len(labels),
            "people_with_pre": len(pre_rows),
            "people_with_post": len(post_rows),
            "paired": len(paired),
            "avg_pre": average([score(r) for l, r in pre_rows.items() if l in paired]),
            "avg_post": average([score(r) for l, r in post_rows.items() if l in paired]),
            "improved": improved, "same": same, "lower": lower,
            "learned_something_new": learned_new,
            "percent_learned_new": round(100 * learned_new / len(paired)) if paired else None,
            "per_question_pre": per_question({l: pre_rows[l] for l in paired}),
            "per_question_post": per_question({l: post_rows[l] for l in paired}),
            "size": QUIZ_SIZE,
        },
        "chat": {
            "total": len(events),
            "by_source": dict(by_source),
            "by_verdict": dict(by_verdict),
            "top_scenarios": by_scenario.most_common(15),
            "by_day": sorted(by_day.items()),
        },
        "days_of_testing": days,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    """Serve the chat page. Only index.html is served, never other files."""
    return send_file(BASE_DIR / "index.html")


@app.route("/health")
def health():
    """Tells you whether the server is up and the key is set (never the key)."""
    return jsonify({
        "ok": True,
        "provider": CHAT_PROVIDER,
        "model": GROQ_MODEL if USING_GROQ else None,
        "api_key_configured": key_is_configured(),
        "access_code_required": bool(ACCESS_CODE),
        "stats_enabled": bool(ADMIN_KEY),
    })


@app.route("/ask", methods=["POST"])
def ask():
    # 0. Check the access code (only when ACCESS_CODE is set in a.env)
    denied = check_access_code()
    if denied:
        return denied

    # 0b. Fair use: limit how often one visitor can ask the AI
    if rate_limited("ask", ASK_PER_MINUTE, 60) or rate_limited("ask_day", ASK_PER_DAY, 86400):
        return fail("You are asking very quickly. Please wait a minute and try again.", 429, "rate_limited")

    # 1. Check the server is configured
    if CHAT_PROVIDER not in VALID_PROVIDERS:
        return fail(
            "CHAT_PROVIDER in a.env must be one of: " + ", ".join(VALID_PROVIDERS) + ".",
            500,
            "bad_config",
        )
    if not key_is_configured():
        return fail(
            "The server has no API key yet. Put your key in the a.env file as "
            "%s and restart the server." % KEY_NAME,
            500,
            "missing_key",
        )
    if not USING_GROQ and CHAT_AUTH_MODE not in VALID_AUTH_MODES:
        return fail(
            "CHAT_AUTH_MODE in a.env must be one of: " + ", ".join(VALID_AUTH_MODES) + ".",
            500,
            "bad_config",
        )

    # 2. Validate the browser's request
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("The request was not valid JSON.", 400, "bad_request")

    question = body.get("question")
    if not isinstance(question, str) or not question.strip():
        return fail("Please type a question first.", 400, "empty_question")
    question = question.strip()
    if len(question) > MAX_QUESTION_CHARS:
        return fail(
            "That question is too long (maximum %d characters)." % MAX_QUESTION_CHARS,
            400,
            "too_long",
        )

    # 2b. Safety: never forward PINs, OTPs, card/account numbers or phone numbers
    if find_sensitive(question):
        return fail(SENSITIVE_MESSAGE, 422, "sensitive")

    # 3. Build the message list for the AI provider
    messages = []
    if USING_GROQ and SYSTEM_PROMPT:
        messages.append({"role": "system", "content": SYSTEM_PROMPT})
    if SEND_HISTORY:
        messages.extend(clean_history(body.get("history")))
    messages.append({"role": "user", "content": question})

    # 4. Call the AI provider (asking Groq for JSON; retry once without it if Groq refuses)
    use_json = USING_GROQ and GROQ_JSON_MODE
    try:
        upstream = call_ai(messages, use_json)
        if use_json and upstream.status_code == 400:
            app.logger.warning("Groq did not accept JSON mode; retrying without it.")
            upstream = call_ai(messages, False)
    except requests.exceptions.Timeout:
        return fail(
            "The AI service took too long to respond. Please try again.",
            504,
            "timeout",
        )
    except requests.exceptions.ConnectionError:
        return fail(
            "Could not connect to the AI service. Check your internet connection.",
            502,
            "network",
        )
    except requests.exceptions.RequestException:
        return fail("Something went wrong while contacting the AI service.", 502, "network")

    # 5. Handle HTTP errors
    if not upstream.ok:
        app.logger.warning(
            "Upstream HTTP %s. Body starts with: %r",
            upstream.status_code, (upstream.text or "")[:300],
        )
        message, status = friendly_http_error(upstream.status_code, upstream_error_detail(upstream))
        return fail(message, status, "upstream_%d" % upstream.status_code)

    # 6. Read the AI's reply
    answer, problem = extract_answer(upstream)
    if problem:
        return fail(problem, 502, "bad_response")

    # 7. Build the final card: verdict badge + reason + red flags + steps, all with emojis
    result = build_result(answer, question)
    if DEBUG_RESPONSES:
        app.logger.info("DEBUG final verdict=%s flags=%d steps=%d",
                        result["verdict"], len(result["red_flags"]), len(result["steps"]))

    return jsonify({
        "ok": True,
        "answer": format_for_page(result),     # what the page reads into the card
        "verdict": result["verdict"],          # shown as the badge at the top left
        "badge": result["badge"],
        "source": result["source"],            # shown on the "Source:" line, not inside the answer
        "result": result,                      # the same data, already split into parts
    })


@app.route("/api/event", methods=["POST"])
def api_event():
    """Counts which scenario the bot matched. Stores NO chat text and no personal data."""
    if rate_limited("event", 120, 60):
        return fail("Too many requests.", 429, "rate_limited")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("Bad request.", 400, "bad_request")
    source, verdict, scenario = body.get("source"), body.get("verdict"), body.get("scenario", "none")
    if source not in VALID_SOURCES or verdict not in VALID_VERDICTS:
        return fail("Bad request.", 400, "bad_request")
    if scenario != "none" and not (isinstance(scenario, str) and SCENARIO_ID_RE.match(scenario)):
        return fail("Bad request.", 400, "bad_request")
    append_jsonl(EVENTS_FILE, {"ts": now_iso(), "source": source, "verdict": verdict, "scenario": scenario})
    return jsonify({"ok": True})


@app.route("/api/quiz", methods=["POST"])
def api_quiz():
    """Saves one quiz result: a first name or 'User 3', before/after, and right/wrong per question."""
    if rate_limited("quiz", 30, 60):
        return fail("Too many requests.", 429, "rate_limited")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("Bad request.", 400, "bad_request")
    label, phase, correct = body.get("label"), body.get("phase"), body.get("correct")
    if not (isinstance(label, str) and LABEL_RE.match(label.strip())):
        return fail("Use a first name or 'User 1' (letters and numbers only, no phone numbers).", 400, "bad_label")
    if re.search(r"\d{5,}", label):
        return fail("Please don't use numbers like a phone number. Use a first name or 'User 1'.", 400, "bad_label")
    if phase not in ("pre", "post"):
        return fail("Bad request.", 400, "bad_request")
    if not (isinstance(correct, list) and len(correct) == QUIZ_SIZE and all(isinstance(c, bool) for c in correct)):
        return fail("Bad request.", 400, "bad_request")
    append_jsonl(QUIZ_FILE, {"ts": now_iso(), "label": label.strip(), "phase": phase, "correct": correct})
    return jsonify({"ok": True})


@app.route("/api/stats")
def api_stats():
    """Team-only: summary of the 10-day test (needs the X-Admin-Key header)."""
    if not ADMIN_KEY:
        return fail("Set ADMIN_KEY in the a.env file to turn on the results page.", 403, "admin_disabled")
    if not admin_ok():
        return fail("Wrong admin key.", 401, "admin_wrong")
    return jsonify(build_stats())


@app.route("/api/export.csv")
def api_export():
    """Team-only: every quiz result as a CSV file for Excel / Google Sheets."""
    if not ADMIN_KEY:
        return fail("Set ADMIN_KEY in the a.env file to turn on the results page.", 403, "admin_disabled")
    if not admin_ok():
        return fail("Wrong admin key.", 401, "admin_wrong")
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time_utc", "tester", "phase", "score"] + ["q%d" % (i + 1) for i in range(QUIZ_SIZE)])
    for row in read_jsonl(QUIZ_FILE):
        correct = row.get("correct", [])
        writer.writerow([row.get("ts"), row.get("label"), row.get("phase"), sum(1 for c in correct if c)]
                        + [1 if c else 0 for c in correct])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=quiz_results.csv"})


# ---------------------------------------------------------------------------
# Start the server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if CHAT_PROVIDER not in VALID_PROVIDERS:
        print("\nWARNING: CHAT_PROVIDER must be groq or supabase.\n")
    elif not key_is_configured():
        print("\nWARNING: %s is not set. Put your key in the a.env file.\n" % KEY_NAME)
    elif USING_GROQ and not API_KEY.startswith("gsk_"):
        print("\nWARNING: Groq keys normally start with gsk_. Double-check GROQ_API_KEY.\n")

    if USING_GROQ:
        print("\nAI provider: Groq  |  model: %s" % GROQ_MODEL)
    else:
        print("\nAI provider: Supabase")
    print("Answer format: verdict badge + reason + red flags + steps (emojis) + separate source line")
    print("Safety guard: ON (PIN / OTP / card / phone numbers are refused)")
    print("Team results page: %s" % ("ON (ADMIN_KEY is set)" if ADMIN_KEY else "OFF - set ADMIN_KEY in a.env to turn it on"))
    print("On this Mac, open:  http://127.0.0.1:%d" % PORT)
    if HOST == "0.0.0.0":
        lan_ip = get_lan_ip()
        if lan_ip:
            print("On other devices on the same network, open:  http://%s:%d" % (lan_ip, PORT))
        if ACCESS_CODE:
            print("An access code is required to chat (set by ACCESS_CODE in a.env).")
        else:
            print("WARNING: No ACCESS_CODE is set, so anyone on this network can use your API key through this app.")
    print()
    app.run(host=HOST, port=PORT, debug=False)
