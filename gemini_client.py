"""
Shared Google Gemini API Client for the SOC Agent Copilot features.
Handles authentication, rate limiting, retries, and prompt formatting.

Uses the new `google-genai` SDK (successor to google-generativeai).
"""
import os
import asyncio
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

GEMINI_AVAILABLE = False
try:
    from google import genai
    GEMINI_AVAILABLE = True
except ImportError:
    try:
        import google.generativeai as genai_legacy
        GEMINI_AVAILABLE = True
    except ImportError:
        print("⚠️ google-genai not installed. Copilot features disabled.")

_GEMINI_CLIENT = None
_USE_LEGACY = False


def _get_client():
    """Lazy-initialize the Gemini client."""
    global _GEMINI_CLIENT, _USE_LEGACY

    if _GEMINI_CLIENT is not None:
        return _GEMINI_CLIENT

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key.startswith("your_"):
        print("⚠️ GEMINI_API_KEY not set. Copilot features disabled.")
        return None

    try:
        from google import genai
        _GEMINI_CLIENT = genai.Client(api_key=api_key)
        _USE_LEGACY = False
        print("✅ Gemini API initialized (google-genai SDK, gemini-2.5-flash)")
    except ImportError:
        import google.generativeai as generativeai
        generativeai.configure(api_key=api_key)
        _GEMINI_CLIENT = generativeai.GenerativeModel("gemini-2.5-flash")
        _USE_LEGACY = True
        print("✅ Gemini API initialized (legacy SDK, gemini-2.5-flash)")

    return _GEMINI_CLIENT


async def generate(prompt: str, max_retries: int = 3) -> str:
    """
    Send a prompt to Gemini and return the response text.
    Includes retry logic for transient API errors.
    """
    if not GEMINI_AVAILABLE:
        return "[Copilot unavailable: google-genai not installed]"

    client = _get_client()
    if client is None:
        return "[Copilot unavailable: GEMINI_API_KEY not set]"

    for attempt in range(max_retries):
        try:
            loop = asyncio.get_event_loop()

            if _USE_LEGACY:
                response = await loop.run_in_executor(
                    None, lambda: client.generate_content(prompt)
                )
            else:
                response = await loop.run_in_executor(
                    None, lambda: client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=prompt
                    )
                )

            return response.text

        except Exception as e:
            wait_time = 2 ** attempt
            print(f"Gemini API error (attempt {attempt + 1}): {e}. Retrying in {wait_time}s...")
            await asyncio.sleep(wait_time)

    return f"[Copilot error: Gemini API failed after {max_retries} attempts: {str(e)}]"
