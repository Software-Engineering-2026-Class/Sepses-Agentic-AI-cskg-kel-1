"""Optional LLM Client for agentic reasoning.

This module provides a thin wrapper around the OpenAI API for reasoning tasks.
If OPENAI_API_KEY is not set, it degrades gracefully and returns None, ensuring
the pipeline remains deterministic and functional without an LLM.
"""

from __future__ import annotations

import os
from loguru import logger

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


class LLMClient:
    """Optional LLM integration for reasoning tasks."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.client = None

        if HAS_OPENAI and self.api_key:
            try:
                self.client = OpenAI(api_key=self.api_key)
                logger.info("[LLMClient] Initialized with model {}", self.model)
            except Exception as e:
                logger.warning("[LLMClient] Failed to initialize OpenAI client: {}", e)
        else:
            logger.info("[LLMClient] OPENAI_API_KEY not set or openai package missing. Operating in deterministic mode.")

    @property
    def is_enabled(self) -> bool:
        return self.client is not None

    def suggest_parser(self, filename: str, sample_content: str) -> str | None:
        """Ask LLM to suggest which parser to use based on content and filename."""
        if not self.is_enabled:
            return None
            
        prompt = f"Given this filename '{filename}' and a sample of its content:\n\n{sample_content[:500]}\n\nWhich cybersecurity data parser should be used? Options: CVE, CWE, CPE, CAPEC, ATTACK, ICSA, UNKNOWN. Reply with just the option name."
        return self._call(prompt)

    def explain_validation_error(self, error_summary: str) -> str | None:
        """Ask LLM to explain a SHACL/validation error in plain English."""
        if not self.is_enabled:
            return None
            
        prompt = f"Explain this RDF SHACL validation error in plain English and suggest a fix:\n{error_summary}"
        return self._call(prompt)

    def _call(self, prompt: str) -> str | None:
        if not self.client:
            return None
            
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error("[LLMClient] API call failed: {}", e)
            return None
