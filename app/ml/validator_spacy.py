"""
spaCy NER Validator for PII Detection

Provides multi-language Named Entity Recognition (NER) validation
to reduce false positives from regex-based PII detection.

Supported Languages:
- English (en): en_core_web_sm
- German (de): de_core_news_sm
- Turkish (tr): Not officially supported by spaCy, uses custom patterns

Usage:
    from app.ml.validator_spacy import SpacyValidator
    
    validator = SpacyValidator(languages=["en", "de"])
    
    # Validate a span
    is_valid = validator.validate_span("John Smith", "PERSON")
    
    # Validate multiple spans
    results = validator.validate_spans([
        {"text": "john@example.com", "type": "EMAIL"},
        {"text": "John Smith", "type": "PERSON"},
    ])
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

import structlog

logger = structlog.get_logger(__name__)

# Type aliases
Language = Literal["en", "de", "tr"]
EntityType = Literal["PERSON", "ORG", "GPE", "EMAIL", "PHONE", "MONEY", "DATE"]

# spaCy model names for each language
SPACY_MODELS: dict[Language, str] = {
    "en": "en_core_web_sm",
    "de": "de_core_news_sm",
    "tr": "xx_ent_wiki_sm",  # Multilingual model as fallback for Turkish
}

# Entity type mappings (spaCy label -> our label)
ENTITY_MAPPINGS: dict[str, EntityType] = {
    "PERSON": "PERSON",
    "PER": "PERSON",  # German model uses PER
    "ORG": "ORG",
    "GPE": "GPE",  # Geopolitical entity
    "LOC": "GPE",
    "MONEY": "MONEY",
    "DATE": "DATE",
}


@dataclass
class ValidationResult:
    """Result of validating a PII span."""
    text: str
    expected_type: str
    is_valid: bool
    confidence: float = 1.0
    detected_type: str | None = None
    language: Language | None = None
    method: str = "spacy"  # spacy | pattern | fallback


@dataclass
class SpacyValidator:
    """
    Multi-language NER validator using spaCy.
    
    Features:
    - Lazy model loading (only loads when needed)
    - Multi-language support (EN, DE, TR)
    - Fallback patterns for unsupported entities
    - Confidence scoring
    
    Attributes:
        languages: List of language codes to support
        enabled: Whether validation is active
        confidence_threshold: Minimum confidence to consider valid
    """
    
    languages: list[Language] = field(default_factory=lambda: ["en"])
    enabled: bool = True
    confidence_threshold: float = 0.5
    
    _nlp_models: dict[Language, Any] = field(default_factory=dict, init=False)
    _loaded: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """Initialize without loading models (lazy loading)."""
        pass
    
    def _load_model(self, lang: Language) -> Any | None:
        """Load a spaCy model for the given language."""
        if lang in self._nlp_models:
            return self._nlp_models[lang]
        
        model_name = SPACY_MODELS.get(lang)
        if not model_name:
            logger.warning("spacy_unsupported_language", language=lang)
            return None
        
        try:
            import spacy
            nlp = spacy.load(model_name)
            self._nlp_models[lang] = nlp
            logger.info("spacy_model_loaded", language=lang, model=model_name)
            return nlp
        except OSError:
            logger.warning(
                "spacy_model_not_found",
                language=lang,
                model=model_name,
                hint=f"Run: python -m spacy download {model_name}",
            )
            return None
        except ImportError:
            logger.warning("spacy_not_installed", hint="Run: pip install spacy")
            return None
    
    def _load_all_models(self) -> None:
        """Load all configured language models."""
        if self._loaded:
            return
        
        for lang in self.languages:
            self._load_model(lang)
        
        self._loaded = True
    
    def _detect_language(self, text: str) -> Language:
        """Simple language detection based on character patterns."""
        # Turkish-specific characters
        turkish_chars = set("çğıöşüÇĞİÖŞÜ")
        # German-specific characters
        german_chars = set("äöüßÄÖÜ")
        
        text_chars = set(text)
        
        if text_chars & turkish_chars:
            return "tr"
        if text_chars & german_chars:
            return "de"
        
        return "en"  # Default to English
    
    def _validate_with_spacy(
        self,
        text: str,
        expected_type: str,
        lang: Language,
    ) -> ValidationResult:
        """Validate a span using spaCy NER."""
        nlp = self._load_model(lang)
        
        if not nlp:
            # Fallback when model not available
            return ValidationResult(
                text=text,
                expected_type=expected_type,
                is_valid=True,  # Accept by default
                confidence=0.5,
                method="fallback",
                language=lang,
            )
        
        # Process text
        doc = nlp(text)
        
        # Check if any entity matches
        for ent in doc.ents:
            mapped_type = ENTITY_MAPPINGS.get(ent.label_)
            if mapped_type and mapped_type == expected_type:
                return ValidationResult(
                    text=text,
                    expected_type=expected_type,
                    is_valid=True,
                    confidence=0.9,
                    detected_type=mapped_type,
                    language=lang,
                    method="spacy",
                )
        
        # No matching entity found
        return ValidationResult(
            text=text,
            expected_type=expected_type,
            is_valid=False,
            confidence=0.7,
            detected_type=doc.ents[0].label_ if doc.ents else None,
            language=lang,
            method="spacy",
        )
    
    def _validate_email_pattern(self, text: str) -> ValidationResult:
        """Validate email using pattern matching (spaCy doesn't detect emails)."""
        import re
        
        # Simple email pattern
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        
        is_valid = bool(re.match(email_pattern, text.strip()))
        
        return ValidationResult(
            text=text,
            expected_type="EMAIL",
            is_valid=is_valid,
            confidence=0.95 if is_valid else 0.3,
            method="pattern",
        )
    
    def _validate_phone_pattern(self, text: str, lang: Language) -> ValidationResult:
        """Validate phone number using language-specific patterns."""
        import re
        
        patterns: dict[Language, list[str]] = {
            "en": [
                r"^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$",  # US
                r"^\+44\s?[0-9]{10,11}$",  # UK
            ],
            "de": [
                r"^\+49\s?[0-9\s]{10,14}$",  # Germany
                r"^0[0-9]{2,4}[-\s]?[0-9]{4,8}$",
            ],
            "tr": [
                r"^\+90\s?[0-9]{10}$",  # Turkey
                r"^0[0-9]{3}[-\s]?[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{2}$",
            ],
        }
        
        lang_patterns = patterns.get(lang, patterns["en"])
        
        for pattern in lang_patterns:
            if re.match(pattern, text.strip()):
                return ValidationResult(
                    text=text,
                    expected_type="PHONE",
                    is_valid=True,
                    confidence=0.9,
                    language=lang,
                    method="pattern",
                )
        
        return ValidationResult(
            text=text,
            expected_type="PHONE",
            is_valid=False,
            confidence=0.6,
            language=lang,
            method="pattern",
        )
    
    def validate_span(
        self,
        text: str,
        expected_type: str,
        lang: Language | None = None,
    ) -> ValidationResult:
        """
        Validate a single PII span.
        
        Args:
            text: The text span to validate
            expected_type: Expected entity type (PERSON, EMAIL, PHONE, etc.)
            lang: Language code (auto-detected if not provided)
        
        Returns:
            ValidationResult with validation details
        """
        if not self.enabled:
            return ValidationResult(
                text=text,
                expected_type=expected_type,
                is_valid=True,
                confidence=1.0,
                method="disabled",
            )
        
        # Detect language if not provided
        if not lang:
            lang = self._detect_language(text)
        
        # Handle special types that spaCy doesn't detect
        if expected_type == "EMAIL":
            return self._validate_email_pattern(text)
        
        if expected_type == "PHONE":
            return self._validate_phone_pattern(text, lang)
        
        # Use spaCy for named entities
        return self._validate_with_spacy(text, expected_type, lang)
    
    def validate_spans(
        self,
        spans: Iterable[dict[str, Any]],
    ) -> list[ValidationResult]:
        """
        Validate multiple PII spans.
        
        Args:
            spans: Iterable of dicts with 'text' and 'type' keys
        
        Returns:
            List of ValidationResults
        """
        results = []
        
        for span in spans:
            text = span.get("text", "")
            expected_type = span.get("type", "UNKNOWN")
            lang = span.get("lang")
            
            result = self.validate_span(text, expected_type, lang)
            results.append(result)
        
        return results
    
    def filter_valid_spans(
        self,
        spans: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Filter spans to only include validated ones.
        
        Args:
            spans: Iterable of span dicts
        
        Returns:
            List of spans that passed validation
        """
        span_list = list(spans)
        results = self.validate_spans(span_list)
        
        return [
            span
            for span, result in zip(span_list, results)
            if result.is_valid and result.confidence >= self.confidence_threshold
        ]


# Global validator instance
_validator: SpacyValidator | None = None


def get_validator(languages: list[Language] | None = None) -> SpacyValidator:
    """Get or create the global validator instance."""
    global _validator
    
    if _validator is None:
        _validator = SpacyValidator(languages=languages or ["en"])
    
    return _validator


def validate_spans(spans: Iterable[str]) -> list[str]:
    """
    Legacy function for backward compatibility.
    
    Returns input spans unchanged (validation is opt-in).
    For full validation, use SpacyValidator directly.
    """
    return list(spans)
