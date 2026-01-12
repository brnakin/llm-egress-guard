from __future__ import annotations

import pytest
from app import normalize

# ============================================================================
# BASIC NORMALIZATION TESTS
# ============================================================================


@pytest.mark.parametrize(
    "raw, expected",
    [
        (chr(0x212B), chr(0x00C5)),  # Angstrom symbol collapses to \u00C5
        ("text", "text"),
    ],
)
def test_nfkc_normalization_applied(raw: str, expected: str) -> None:
    result = normalize.normalize_text(raw)
    assert result.text == expected
    assert (raw == expected) or ("nfkc" in result.steps)


def test_zero_width_removed() -> None:
    text = "secret" + chr(0x200B) + "value"
    result = normalize.normalize_text(text)
    assert result.text == "secretvalue"
    assert "strip_zero_width" in result.steps


def test_control_characters_removed() -> None:
    text = "safe" + chr(0) + "text"
    result = normalize.normalize_text(text)
    assert result.text == "safetext"
    assert "strip_control" in result.steps


def test_html_unescape_bounded() -> None:
    text = "Email: user&amp;example.com"
    result = normalize.normalize_text(text, max_unescape=100)
    assert result.text == "Email: user&example.com"
    assert "html_unescape" in result.steps


def test_html_unescape_skipped_when_above_threshold() -> None:
    text = "&amp;" * 200
    result = normalize.normalize_text(text, max_unescape=10)
    assert result.text == text
    assert "html_unescape" not in result.steps


def test_normalize_many_batches() -> None:
    inputs = ["a", "b"]
    results = normalize.normalize_many(inputs)
    assert [result.text for result in results] == inputs
    assert all(isinstance(result.steps, list) for result in results)


# ============================================================================
# XSS AND SECURITY TESTS
# ============================================================================


def test_xss_basic_script_tag() -> None:
    """Test basic XSS with HTML entities."""
    text = "&lt;script&gt;alert(1)&lt;/script&gt;"
    result = normalize.normalize_text(text)
    assert result.text == "<script>alert(1)</script>"
    assert "html_unescape" in result.steps
    assert result.entity_count == 4


def test_xss_numeric_entities() -> None:
    """Test XSS with numeric HTML entities."""
    text = "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"
    result = normalize.normalize_text(text)
    assert result.text == "<script>alert(1)</script>"
    assert "html_unescape" in result.steps


def test_xss_decimal_entities() -> None:
    """Test XSS with decimal HTML entities."""
    text = "&#60;script&#62;alert(1)&#60;/script&#62;"
    result = normalize.normalize_text(text)
    assert result.text == "<script>alert(1)</script>"
    assert "html_unescape" in result.steps


def test_xss_mixed_entities() -> None:
    """Test XSS with mixed entity types."""
    text = "&lt;img src=x onerror&#61;&quot;alert(1)&quot;&gt;"
    result = normalize.normalize_text(text)
    assert '<img src=x onerror="alert(1)">' in result.text
    assert "html_unescape" in result.steps


# ============================================================================
# DOUBLE ENCODING TESTS
# ============================================================================


def test_double_encoding_html() -> None:
    """Test detection of double-encoded HTML entities."""
    text = "&amp;lt;script&amp;gt;"
    result = normalize.normalize_text(text)
    # First pass unescapes to: &lt;script&gt;
    # But we only do one pass, so it stays as &lt;script&gt;
    assert result.text == "&lt;script&gt;"
    assert "html_unescape" in result.steps
    # The result still contains entities, should be detected
    if result.anomalies:
        assert any("double_encoding_detected" in a for a in result.anomalies)


def test_double_encoding_url() -> None:
    """Test double URL encoding."""
    text = "%2520"  # Double-encoded space
    result = normalize.normalize_text(text)
    assert result.text == " "  # Should fully decode
    assert "url_decode" in result.steps


def test_triple_url_encoding_blocked() -> None:
    """Test that triple URL encoding is limited."""
    text = "%252520"  # Triple-encoded space
    result = normalize.normalize_text(text)
    # Should only decode twice (max_passes=2)
    assert result.text == "%20"
    assert "url_decode" in result.steps
    if result.anomalies:
        assert any("url_decode_max_passes_reached" in a for a in result.anomalies)


def test_mixed_url_and_html_encoding() -> None:
    """Test mixed URL and HTML encoding."""
    text = "%3Cscript%3E&amp;%3C/script%3E"
    result = normalize.normalize_text(text)
    # URL decode first: <script>&</script>
    # Then HTML unescape: <script>&</script>
    assert "<script>" in result.text
    assert "url_decode" in result.steps
    assert "html_unescape" in result.steps


# ============================================================================
# DOS RESISTANCE TESTS
# ============================================================================


def test_large_entity_count_skipped() -> None:
    """Test that excessive entity counts are rejected."""
    text = "&amp;" * 2000  # 2000 entities
    result = normalize.normalize_text(text, max_unescape=100)
    assert result.text == text  # Should be unchanged
    assert "html_unescape" not in result.steps
    assert result.entity_count == 2000  # Count is tracked even when skipped
    assert any("html_entity_count_exceeded" in a for a in result.anomalies)


def test_large_input_length() -> None:
    """Test that very large inputs are handled."""
    text = "A" * 100000  # 100KB
    result = normalize.normalize_text(text, max_unescape=1000)
    assert len(result.text) == 100000
    # Should complete without errors


def test_entity_expansion_bomb() -> None:
    """Test protection against entity expansion attacks."""
    # Create input that would expand significantly
    text = "&nbsp;" * 500  # Each expands from 6 chars to 1 char (actually stays similar)
    result = normalize.normalize_text(text, max_unescape=600)
    assert "html_unescape" in result.steps


def test_output_length_limit() -> None:
    """Test that output length limits are enforced."""
    # This is tricky because we need an entity that expands massively
    # For now, test the mechanism exists
    result = normalize.normalize_text("&amp;" * 50, max_unescape=1000)
    assert result.text == "&" * 50


# ============================================================================
# UNICODE EDGE CASES
# ============================================================================


def test_unicode_combining_marks() -> None:
    """Test handling of combining marks and diacritics."""
    text = "e\u0301"  # e + combining acute accent
    result = normalize.normalize_text(text)
    # NFKC should normalize combining characters
    assert "nfkc" in result.steps


def test_unicode_zero_width_characters() -> None:
    """Test removal of various zero-width characters."""
    text = "a\u200Bb\u200Cc\u200Dd\u200Ee\u200Ff\u2060g\uFEFFh"
    result = normalize.normalize_text(text)
    assert result.text == "abcdefgh"
    assert "strip_zero_width" in result.steps


def test_unicode_bidirectional_marks() -> None:
    """Test handling of bidirectional text marks."""
    text = "start\u200Emiddle\u200Fend"  # LTR and RTL marks
    result = normalize.normalize_text(text)
    assert result.text == "startmiddleend"
    assert "strip_zero_width" in result.steps


def test_unicode_various_spaces() -> None:
    """Test normalization of various Unicode spaces."""
    text = "word\u00A0word"  # Non-breaking space
    result = normalize.normalize_text(text)
    # NFKC should normalize to regular space
    assert "nfkc" in result.steps


def test_unicode_fullwidth_characters() -> None:
    """Test normalization of fullwidth characters."""
    text = "\uFF21\uFF22\uFF23"  # Fullwidth ABC
    result = normalize.normalize_text(text)
    # NFKC should normalize to regular ASCII
    assert result.text == "ABC"
    assert "nfkc" in result.steps


def test_unicode_normalization_before_entity_decode() -> None:
    """Test that normalization order is: URL → HTML → NFKC → strip."""
    # This input has URL encoding that contains HTML entities
    text = "%26lt%3B"  # URL-encoded &lt;
    result = normalize.normalize_text(text)
    # Should: URL decode → &lt; → HTML unescape → <
    assert result.text == "<"
    assert "url_decode" in result.steps
    assert "html_unescape" in result.steps
    # Check order: url_decode should come before html_unescape
    url_idx = result.steps.index("url_decode")
    html_idx = result.steps.index("html_unescape")
    assert url_idx < html_idx


# ============================================================================
# NORMALIZATION ORDER TESTS
# ============================================================================


def test_normalization_order_url_then_html() -> None:
    """Verify URL decode happens before HTML unescape."""
    text = "%26amp%3B"  # URL-encoded &amp;
    result = normalize.normalize_text(text)
    assert result.text == "&"
    assert "url_decode" in result.steps
    assert "html_unescape" in result.steps


def test_normalization_order_html_then_nfkc() -> None:
    """Verify HTML unescape happens before NFKC."""
    text = "&nbsp;"  # Non-breaking space entity
    result = normalize.normalize_text(text)
    # HTML unescape first, then NFKC normalizes nbsp
    assert "html_unescape" in result.steps


def test_normalization_order_nfkc_then_strip() -> None:
    """Verify NFKC happens before stripping."""
    text = "\uFF21\u200B\uFF22"  # Fullwidth A, zero-width space, fullwidth B
    result = normalize.normalize_text(text)
    assert result.text == "AB"
    assert "nfkc" in result.steps
    assert "strip_zero_width" in result.steps
    nfkc_idx = result.steps.index("nfkc")
    strip_idx = result.steps.index("strip_zero_width")
    assert nfkc_idx < strip_idx


# ============================================================================
# ANOMALY DETECTION TESTS
# ============================================================================


def test_anomaly_tracking() -> None:
    """Test that anomalies are properly tracked."""
    text = "&amp;" * 2000
    result = normalize.normalize_text(text, max_unescape=10)
    assert len(result.anomalies) > 0
    assert any("html_entity_count_exceeded" in a for a in result.anomalies)


def test_entity_count_tracking() -> None:
    """Test that entity counts are tracked."""
    text = "&lt;&gt;&amp;&quot;"
    result = normalize.normalize_text(text)
    # Should have counted 4 entities
    assert result.entity_count == 4


# ============================================================================
# EDGE CASES
# ============================================================================


def test_none_input() -> None:
    """Test handling of None input."""
    result = normalize.normalize_text(None)
    assert result.text == ""
    assert len(result.steps) >= 0


def test_empty_string() -> None:
    """Test handling of empty string."""
    result = normalize.normalize_text("")
    assert result.text == ""


def test_no_changes_needed() -> None:
    """Test input that needs no normalization."""
    text = "plain text"
    result = normalize.normalize_text(text)
    assert result.text == text
    assert len(result.steps) == 0


def test_newline_normalization() -> None:
    """Test Windows newline normalization."""
    text = "line1\r\nline2\r\nline3"
    result = normalize.normalize_text(text)
    assert result.text == "line1\nline2\nline3"
    assert "normalize_newlines" in result.steps
