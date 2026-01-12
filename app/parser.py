"""Parser stage — Context-aware Markdown parsing for FP reduction.

This module segments LLM output into text/code/link segments with context
metadata, enabling detectors to apply context-based risk adjustments.

Sprint 3: Implements standard segment types (text, code, link) with
explain-only heuristic detection and ML integration hooks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

# Regex patterns for Markdown parsing
# Fenced code blocks: ```lang\ncode\n``` (with optional language identifier)
FENCED_CODE_BLOCK_REGEX = re.compile(
    r"```(\w*)\n(.*?)```",
    re.DOTALL,
)

# Inline code: `code` (backtick-wrapped, single line)
INLINE_CODE_REGEX = re.compile(r"`([^`\n]+)`")

# Markdown links: [text](url) and raw URLs
MARKDOWN_LINK_REGEX = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
RAW_URL_REGEX = re.compile(
    r"(?<![`\w])https?://[^\s\]\)>\"\'\`]+",
    re.IGNORECASE,
)

# Educational keywords for explain-only detection
EDUCATIONAL_KEYWORDS = frozenset(
    {
        # Explicit warnings
        "example",
        "avoid",
        "never",
        "dangerous",
        "warning",
        "caution",
        # Instructional
        "don't",
        "do not",
        "tutorial",
        "demonstrates",
        "here's how",
        "here is how",
        "shows how",
        "learn",
        "explain",
        "explanation",
        # Negative examples
        "do not run",
        "malicious",
        "unsafe",
        "insecure",
        "vulnerable",
        "attack",
        "exploit",
        # Educational context
        "for educational",
        "for learning",
        "bad practice",
        "anti-pattern",
        "antipattern",
        "what not to do",
    }
)

# Context window for explain-only detection (characters before/after segment)
CONTEXT_WINDOW_SIZE = 200

SegmentType = Literal["text", "code", "link"]


@dataclass(slots=True)
class Segment:
    """A parsed segment of the input text with context metadata."""

    type: SegmentType
    content: str
    start: int
    end: int
    metadata: dict[str, Any] = field(default_factory=dict)
    explain_only: bool = False

    @property
    def language(self) -> str | None:
        """Return the language for code segments, None otherwise."""
        return self.metadata.get("lang")

    @property
    def url(self) -> str | None:
        """Return the URL for link segments, None otherwise."""
        return self.metadata.get("url")

    @property
    def link_text(self) -> str | None:
        """Return the link text for link segments, None otherwise."""
        return self.metadata.get("link_text")


@dataclass(slots=True)
class ParsedContent:
    """Container for parsed content with segments and original text."""

    text: str  # Original full text preserved for detector offset compatibility
    segments: list[Segment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_segment_at_offset(self, offset: int) -> Segment | None:
        """Find the segment containing the given character offset.

        Args:
            offset: Character position in the original text.

        Returns:
            The segment containing this offset, or None if not found.
        """
        for segment in self.segments:
            if segment.start <= offset < segment.end:
                return segment
        return None

    def get_segments_in_range(self, start: int, end: int) -> list[Segment]:
        """Find all segments that overlap with the given range.

        Args:
            start: Start offset (inclusive).
            end: End offset (exclusive).

        Returns:
            List of segments overlapping the range.
        """
        result = []
        for segment in self.segments:
            # Check for overlap: segment.start < end AND segment.end > start
            if segment.start < end and segment.end > start:
                result.append(segment)
        return result

    @property
    def has_code_segments(self) -> bool:
        """Return True if any code segments exist."""
        return any(s.type == "code" for s in self.segments)

    @property
    def has_explain_only_segments(self) -> bool:
        """Return True if any explain-only segments exist."""
        return any(s.explain_only for s in self.segments)


def _has_educational_keywords(text: str) -> bool:
    """Check if text contains educational/warning keywords.

    Args:
        text: Text to check for educational context.

    Returns:
        True if educational keywords are found.
    """
    lowered = text.lower()
    for keyword in EDUCATIONAL_KEYWORDS:
        if keyword in lowered:
            return True
    return False


def _get_surrounding_text(full_text: str, start: int, end: int) -> str:
    """Extract text surrounding a segment for context analysis.

    Args:
        full_text: The complete input text.
        start: Segment start offset.
        end: Segment end offset.

    Returns:
        Text before and after the segment (within CONTEXT_WINDOW_SIZE).
    """
    context_start = max(0, start - CONTEXT_WINDOW_SIZE)
    context_end = min(len(full_text), end + CONTEXT_WINDOW_SIZE)

    before = full_text[context_start:start]
    after = full_text[end:context_end]

    return before + " " + after


def _detect_explain_only(
    segment: Segment,
    full_text: str,
    *,
    ml_preclassifier: Any | None = None,
    shadow_mode: bool = False,
) -> bool:
    """Determine if a segment is educational/explanatory context.

    Uses heuristic keyword detection with optional ML pre-classifier override.

    Args:
        segment: The segment to analyze.
        full_text: Complete input text for context extraction.
        ml_preclassifier: Optional ML model for classification.

    Returns:
        True if segment appears to be educational/explanatory.
    """
    # Only code segments can be explain-only (commands in prose are suspicious)
    if segment.type != "code":
        return False

    # Heuristic: Check surrounding text for educational keywords
    surrounding = _get_surrounding_text(full_text, segment.start, segment.end)
    heuristic_result = _has_educational_keywords(surrounding)

    final_result = heuristic_result
    ml_pred = None

    # ML hook: If pre-classifier is available and enabled, use it
    if ml_preclassifier is not None:
        try:
            ml_pred = ml_preclassifier.predict(segment.content)
            if ml_pred in ("educational", "explain_only", "text"):
                final_result = True
            elif ml_pred in ("command", "executable", "malicious"):
                final_result = False
        except Exception:
            # Fall through to heuristic on ML failure
            ml_pred = None

    # Shadow mode: record disagreements between ML and heuristic
    if (
        shadow_mode
        and ml_pred is not None
        and ml_pred
        not in ("educational", "explain_only", "text", "command", "executable", "malicious")
    ):
        # If ML returns something unexpected, still log it with final decision
        pass
    if shadow_mode and ml_pred is not None:
        try:
            from app import metrics

            metrics.observe_ml_shadow(
                ml_pred=str(ml_pred),
                heuristic="educational" if heuristic_result else "command",
                final="educational" if final_result else "command",
            )
        except Exception:
            # Metrics are best-effort; ignore failures
            pass

    return final_result


def _parse_fenced_code_blocks(text: str) -> list[tuple[int, int, str, str]]:
    """Extract fenced code blocks with positions.

    Returns:
        List of (start, end, language, content) tuples.
    """
    results = []
    for match in FENCED_CODE_BLOCK_REGEX.finditer(text):
        lang = match.group(1) or ""
        content = match.group(2)
        results.append((match.start(), match.end(), lang, content))
    return results


def _parse_inline_code(text: str) -> list[tuple[int, int, str]]:
    """Extract inline code spans with positions.

    Returns:
        List of (start, end, content) tuples.
    """
    results = []
    for match in INLINE_CODE_REGEX.finditer(text):
        results.append((match.start(), match.end(), match.group(1)))
    return results


def _parse_markdown_links(text: str) -> list[tuple[int, int, str, str]]:
    """Extract Markdown links [text](url) with positions.

    Returns:
        List of (start, end, link_text, url) tuples.
    """
    results = []
    for match in MARKDOWN_LINK_REGEX.finditer(text):
        link_text = match.group(1)
        url = match.group(2)
        results.append((match.start(), match.end(), link_text, url))
    return results


def _parse_raw_urls(text: str, exclude_ranges: list[tuple[int, int]]) -> list[tuple[int, int, str]]:
    """Extract raw URLs that aren't inside other parsed elements.

    Args:
        text: Input text to parse.
        exclude_ranges: List of (start, end) ranges to skip (e.g., code blocks).

    Returns:
        List of (start, end, url) tuples.
    """
    results = []
    for match in RAW_URL_REGEX.finditer(text):
        start, end = match.start(), match.end()
        # Skip if this URL is inside an excluded range
        in_excluded = any(ex_start <= start < ex_end for ex_start, ex_end in exclude_ranges)
        if not in_excluded:
            results.append((start, end, match.group(0)))
    return results


def _build_segments(
    text: str,
    fenced_blocks: list[tuple[int, int, str, str]],
    inline_codes: list[tuple[int, int, str]],
    md_links: list[tuple[int, int, str, str]],
    raw_urls: list[tuple[int, int, str]],
) -> list[Segment]:
    """Build segment list from parsed elements, filling gaps with text segments.

    Args:
        text: Original input text.
        fenced_blocks: Parsed fenced code blocks.
        inline_codes: Parsed inline code spans.
        md_links: Parsed Markdown links.
        raw_urls: Parsed raw URLs.

    Returns:
        Sorted list of non-overlapping segments covering the entire text.
    """
    # Collect all special segments with their ranges
    special_segments: list[tuple[int, int, Segment]] = []

    # Fenced code blocks
    for start, end, lang, content in fenced_blocks:
        seg = Segment(
            type="code",
            content=content,
            start=start,
            end=end,
            metadata={"lang": lang, "fenced": True},
        )
        special_segments.append((start, end, seg))

    # Inline code (skip if inside fenced block)
    fenced_ranges = [(s, e) for s, e, _, _ in fenced_blocks]
    for start, end, content in inline_codes:
        in_fenced = any(fs <= start < fe for fs, fe in fenced_ranges)
        if not in_fenced:
            seg = Segment(
                type="code",
                content=content,
                start=start,
                end=end,
                metadata={"fenced": False},
            )
            special_segments.append((start, end, seg))

    # Markdown links (skip if inside code)
    code_ranges = fenced_ranges + [(s, e) for s, e, _ in inline_codes]
    for start, end, link_text, url in md_links:
        in_code = any(cs <= start < ce for cs, ce in code_ranges)
        if not in_code:
            seg = Segment(
                type="link",
                content=text[start:end],  # Full [text](url) string
                start=start,
                end=end,
                metadata={"link_text": link_text, "url": url},
            )
            special_segments.append((start, end, seg))

    # Raw URLs (skip if inside code or already a markdown link)
    link_ranges = [(s, e) for s, e, _, _ in md_links]
    all_special_ranges = code_ranges + link_ranges
    for start, end, url in raw_urls:
        in_special = any(ss <= start < se for ss, se in all_special_ranges)
        if not in_special:
            seg = Segment(
                type="link",
                content=url,
                start=start,
                end=end,
                metadata={"url": url, "raw": True},
            )
            special_segments.append((start, end, seg))

    # Sort by start position
    special_segments.sort(key=lambda x: x[0])

    # Build final segment list, filling gaps with text segments
    segments: list[Segment] = []
    current_pos = 0

    for start, end, segment in special_segments:
        # Skip overlapping segments (shouldn't happen with proper parsing)
        if start < current_pos:
            continue

        # Add text segment for gap before this special segment
        if start > current_pos:
            gap_content = text[current_pos:start]
            if gap_content.strip():  # Only add non-empty text segments
                segments.append(
                    Segment(
                        type="text",
                        content=gap_content,
                        start=current_pos,
                        end=start,
                    )
                )

        segments.append(segment)
        current_pos = end

    # Add final text segment if there's content after last special segment
    if current_pos < len(text):
        final_content = text[current_pos:]
        if final_content.strip():
            segments.append(
                Segment(
                    type="text",
                    content=final_content,
                    start=current_pos,
                    end=len(text),
                )
            )

    return segments


def parse_content(
    text: str,
    *,
    metadata: dict[str, Any] | None = None,
    ml_preclassifier: Any | None = None,
    shadow_mode: bool = False,
    detect_explain_only_enabled: bool = True,
) -> ParsedContent:
    """Parse input text into segments with context metadata.

    This function segments Markdown-formatted LLM output into text, code,
    and link segments. Each segment includes offsets for proper action
    application and optional explain-only classification.

    Args:
        text: Input text to parse (typically normalized LLM output).
        metadata: Optional metadata to attach to the parsed content.
        ml_preclassifier: Optional ML pre-classifier for explain-only detection.
        detect_explain_only_enabled: Whether to run explain-only detection.

    Returns:
        ParsedContent with segments and original text preserved.

    Example:
        >>> content = parse_content("Here's an example:\\n```bash\\ncurl | bash\\n```")
        >>> content.segments[0].type
        'text'
        >>> content.segments[1].type
        'code'
        >>> content.segments[1].explain_only
        True  # Due to "example" keyword in surrounding text
    """
    if not text:
        return ParsedContent(text=text, segments=[], metadata=metadata or {})

    # Parse all special elements
    fenced_blocks = _parse_fenced_code_blocks(text)
    inline_codes = _parse_inline_code(text)

    # Build exclusion ranges for raw URL parsing
    code_ranges = [(s, e) for s, e, _, _ in fenced_blocks]
    code_ranges.extend((s, e) for s, e, _ in inline_codes)

    md_links = _parse_markdown_links(text)
    raw_urls = _parse_raw_urls(text, code_ranges + [(s, e) for s, e, _, _ in md_links])

    # Build segment list
    segments = _build_segments(text, fenced_blocks, inline_codes, md_links, raw_urls)

    # Apply explain-only detection to code segments
    if detect_explain_only_enabled:
        for segment in segments:
            if segment.type == "code":
                segment.explain_only = _detect_explain_only(
                    segment,
                    text,
                    ml_preclassifier=ml_preclassifier,
                    shadow_mode=shadow_mode,
                )

    return ParsedContent(
        text=text,
        segments=segments,
        metadata=metadata or {},
    )


def get_segment_at_offset(offset: int, segments: list[Segment]) -> Segment | None:
    """Utility function to find segment at a given offset.

    Args:
        offset: Character position in the original text.
        segments: List of segments to search.

    Returns:
        The segment containing this offset, or None if not found.
    """
    for segment in segments:
        if segment.start <= offset < segment.end:
            return segment
    return None


def get_context_for_finding(
    finding_start: int,
    finding_end: int,
    parsed: ParsedContent,
) -> tuple[SegmentType, bool]:
    """Get context information for a detector finding.

    Args:
        finding_start: Start offset of the finding.
        finding_end: End offset of the finding.
        parsed: Parsed content with segments.

    Returns:
        Tuple of (segment_type, explain_only) for the finding.
        Defaults to ("text", False) if no segment found.
    """
    # Find the primary segment (at start of finding)
    segment = parsed.get_segment_at_offset(finding_start)
    if segment is None:
        # Try finding any overlapping segment
        overlapping = parsed.get_segments_in_range(finding_start, finding_end)
        if overlapping:
            segment = overlapping[0]

    if segment is None:
        return "text", False

    return segment.type, segment.explain_only
