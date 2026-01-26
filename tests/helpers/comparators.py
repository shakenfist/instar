"""String comparison utilities with whitespace-aware diff output."""

import difflib
import re


def _normalize_output(text: str) -> str:
    """
    Normalize qemu-img info output to handle environment-specific differences.

    This normalizes:
    - image: paths (vary by machine)
    - disk size values (vary by filesystem sparse allocation)
    - filename: paths in Child node section
    - file length values (vary by filesystem)

    The goal is to make tests pass regardless of the machine they run on,
    while still verifying the overall output structure and format-specific
    values are correct.
    """
    lines = text.split('\n')
    normalized = []

    for line in lines:
        # Normalize "image: /path/to/file" -> "image: <normalized>"
        if line.startswith('image: '):
            line = 'image: <normalized>'
        # Normalize "disk size: XXX" -> "disk size: <normalized>"
        elif line.startswith('disk size: '):
            line = 'disk size: <normalized>'
        # Normalize "    filename: /path/to/file" (in Child node section)
        elif re.match(r'^    filename: ', line):
            line = '    filename: <normalized>'
        # Normalize "    file length: XXX" (in Child node section)
        elif re.match(r'^    file length: ', line):
            line = '    file length: <normalized>'
        # Also normalize "    disk size:" in Child node section
        elif re.match(r'^    disk size: ', line):
            line = '    disk size: <normalized>'

        normalized.append(line)

    return '\n'.join(normalized)


def compare_outputs(imago_output: str, expected_output: str) -> tuple:
    """
    Compare imago output against expected output (from qemu-img or override).

    Returns:
        tuple: (matched: bool, diff_text: str)
               If matched is True, diff_text is empty.
               If matched is False, diff_text contains a human-readable diff
               with whitespace characters made visible.
    """
    # Normalize both outputs to handle environment-specific differences
    normalized_imago = _normalize_output(imago_output)
    normalized_expected = _normalize_output(expected_output)

    if normalized_imago == normalized_expected:
        return True, ''

    # Generate a unified diff with whitespace made visible
    imago_visible = _make_whitespace_visible(normalized_imago)
    expected_visible = _make_whitespace_visible(normalized_expected)

    diff = difflib.unified_diff(
        expected_visible.splitlines(keepends=True),
        imago_visible.splitlines(keepends=True),
        fromfile='expected (qemu-img)',
        tofile='actual (imago)',
        lineterm=''
    )

    diff_text = ''.join(diff)
    return False, diff_text


def _make_whitespace_visible(text: str) -> str:
    """
    Make whitespace characters visible in text for diff output.

    Replaces:
        - trailing spaces with visible markers
        - tabs with visible markers
        - trailing newlines made explicit
    """
    lines = text.split('\n')
    visible_lines = []

    for line in lines:
        # Mark trailing spaces
        stripped = line.rstrip(' ')
        trailing_spaces = len(line) - len(stripped)
        if trailing_spaces > 0:
            line = stripped + '\u2423' * trailing_spaces  # ␣ symbol

        # Mark tabs
        line = line.replace('\t', '\u2192\t')  # → symbol before tab

        visible_lines.append(line)

    result = '\n'.join(visible_lines)

    # Mark trailing newline presence
    if text.endswith('\n'):
        result += '\u21b5'  # ↵ symbol

    return result


def format_failure_message(
    image_id: str,
    imago_output: str,
    expected_output: str,
    diff_text: str
) -> str:
    """
    Format a detailed failure message for test output.

    Args:
        image_id: The test image identifier
        imago_output: Raw imago output
        expected_output: Raw expected output
        diff_text: The diff with visible whitespace

    Returns:
        Formatted failure message string
    """
    msg_parts = [
        f'Output mismatch for {image_id}',
        '',
        'Legend: ␣=trailing space, →=tab, ↵=trailing newline',
        '',
        'Diff (- expected, + actual):',
        diff_text,
    ]

    # Add raw outputs for debugging if they're not too long
    if len(imago_output) < 2000 and len(expected_output) < 2000:
        msg_parts.extend([
            '',
            '--- Raw expected output ---',
            repr(expected_output),
            '',
            '--- Raw actual output ---',
            repr(imago_output),
        ])

    return '\n'.join(msg_parts)
