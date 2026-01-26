"""String comparison utilities with whitespace-aware diff output."""

import difflib

# Placeholder used in baseline files for the testdata root path
TESTDATA_ROOT_PLACEHOLDER = '$TESTDATA_ROOT'


def substitute_testdata_root(text: str, testdata_root: str) -> str:
    """
    Substitute the testdata root placeholder with the actual path.

    Baselines store paths as $TESTDATA_ROOT/downloaded/... to be portable
    across different environments. This function substitutes the placeholder
    with the actual testdata path for the current environment.

    Args:
        text: Text containing $TESTDATA_ROOT placeholders
        testdata_root: The actual testdata root path (IMAGO_TESTDATA_PATH)

    Returns:
        Text with placeholders substituted
    """
    return text.replace(TESTDATA_ROOT_PLACEHOLDER, testdata_root)


def compare_outputs(imago_output: str, expected_output: str) -> tuple:
    """
    Compare imago output against expected output (from qemu-img or override).

    Returns:
        tuple: (matched: bool, diff_text: str)
               If matched is True, diff_text is empty.
               If matched is False, diff_text contains a human-readable diff
               with whitespace characters made visible.
    """
    if imago_output == expected_output:
        return True, ''

    # Generate a unified diff with whitespace made visible
    imago_visible = _make_whitespace_visible(imago_output)
    expected_visible = _make_whitespace_visible(expected_output)

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
