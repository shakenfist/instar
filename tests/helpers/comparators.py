"""String comparison utilities with whitespace-aware diff output."""

import difflib
import json

# Placeholder used in baseline files for the testdata root path
TESTDATA_ROOT_PLACEHOLDER = '$TESTDATA_ROOT'

# Tolerance for actual-size/disk size field (filesystem block size).
# The "actual-size" (JSON) and "disk size" (human) fields report allocated
# disk space which depends on filesystem block allocation, not image content.
# When sparse files are transferred via git and re-sparsified, the exact
# allocation can differ significantly from the original - the sparsification
# algorithm may detect different zero regions depending on filesystem block
# size, kernel version, and file content layout. See docs/quirks.md
# "File Sparseness and Git" for details.
#
# We use a relative tolerance (50%) rather than absolute bytes because:
# 1. Large sparse files can have allocation differences of many MiB
# 2. The difference is proportional to file size and sparseness
# 3. actual-size reflects filesystem allocation, not image content
ACTUAL_SIZE_TOLERANCE_PERCENT = 0.5  # Allow 50% difference

# Size unit multipliers for parsing human-readable sizes
SIZE_UNITS = {
    'B': 1,
    'KiB': 1024,
    'MiB': 1024 * 1024,
    'GiB': 1024 * 1024 * 1024,
    'TiB': 1024 * 1024 * 1024 * 1024,
}


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


def _parse_human_size(size_str: str) -> int:
    """
    Parse a human-readable size string like '36 KiB' to bytes.

    Args:
        size_str: Size string like '36 KiB', '512 MiB', etc.

    Returns:
        Size in bytes, or -1 if parsing fails.
    """
    parts = size_str.strip().split()
    if len(parts) != 2:
        return -1
    try:
        value = int(parts[0])
        unit = parts[1]
        if unit in SIZE_UNITS:
            return value * SIZE_UNITS[unit]
    except (ValueError, KeyError):
        pass
    return -1


def _compare_human_with_tolerance(
    actual_text: str,
    expected_text: str,
    tolerance_percent: float
) -> tuple:
    """
    Compare human-readable outputs, allowing tolerance for disk size field.

    The "disk size" field depends on filesystem block allocation which
    varies across systems even for identical file content. This function
    compares lines and allows disk size values to differ by up to the
    tolerance percentage.

    Args:
        actual_text: Human-readable text from imago
        expected_text: Human-readable text from baseline
        tolerance_percent: Maximum allowed relative difference (0.5 = 50%)

    Returns:
        tuple: (matched: bool, normalized_actual: str, normalized_expected: str)
               If matched, the normalized strings will be identical.
               If not matched, they show what differed.
    """
    actual_lines = actual_text.splitlines(keepends=True)
    expected_lines = expected_text.splitlines(keepends=True)

    if len(actual_lines) != len(expected_lines):
        return False, actual_text, expected_text

    normalized_actual = []
    normalized_expected = []
    all_match = True

    for actual_line, expected_line in zip(actual_lines, expected_lines):
        # Check if this is a "disk size:" line
        actual_stripped = actual_line.lstrip()
        expected_stripped = expected_line.lstrip()

        if (actual_stripped.startswith('disk size:') and
                expected_stripped.startswith('disk size:')):
            # Extract the size values
            actual_size_str = actual_stripped.replace('disk size:', '').strip()
            expected_size_str = expected_stripped.replace('disk size:', '').strip()

            # Remove trailing newline for parsing
            actual_size_str = actual_size_str.rstrip('\n')
            expected_size_str = expected_size_str.rstrip('\n')

            actual_bytes = _parse_human_size(actual_size_str)
            expected_bytes = _parse_human_size(expected_size_str)

            if actual_bytes >= 0 and expected_bytes >= 0:
                if expected_bytes == 0:
                    within_tolerance = actual_bytes == 0
                else:
                    relative_diff = abs(actual_bytes - expected_bytes) / expected_bytes
                    within_tolerance = relative_diff <= tolerance_percent
                if within_tolerance:
                    # Within tolerance, normalize to expected value
                    normalized_actual.append(expected_line)
                    normalized_expected.append(expected_line)
                    continue

        # Not a disk size line or not within tolerance
        if actual_line != expected_line:
            all_match = False

        normalized_actual.append(actual_line)
        normalized_expected.append(expected_line)

    if all_match:
        normalized = ''.join(normalized_expected)
        return True, normalized, normalized

    return False, ''.join(normalized_actual), ''.join(normalized_expected)


def _compare_json_with_tolerance(
    actual_text: str,
    expected_text: str,
    tolerance_percent: float
) -> tuple:
    """
    Compare JSON outputs, allowing tolerance for actual-size field.

    The "actual-size" field depends on filesystem block allocation which
    varies across systems even for identical file content. This function
    compares JSON structures and allows actual-size values to differ by
    up to the tolerance percentage.

    Args:
        actual_text: JSON text from imago
        expected_text: JSON text from baseline
        tolerance_percent: Maximum allowed relative difference (0.5 = 50%)

    Returns:
        tuple: (matched: bool, normalized_actual: str, normalized_expected: str)
               If matched, the normalized strings will be identical.
               If not matched, they show what differed.
    """
    try:
        actual = json.loads(actual_text)
        expected = json.loads(expected_text)
    except json.JSONDecodeError:
        # Not valid JSON, can't apply tolerance
        return False, actual_text, expected_text

    def values_match(actual_val, expected_val, path=''):
        """
        Recursively compare values, returning True if they match
        (with tolerance for actual-size).
        """
        if isinstance(expected_val, dict) and isinstance(actual_val, dict):
            if set(actual_val.keys()) != set(expected_val.keys()):
                return False
            for key in expected_val:
                if not values_match(actual_val[key], expected_val[key],
                                    f'{path}.{key}'):
                    return False
            return True
        elif isinstance(expected_val, list) and isinstance(actual_val, list):
            if len(actual_val) != len(expected_val):
                return False
            for i, (a, e) in enumerate(zip(actual_val, expected_val)):
                if not values_match(a, e, f'{path}[{i}]'):
                    return False
            return True
        elif path.endswith('.actual-size'):
            # Allow percentage-based tolerance for actual-size field
            # since sparse file allocation varies significantly across systems
            if isinstance(actual_val, int) and isinstance(expected_val, int):
                if expected_val == 0:
                    return actual_val == 0
                relative_diff = abs(actual_val - expected_val) / expected_val
                return relative_diff <= tolerance_percent
            return actual_val == expected_val
        else:
            return actual_val == expected_val

    matched = values_match(actual, expected)

    if matched:
        # Return identical normalized text to indicate match
        normalized = json.dumps(expected, indent=4) + '\n'
        return True, normalized, normalized

    # Not matched - return original texts for diff
    return False, actual_text, expected_text


def compare_outputs(imago_output: str, expected_output: str) -> tuple:
    """
    Compare imago output against expected output (from qemu-img or override).

    For JSON output, allows tolerance for the "actual-size" field.
    For human output, allows tolerance for the "disk size:" field.
    Both depend on filesystem allocation and can vary across systems.
    See docs/quirks.md "File Sparseness and Git" for details.

    Returns:
        tuple: (matched: bool, diff_text: str)
               If matched is True, diff_text is empty.
               If matched is False, diff_text contains a human-readable diff
               with whitespace characters made visible.
    """
    if imago_output == expected_output:
        return True, ''

    # For JSON output, try comparing with tolerance for actual-size
    matched, imago_normalized, expected_normalized = _compare_json_with_tolerance(
        imago_output, expected_output, ACTUAL_SIZE_TOLERANCE_PERCENT
    )

    if matched:
        return True, ''

    # For human output, try comparing with tolerance for disk size
    matched, imago_normalized, expected_normalized = _compare_human_with_tolerance(
        imago_output, expected_output, ACTUAL_SIZE_TOLERANCE_PERCENT
    )

    if matched:
        return True, ''

    # Generate a unified diff with whitespace made visible
    imago_visible = _make_whitespace_visible(imago_normalized)
    expected_visible = _make_whitespace_visible(expected_normalized)

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
