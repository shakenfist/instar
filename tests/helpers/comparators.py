"""String comparison utilities with whitespace-aware diff output."""

import difflib
import json
import os
import re

# Placeholder used in baseline files for the testdata root path
TESTDATA_ROOT_PLACEHOLDER = '$TESTDATA_ROOT'

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
        testdata_root: The actual testdata root path (INSTAR_TESTDATA_PATH)

    Returns:
        Text with placeholders substituted
    """
    return text.replace(TESTDATA_ROOT_PLACEHOLDER, testdata_root)


def get_disk_size(path: str) -> int:
    """
    Get the actual disk allocation for a file.

    This returns st_blocks * 512, which is what qemu-img and instar report
    as "actual-size" (JSON) or "disk size" (human). This value reflects
    the actual disk space used, accounting for sparse files.

    Args:
        path: Path to the file

    Returns:
        Disk allocation in bytes (st_blocks * 512)
    """
    stat_result = os.stat(path)
    # st_blocks is in 512-byte units on all platforms
    return stat_result.st_blocks * 512


def _format_human_size(size_bytes: int) -> str:
    """
    Format a size in bytes to human-readable format matching instar/qemu-img style.

    Uses 3 significant figures like qemu-img's %0.3g format. This matches
    instar's qemu_compat formatting mode.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string like '36 KiB', '512 MiB', etc.
    """
    if size_bytes == 0:
        return '0'

    # Try each unit from largest to smallest
    for unit_name, unit_bytes in [
        ('TiB', 1024 ** 4),
        ('GiB', 1024 ** 3),
        ('MiB', 1024 ** 2),
        ('KiB', 1024),
    ]:
        if size_bytes >= unit_bytes:
            value = size_bytes / unit_bytes
            # Use 3 significant figures like qemu-img's %0.3g format
            # This matches instar's qemu_compat mode
            if value >= 100.0:
                # For values >= 100, round to whole number (3 sig figs)
                rounded = round(value)
                return f'{rounded} {unit_name}'
            elif value >= 10.0:
                # For values 10-99.9, use 1 decimal place
                rounded = round(value * 10.0) / 10.0
                if rounded == int(rounded):
                    return f'{int(rounded)} {unit_name}'
                return f'{rounded:.1f} {unit_name}'
            elif value >= 1.0:
                # For values 1-9.99, use 2 decimal places
                rounded = round(value * 100.0) / 100.0
                if rounded == int(rounded):
                    return f'{int(rounded)} {unit_name}'
                formatted = f'{rounded:.2f}'.rstrip('0').rstrip('.')
                return f'{formatted} {unit_name}'
            else:
                # For values < 1, use 3 decimal places
                rounded = round(value * 1000.0) / 1000.0
                formatted = f'{rounded:.3f}'.rstrip('0').rstrip('.')
                return f'{formatted} {unit_name}'

    return f'{size_bytes}'


def substitute_actual_size(expected_output: str, disk_size: int) -> str:
    """
    Substitute the actual-size/disk size values in expected output.

    The "actual-size" (JSON) and "disk size" (human) fields report allocated
    disk space which depends on filesystem block allocation. Instead of using
    stored baseline values, we substitute the actual disk size of the test
    image at test time for accurate comparison.

    Args:
        expected_output: Expected output text (JSON or human format)
        disk_size: Actual disk allocation in bytes from filesystem

    Returns:
        Expected output with actual-size values substituted
    """
    # Try JSON substitution first
    try:
        data = json.loads(expected_output)
        data = _substitute_json_actual_size(data, disk_size)
        return json.dumps(data, indent=4) + '\n'
    except json.JSONDecodeError:
        pass

    # Try human format substitution
    return _substitute_human_disk_size(expected_output, disk_size)


def _substitute_json_actual_size(data: dict, disk_size: int) -> dict:
    """
    Recursively substitute actual-size values in JSON data.

    Args:
        data: Parsed JSON data (dict or list)
        disk_size: Actual disk allocation in bytes

    Returns:
        JSON data with actual-size values replaced
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if key == 'actual-size':
                result[key] = disk_size
            elif isinstance(value, (dict, list)):
                result[key] = _substitute_json_actual_size(value, disk_size)
            else:
                result[key] = value
        return result
    elif isinstance(data, list):
        return [_substitute_json_actual_size(item, disk_size)
                if isinstance(item, (dict, list)) else item
                for item in data]
    return data


def _substitute_human_disk_size(text: str, disk_size: int) -> str:
    """
    Substitute disk size value in human-readable output.

    Replaces lines like 'disk size: 36 KiB' with the actual disk size.

    Args:
        text: Human-readable output text
        disk_size: Actual disk allocation in bytes

    Returns:
        Text with disk size line replaced
    """
    formatted_size = _format_human_size(disk_size)
    # Match 'disk size: <value>' pattern, preserving leading whitespace
    pattern = r'^(\s*disk size:\s*).*$'
    replacement = rf'\g<1>{formatted_size}'
    return re.sub(pattern, replacement, text, flags=re.MULTILINE)


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


def compare_outputs(instar_output: str, expected_output: str) -> tuple:
    """
    Compare instar output against expected output.

    This performs exact string comparison. The caller should have already
    substituted environment-specific values (like actual-size) using
    substitute_actual_size() before calling this function.

    Returns:
        tuple: (matched: bool, diff_text: str)
               If matched is True, diff_text is empty.
               If matched is False, diff_text contains a human-readable diff
               with whitespace characters made visible.
    """
    if instar_output == expected_output:
        return True, ''

    # Generate a unified diff with whitespace made visible
    instar_visible = _make_whitespace_visible(instar_output)
    expected_visible = _make_whitespace_visible(expected_output)

    diff = difflib.unified_diff(
        expected_visible.splitlines(keepends=True),
        instar_visible.splitlines(keepends=True),
        fromfile='expected (qemu-img)',
        tofile='actual (instar)',
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
    instar_output: str,
    expected_output: str,
    diff_text: str
) -> str:
    """
    Format a detailed failure message for test output.

    Args:
        image_id: The test image identifier
        instar_output: Raw instar output
        expected_output: Raw expected output
        diff_text: The diff with visible whitespace

    Returns:
        Formatted failure message string
    """
    msg_parts = [
        f'Output mismatch for {image_id}',
        '',
        'Legend: \u2423=trailing space, \u2192=tab, \u21b5=trailing newline',
        '',
        'Diff (- expected, + actual):',
        diff_text,
    ]

    # Add raw outputs for debugging if they're not too long
    if len(instar_output) < 2000 and len(expected_output) < 2000:
        msg_parts.extend([
            '',
            '--- Raw expected output ---',
            repr(expected_output),
            '',
            '--- Raw actual output ---',
            repr(instar_output),
        ])

    return '\n'.join(msg_parts)
