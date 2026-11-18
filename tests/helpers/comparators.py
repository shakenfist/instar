"""String comparison utilities with whitespace-aware diff output."""

import difflib
import json
import os
import re

# Placeholder used in baseline files for the testdata root path
TESTDATA_ROOT_PLACEHOLDER = '$TESTDATA_ROOT'

# Human-format info output: the lines that name a file, and the disk-size
# lines whose value is resolved from them.
_HUMAN_IMAGE_RE = re.compile(r'^image:\s*(.*)$', re.MULTILINE)
_HUMAN_FILENAME_RE = re.compile(r'^\s*filename:\s*(.*)$', re.MULTILINE)
_HUMAN_CHILD_NODE_RE = re.compile(r"^Child node '")
_HUMAN_DISK_SIZE_RE = re.compile(r'^(\s*disk size:\s*).*$')

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


def _iter_named_files(data):
    """
    Yield every existing file path a parsed info output names.

    Only 'filename' keys are followed. A backing file is named by
    'backing-filename' / 'full-backing-filename' and is deliberately not
    yielded: it is a separate image, and qemu-img does not count it in the
    allocation it reports for this one.

    Args:
        data: Parsed JSON data (dict or list)

    Yields:
        Path strings, with duplicates and non-existent paths left in for
        the caller to resolve.
    """
    if isinstance(data, dict):
        filename = data.get('filename')
        if isinstance(filename, str) and os.path.exists(filename):
            yield filename
        for value in data.values():
            if isinstance(value, (dict, list)):
                yield from _iter_named_files(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                yield from _iter_named_files(item)


def _image_total_disk_size(data, fallback: int) -> int:
    """
    Sum the allocations of the distinct files an image's output names.

    An image is usually one file, and then this is that file's allocation
    and nothing changes. A VMDK descriptor that resolves to separate extent
    files is several files, and qemu-img reports the image's allocation as
    the sum over the descriptor and every extent, so the oracle has to sum
    them too -- resolving the top-level object's own filename would get the
    descriptor's few blocks and substitute away the very figure a
    multi-file image is being compared on (issue #922).

    Paths are deduplicated by realpath, because the same file is named more
    than once: a single-file image appears as both the image and its '/file'
    protocol child, and each VMDK extent appears as both a child and an
    entry in the format-specific extents array.

    Args:
        data: Parsed JSON data for one image
        fallback: Allocation to use when the output names no existing file

    Returns:
        Allocation in bytes
    """
    paths = {os.path.realpath(path) for path in _iter_named_files(data)}
    if not paths:
        return fallback
    return sum(get_disk_size(path) for path in sorted(paths))


def _substitute_json_actual_size(data: dict, disk_size: int,
                                 top_level: bool = True) -> dict:
    """
    Recursively substitute actual-size values in JSON data.

    For dicts that carry their own 'filename', the disk_size lookup is
    redone per-file (e.g. VMDK monolithicFlat has separate descriptor
    and extent files with different on-disk sizes). Dicts without a
    filename fall back to the passed-in disk_size, preserving the
    single-file behaviour used by every other format.

    The outermost object is the image rather than one of its files, so its
    actual-size is the sum over every file the output names. See
    _image_total_disk_size.

    Args:
        data: Parsed JSON data (dict or list)
        disk_size: Actual disk allocation in bytes (the fallback when
            a dict has no filename of its own)
        top_level: True while data is an image object rather than one of
            its children. A list at the top level (info --chain) holds one
            image per element, so each element stays top-level.

    Returns:
        JSON data with actual-size values replaced
    """
    if isinstance(data, dict):
        # If this dict references its own file, use that file's
        # actual disk size rather than the passed-in default. Any
        # OSError from get_disk_size is intentionally allowed to
        # propagate: after os.path.exists returned True, a stat
        # failure indicates a real test-environment problem (race,
        # permission, broken testdata) that should fail loud rather
        # than silently fall back to the wrong actual-size.
        effective_size = disk_size
        filename = data.get('filename')
        if isinstance(filename, str) and os.path.exists(filename):
            effective_size = get_disk_size(filename)
        if top_level:
            effective_size = _image_total_disk_size(data, effective_size)
        result = {}
        for key, value in data.items():
            if key == 'actual-size':
                result[key] = effective_size
            elif isinstance(value, (dict, list)):
                result[key] = _substitute_json_actual_size(
                    value, disk_size, top_level=False
                )
            else:
                result[key] = value
        return result
    elif isinstance(data, list):
        return [_substitute_json_actual_size(item, disk_size,
                                             top_level=top_level)
                if isinstance(item, (dict, list)) else item
                for item in data]
    return data


def _substitute_human_disk_size(text: str, disk_size: int) -> str:
    """
    Substitute disk size values in human-readable output.

    Human output carries the image's own 'disk size' line and, from
    qemu-img 8.0, one per protocol child node. They are not the same
    number once an image is more than one file: the image's line is the
    sum over every file it names, while each child node reports its own
    file. Substituting one allocation into all of them hid a real
    divergence on multi-file VMDK (issue #922), so each line is resolved
    from the path the output names for it.

    Args:
        text: Human-readable output text
        disk_size: Actual disk allocation of the image file itself, used
            where the output names no path that exists

    Returns:
        Text with disk size lines replaced
    """
    total_size = _total_human_disk_size(text, disk_size)

    result = []
    in_child_node = False
    child_path = None
    for line in text.split('\n'):
        if _HUMAN_CHILD_NODE_RE.match(line):
            in_child_node = True
            child_path = None
            result.append(line)
            continue

        filename_match = _HUMAN_FILENAME_RE.match(line)
        if filename_match and in_child_node:
            child_path = filename_match.group(1).strip()
            result.append(line)
            continue

        disk_size_match = _HUMAN_DISK_SIZE_RE.match(line)
        if disk_size_match:
            if not in_child_node:
                line_size = total_size
            elif child_path and os.path.exists(child_path):
                line_size = get_disk_size(child_path)
            else:
                line_size = disk_size
            result.append(
                f'{disk_size_match.group(1)}{_format_human_size(line_size)}'
            )
            continue

        result.append(line)

    return '\n'.join(result)


def _total_human_disk_size(text: str, fallback: int) -> int:
    """
    Sum the allocations of the distinct files human output names.

    The image itself is named by the 'image:' line, and every other file
    it is made of by a 'filename:' line -- the VMDK extents appear in the
    format-specific extents block even on the qemu versions that print no
    child nodes. Paths are deduplicated by realpath because the same file
    is named more than once. A 'backing file:' line is not a 'filename:'
    line, so a backing image is correctly left out of the sum.

    Args:
        text: Human-readable output text
        fallback: Allocation to use when no named path exists

    Returns:
        Allocation in bytes
    """
    named = []
    for pattern in (_HUMAN_IMAGE_RE, _HUMAN_FILENAME_RE):
        named.extend(match.group(1).strip()
                     for match in pattern.finditer(text))
    paths = {os.path.realpath(path) for path in named if os.path.exists(path)}
    if not paths:
        return fallback
    return sum(get_disk_size(path) for path in sorted(paths))


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
