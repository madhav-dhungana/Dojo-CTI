#!/usr/bin/env python3
"""Apply or reverse Dojo EPSS template insertions.

This avoids brittle line-number patch failures when DefectDojo templates move
between releases. The changes are still additive and idempotent.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SIDEBAR_BOOTSTRAP_BLOCK = [
    "                                        {# dojo_epss: EPSS sidebar entry - purely additive #}\n",
    '                                        {% include "dojo_epss/partials/sidebar_menu.html" %}\n',
]
SIDEBAR_BOOTSTRAP_OLD_BLOCK = [
    "                                        {# dojo_epss: EPSS sidebar entry — purely additive #}\n",
    '                                        {% include "dojo_epss/partials/sidebar_menu.html" %}\n',
]
SIDEBAR_TAILWIND_BLOCK = [
    "                    {# dojo_epss: EPSS sidebar entry - purely additive #}\n",
    '                    {% include "dojo_epss/partials/sidebar_menu_tailwind.html" %}\n',
]
HEADER_BLOCK = [
    "                                    {% comment %}dojo_epss: additive 'EPSS Update' column header{% endcomment %}\n",
    '                                    {% include "dojo_epss/partials/finding_epss_update_th.html" %}\n',
]
BODY_BLOCK = [
    "                                        {% comment %}dojo_epss: additive 'EPSS Update' column body cell{% endcomment %}\n",
    '                                        <td class="nowrap">\n',
    '                                            {% include "dojo_epss/partials/finding_epss_update_td.html" with finding=finding %}\n',
    "                                        </td>\n",
]
DATATABLE_BLOCK = [
    "                    /* dojo_epss: keep DataTables column count in sync with extra <th>/<td> */\n",
    '                    { "data": "epss_update", "orderable": false },\n',
]


BASE_TEMPLATES = (
    "dojo/templates/base.html",
    "dojo/templates_classic/base.html",
)
FINDINGS_TEMPLATES = (
    "dojo/templates/dojo/findings_list_snippet.html",
    "dojo/templates_classic/dojo/findings_list_snippet.html",
)


# This function reads one template. This function needs the DefectDojo root.
def _read_lines(root: Path, relative: str) -> tuple[Path, list[str]]:
    path = root / relative
    if not path.exists():
        raise RuntimeError(f"Template not found: {path}")
    return path, path.read_text(encoding="utf-8").splitlines(keepends=True)


# This function reads an optional template. This function needs the DefectDojo root.
def _read_optional_lines(root: Path, relative: str) -> tuple[Path, list[str]] | None:
    path = root / relative
    if not path.exists():
        return None
    return path, path.read_text(encoding="utf-8").splitlines(keepends=True)


# This function writes changed lines. This function needs a path and lines.
def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(lines), encoding="utf-8")


# This function checks if text exists. This function needs lines and a needle.
def _contains(lines: list[str], needle: str) -> bool:
    return needle in "".join(lines)


# This function finds a line index. This function needs lines and a marker.
def _find_line(lines: list[str], marker: str) -> int:
    for index, line in enumerate(lines):
        if marker in line:
            return index
    raise RuntimeError(f"Could not find template anchor: {marker}")


# This function finds a previous line. This function needs a start and marker.
def _find_previous(lines: list[str], start: int, marker: str) -> int:
    for index in range(start, -1, -1):
        if marker in lines[index]:
            return index
    raise RuntimeError(f"Could not find previous template anchor: {marker}")


# This function removes exact blocks. This function needs lines and blocks.
def _remove_blocks(lines: list[str], blocks: list[list[str]]) -> tuple[list[str], int]:
    removed = 0
    out = lines
    for block in blocks:
        width = len(block)
        cursor = 0
        while cursor <= len(out) - width:
            if out[cursor:cursor + width] == block:
                del out[cursor:cursor + width]
                removed += 1
                continue
            cursor += 1
    return out, removed


# This function removes old sidebar inserts. This function needs template lines.
def _remove_sidebar_insertions(lines: list[str]) -> tuple[list[str], int]:
    lines, removed = _remove_blocks(
        lines,
        [SIDEBAR_BOOTSTRAP_BLOCK, SIDEBAR_BOOTSTRAP_OLD_BLOCK, SIDEBAR_TAILWIND_BLOCK],
    )

    cursor = 0
    include_names = (
        'include "dojo_epss/partials/sidebar_menu.html"',
        'include "dojo_epss/partials/sidebar_menu_tailwind.html"',
    )
    while cursor < len(lines):
        if any(name in lines[cursor] for name in include_names):
            start = cursor
            if cursor > 0 and "dojo_epss: EPSS sidebar entry" in lines[cursor - 1]:
                start = cursor - 1
            del lines[start:cursor + 1]
            removed += 1
            cursor = max(start - 1, 0)
            continue
        cursor += 1
    return lines, removed


# This function detects the newer sidebar. This function needs template lines.
def _is_tailwind_sidebar(lines: list[str]) -> bool:
    return (
        any("x-data" in line for line in lines)
        and any("hover:bg-white/10" in line for line in lines)
    )


# This function finds the sidebar block end. This function needs template lines.
def _find_sidebar_block_end(lines: list[str], tailwind: bool) -> int:
    support_index = _find_line(lines, "{% block support-tab %}")
    markers = ("{% endblock sidebar-items %}", "{% endblock %}") if tailwind else ("{% endblock %}",)
    for index in range(support_index, -1, -1):
        stripped = lines[index].strip()
        if stripped in markers:
            return index
    raise RuntimeError("Could not find sidebar block end")


# This function applies one sidebar include. This function needs a template path.
def _apply_sidebar_template(root: Path, relative: str) -> str:
    path, lines = _read_lines(root, relative)
    lines, removed = _remove_sidebar_insertions(lines)

    tailwind = _is_tailwind_sidebar(lines)
    insert_index = _find_sidebar_block_end(lines, tailwind)
    if tailwind:
        lines[insert_index:insert_index] = SIDEBAR_TAILWIND_BLOCK
        style = "tailwind"
    else:
        lines[insert_index:insert_index] = SIDEBAR_BOOTSTRAP_BLOCK
        style = "bootstrap"

    _write_lines(path, lines)
    action = "moved" if removed else "inserted"
    return f"{relative}: sidebar {action}: {style}"


# This function applies sidebar includes. This function needs the Dojo root.
def _apply_sidebars(root: Path) -> list[str]:
    messages = []
    for relative in BASE_TEMPLATES:
        if (root / relative).exists():
            messages.append(_apply_sidebar_template(root, relative))
    if not messages:
        raise RuntimeError("No supported DefectDojo base templates found")
    return messages


# This function applies one Findings list include set. This function needs a template path.
def _apply_findings_template(root: Path, relative: str) -> str:
    path, lines = _read_lines(root, relative)
    changed = []

    if not _contains(lines, 'include "dojo_epss/partials/finding_epss_update_th.html"'):
        known_index = _find_line(lines, '{% trans "Known Exploited" %}')
        insert_index = _find_previous(lines, known_index, '<th scope="col">')
        lines[insert_index:insert_index] = HEADER_BLOCK
        changed.append("header")

    if not _contains(lines, 'include "dojo_epss/partials/finding_epss_update_td.html"'):
        known_index = _find_line(lines, "finding.known_exploited")
        insert_index = _find_previous(lines, known_index, '<td')
        lines[insert_index:insert_index] = BODY_BLOCK
        changed.append("body")

    if not _contains(lines, '"data": "epss_update"'):
        known_index = _find_line(lines, '"data": "known_exploited"')
        lines[known_index:known_index] = DATATABLE_BLOCK
        changed.append("datatable")

    if changed:
        _write_lines(path, lines)
        return f"{relative}: findings inserted: " + ", ".join(changed)
    return f"{relative}: findings already present"


# This function applies Findings list includes. This function needs the Dojo root.
def _apply_findings(root: Path) -> list[str]:
    messages = []
    for relative in FINDINGS_TEMPLATES:
        if (root / relative).exists():
            messages.append(_apply_findings_template(root, relative))
    if not messages:
        raise RuntimeError("No supported DefectDojo findings list templates found")
    return messages


# This function reverses all insertions. This function needs the Dojo root.
def _reverse(root: Path) -> list[str]:
    messages = []
    for relative in BASE_TEMPLATES:
        template = _read_optional_lines(root, relative)
        if template is not None:
            path, lines = template
            lines, removed = _remove_sidebar_insertions(lines)
            if removed:
                _write_lines(path, lines)
            messages.append(f"{relative}: removed {removed} block(s)")

    for relative in FINDINGS_TEMPLATES:
        template = _read_optional_lines(root, relative)
        if template is not None:
            path, lines = template
            lines, removed = _remove_blocks(lines, [HEADER_BLOCK, BODY_BLOCK, DATATABLE_BLOCK])
            if removed:
                _write_lines(path, lines)
            messages.append(f"{relative}: removed {removed} block(s)")

    if not messages:
        raise RuntimeError("No supported DefectDojo templates found")
    return messages


# This function runs the patcher. This function needs command line args.
def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", help="DefectDojo source root, for example /app")
    parser.add_argument("--reverse", action="store_true", help="Remove Dojo EPSS template insertions")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        messages = _reverse(root) if args.reverse else [*_apply_sidebars(root), *_apply_findings(root)]
    except RuntimeError as exc:
        print(f"dojo_epss template patch failed: {exc}", file=sys.stderr)
        return 1

    for message in messages:
        print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
