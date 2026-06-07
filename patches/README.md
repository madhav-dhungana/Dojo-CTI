# Template insertions for DefectDojo

`dojo_epss` does not edit DefectDojo source directly during development. The
installer copies the package into the target DefectDojo checkout or overlay
image, then runs:

```bash
python3 dojo_epss_pkg/patches/apply_template_patches.py .
```

The patcher is additive and idempotent. It searches for stable template anchors
instead of relying on fixed line numbers.

## What Gets Inserted

| Area | What it does |
|---|---|
| Sidebar navigation | Adds the EPSS menu as a top-level sidebar item. Old Bootstrap templates use `dojo_epss/partials/sidebar_menu.html`; new Tailwind/Alpine templates use `dojo_epss/partials/sidebar_menu_tailwind.html`. |
| Findings list | Adds the additive **EPSS Update** column to each available `findings_list_snippet.html`. Existing DefectDojo columns are not moved, renamed, or removed. |

## Supported Template Layouts

The patcher supports:

- older DefectDojo versions with only `dojo/templates/base.html`
- newer DefectDojo versions with `dojo/templates/base.html` for Tailwind UI
- newer DefectDojo versions with `dojo/templates_classic/base.html` for classic UI

When both new and classic UI trees exist, both are patched so users can switch
UI preference without rebuilding the image again.

## Reverse / Uninstall

From the root of a DefectDojo checkout:

```bash
python3 dojo_epss_pkg/patches/apply_template_patches.py --reverse .
```

The reverse mode removes only Dojo EPSS-owned insertions.

## Legacy Patch Files

`01-sidebar-menu.patch` and `02-findings-list-epss-update-column.patch` are
kept for audit/reference history. The installer uses `apply_template_patches.py`
because fixed-context patch files are fragile across DefectDojo UI updates.
