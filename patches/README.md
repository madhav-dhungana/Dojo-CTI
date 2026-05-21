# Template patches for DefectDojo

These two unified-diff patches are the **only** changes `dojo_epss` needs in
DefectDojo's own files. They were generated against **DefectDojo 2.58.2** and
verified with `patch --dry-run -p1` against an unmodified checkout (zero fuzz).

| Patch | What it does |
|---|---|
| `01-sidebar-menu.patch` | Adds a single `{% include %}` line inside the existing `{% block sidebar-items %}` of `dojo/templates/base.html`, just before the block closes. The included partial (`dojo_epss/partials/sidebar_menu.html`) is self-guarding — it renders nothing if the EPSS URLs aren't mounted, so the patch is safe to leave in place across upgrades or when the module is temporarily disabled. |
| `02-findings-list-epss-update-column.patch` | Adds the additive **EPSS Update** column to `dojo/templates/dojo/findings_list_snippet.html`: one `<th>` immediately after the existing "EPSS Percentile" header, and one `<td>` immediately after the matching body cell. No existing column is moved, renamed, or removed. |

## Apply

From the root of your DefectDojo checkout:

```bash
patch -p1 < /path/to/dojo_epss/patches/01-sidebar-menu.patch
patch -p1 < /path/to/dojo_epss/patches/02-findings-list-epss-update-column.patch
```

## Reverse / uninstall

```bash
patch -R -p1 < /path/to/dojo_epss/patches/02-findings-list-epss-update-column.patch
patch -R -p1 < /path/to/dojo_epss/patches/01-sidebar-menu.patch
```

## Why these are shipped as patches rather than auto-applied

Modifying core DefectDojo templates is the operator's call, not the library's.
Shipping the patches alongside the package keeps the integration explicit and
auditable, plays well with config-management tools (Ansible, Puppet, K8s
ConfigMaps, etc.), and makes upgrades trivial — when DefectDojo's templates
shift, you re-run the patches; if they fail to apply, you re-generate them
from the new line numbers using the same approach.

## Re-generating against a newer DefectDojo

If a future DefectDojo release changes the surrounding context lines:

```bash
# 1. Make a copy of the two affected templates.
cp dojo/templates/base.html /tmp/base.html.orig
cp dojo/templates/dojo/findings_list_snippet.html /tmp/snip.html.orig

# 2. Apply the desired edits manually (search for "EPSS Percentile" — the
#    insertion points are immediately after the matching <th>/<td>).

# 3. Regenerate the diffs.
diff -u /tmp/base.html.orig dojo/templates/base.html > 01-sidebar-menu.patch
diff -u /tmp/snip.html.orig dojo/templates/dojo/findings_list_snippet.html \
    > 02-findings-list-epss-update-column.patch

# 4. Rewrite the headers so the patches apply with -p1.
sed -i 's|^--- /tmp/.*\.orig|--- a/dojo/templates/base.html|' 01-sidebar-menu.patch
# ...etc.
```
