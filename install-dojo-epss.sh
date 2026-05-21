#!/usr/bin/env bash
# install-dojo-epss.sh — one-shot installer for dojo_epss into a docker-compose
# DefectDojo deployment. Works in both dev and prod modes.
#
# Run from the root of your DefectDojo checkout, e.g.:
#     cd ~/path/django-DefectDojo
#     bash /path/to/install-dojo-epss.sh
#
# The script auto-detects whether you're running DefectDojo in dev mode (host
# folder bind-mounted at /app inside the containers) or production mode (code
# baked into the image).
#
#   dev mode  → installs in-place: rsync source, patch host templates,
#               pip install -e (or non-editable fallback), migrate, restart.
#   prod mode → builds an overlay image that bakes dojo_epss + patches in,
#               then `docker compose up -d --build` to swap the four
#               Django/Celery services to the new image.
#
# Options:
#   --source PATH         Where the dojo_epss source folder lives. If omitted,
#                         a handful of common locations are searched.
#   --mode dev|prod|auto  Override the auto-detection (default: auto).
#   --uninstall           Reverse the installation.
#   --help                Print this header.

set -euo pipefail

# ---------------------------------------------------------------------------
# Args + colors
# ---------------------------------------------------------------------------
MODE_FLAG="auto"
ACTION="install"
SOURCE=""
SOURCE_DEFAULTS=(
    "./dojo_epss_pkg"
    "./Dojo-EPSS"
    "../dojo_epss"
    "../Dojo-EPSS"
)
PKG_LOCAL="./dojo_epss_pkg"
LS=dojo/settings/local_settings.py
DOJO_EPSS_LS=dojo_epss_local_settings.py   # used by prod-mode Dockerfile COPY

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall)  ACTION="uninstall"; shift ;;
        --source)     SOURCE="$2"; shift 2 ;;
        --mode)       MODE_FLAG="$2"; shift 2 ;;
        -h|--help)    sed -n '2,35p' "$0"; exit 0 ;;
        *)            echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

G='\033[0;32m'; Y='\033[0;33m'; R='\033[0;31m'; B='\033[0;34m'; N='\033[0m'
log()  { echo -e "${B}==>${N} $*"; }
ok()   { echo -e "${G}✓${N} $*"; }
warn() { echo -e "${Y}!${N} $*"; }
err()  { echo -e "${R}✗${N} $*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Status Check
# ---------------------------------------------------------------------------
[[ ${EUID:-$(id -u)} -ne 0 ]] || die \
    "Don't run this script with sudo. It uses 'docker compose exec' which already "$'\n'\
    "has the privileges it needs, and sudo'd file copies leave root-owned files in "$'\n'\
    "your DefectDojo checkout."

[[ -f docker-compose.yml && -d dojo/templates ]] \
    || die "Run this from the root of your DefectDojo checkout (no docker-compose.yml here)."

command -v docker >/dev/null || die "docker not found in PATH."
docker compose version >/dev/null 2>&1 || die "docker compose plugin not available."

# Locate source folder.
if [[ "$ACTION" == "install" && -z "$SOURCE" ]]; then
    for cand in "${SOURCE_DEFAULTS[@]}"; do
        if [[ -f "$cand/pyproject.toml" ]] && grep -q '^name = "dojo-epss"' "$cand/pyproject.toml" 2>/dev/null; then
            SOURCE="$cand"; break
        fi
    done
fi
if [[ "$ACTION" == "install" ]]; then
    [[ -n "$SOURCE" && -f "$SOURCE/pyproject.toml" ]] \
        || die "Could not locate dojo_epss source. Pass --source /path/to/dojo_epss."
    log "Using source: $SOURCE"
fi

CONTAINERS=(uwsgi celeryworker celerybeat)

# ---------------------------------------------------------------------------
# Mode detection
# ---------------------------------------------------------------------------
detect_mode() {
    local mode="prod"
    # Check running uwsgi container whether docker-compose.yml exists at /app.
    # In dev mode the host repo is bind-mounted at /app, so it does. In prod
    # mode the image only contains DefectDojo's app source, not the compose file.
    if docker compose ps --services --filter status=running 2>/dev/null | grep -q '^uwsgi$'; then
        if docker compose exec -T uwsgi test -f /app/docker-compose.yml 2>/dev/null; then
            mode="dev"
        fi
    else
        mode="unknown"
    fi
    echo "$mode"
}

if [[ "$MODE_FLAG" == "auto" ]]; then
    MODE=$(detect_mode)
    if [[ "$MODE" == "unknown" ]]; then
        die "uwsgi container isn't running. Start DefectDojo first with: docker compose up -d"
    fi
else
    MODE="$MODE_FLAG"
fi
log "Mode: $MODE"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
rsync_pkg() {
    log "Copying dojo_epss → $PKG_LOCAL …"
    mkdir -p "$PKG_LOCAL"
    if command -v rsync >/dev/null; then
        rsync -a --delete --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
            "$SOURCE/" "$PKG_LOCAL/"
    else
        rm -rf "$PKG_LOCAL"; mkdir -p "$PKG_LOCAL"
        cp -R "$SOURCE"/. "$PKG_LOCAL/"
        find "$PKG_LOCAL" \( -name '__pycache__' -o -name '*.pyc' -o -name '.DS_Store' \) -prune -exec rm -rf {} +
    fi
    ok "package copied."
}

apply_patches() {
    log "Applying template patches …"
    local applied_any=0
    for p in 01-sidebar-menu.patch 02-findings-list-epss-update-column.patch; do
        local f="$PKG_LOCAL/patches/$p"
        [[ -f "$f" ]] || die "Patch missing: $f"
        if patch --forward --dry-run -p1 --silent < "$f" 2>/dev/null; then
            patch --forward -p1 --silent < "$f"
            ok "applied $p"; applied_any=1
        else
            warn "$p already applied — skipping."
        fi
    done
    [[ $applied_any -eq 1 ]] || true
}

reverse_patches() {
    log "Reversing template patches …"
    for p in 02-findings-list-epss-update-column.patch 01-sidebar-menu.patch; do
        local f="$PKG_LOCAL/patches/$p"
        if [[ -f "$f" ]]; then
            patch -R -p1 --forward --silent < "$f" 2>/dev/null \
                || warn "Reverse-patch $p failed (probably already reversed)."
        fi
    done
}

# Returns the local_settings.py content (sans markers) on stdout.
#
# NOTE: We override ROOT_URLCONF instead of using EXTRA_URL_PATTERNS.
# Reason: EXTRA_URL_PATTERNS in local_settings.py calls include() at
# settings-load time, which eagerly imports dojo_epss.urls -> views ->
# forms -> models. Defining Django models that early raises
# AppRegistryNotReady because the app registry is not yet populated when
# settings.py runs. ROOT_URLCONF is just a string at settings load; Django
# imports the actual URLconf module later, after app loading completes.
ls_block_body() {
    cat <<'PY'
INSTALLED_APPS = INSTALLED_APPS + ("dojo_epss",)

# Defer URL include until after Django boots (see dojo_epss/_root_urls.py).
ROOT_URLCONF = "dojo_epss._root_urls"

try:
    from celery.schedules import crontab
    CELERY_BEAT_SCHEDULE = {
        **CELERY_BEAT_SCHEDULE,
        "dojo_epss-schedule-dispatcher-hourly": {
            "task": "dojo_epss.schedule_dispatcher_task",
            "schedule": crontab(minute="7"),
            "options": {"expires": int(60 * 30)},
        },
    }
except Exception:
    pass
PY
}

# Always rewrites the dojo_epss block: strips any old one first, then
# appends a fresh copy. Safe across version upgrades of the block format.
write_local_settings() {
    local start="# >>> dojo_epss install block >>>"
    local end="# <<< dojo_epss install block <<<"
    log "Writing $LS …"

    # Strip any pre-existing dojo_epss block so reruns get the latest version.
    if [[ -f "$LS" ]] && grep -qF "$start" "$LS"; then
        python3 - "$LS" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
txt = p.read_text()
new = re.sub(
    r"# >>> dojo_epss install block >>>.*?# <<< dojo_epss install block <<<\n",
    "", txt, flags=re.S,
)
p.write_text(new)
PY
        warn "stripped previous dojo_epss block — will rewrite with current version."
    fi

    {
        [[ -f "$LS" ]] && cat "$LS"
        echo
        echo "$start"
        ls_block_body
        echo "$end"
    } > "$LS.new"
    mv "$LS.new" "$LS"
    ok "wrote $LS"
}

# Standalone copy of local_settings used by the prod-mode Dockerfile COPY.
write_prod_local_settings() {
    log "Writing $DOJO_EPSS_LS for the image build …"
    {
        echo "# Auto-generated by dojo_epss install script (prod mode)."
        echo "# COPYed into /app/dojo/settings/local_settings.py by Dockerfile.dojo-epss-overlay"
        ls_block_body
    } > "$DOJO_EPSS_LS"
    ok "wrote $DOJO_EPSS_LS"
}

remove_local_settings_block() {
    if [[ -f "$LS" ]]; then
        python3 - "$LS" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
txt = p.read_text()
new = re.sub(
    r"# >>> dojo_epss install block >>>.*?# <<< dojo_epss install block <<<\n",
    "", txt, flags=re.S,
)
if new != txt:
    p.write_text(new); print("  removed block from", p)
if new.strip() == "":
    p.unlink(); print("  local_settings.py was empty after removal; deleted")
PY
    fi
    rm -f "$DOJO_EPSS_LS"
}

# ---------------------------------------------------------------------------
# DEV-mode install
# ---------------------------------------------------------------------------
install_dev() {
    rsync_pkg

    # Restarts containers so they see the just-copied dojo_epss_pkg/ via the
    # bind mount. macOS Docker Desktop sometimes doesn't propagate new files
    # into already-running containers; a restart is the safe fix.
    log "Restarting containers so the bind mount picks up new files …"
    docker compose restart "${CONTAINERS[@]}" >/dev/null
    sleep 3

    apply_patches
    write_local_settings

    log "pip install dojo_epss into each container …"
    for svc in "${CONTAINERS[@]}"; do
        # Try editable first; fall back to non-editable if the build backend
        # bootstrap is unavailable (e.g. container has no internet to install
        # setuptools>=68 into the temp build env).
        if docker compose exec -T "$svc" pip install --quiet --no-deps -e /app/dojo_epss_pkg 2>/dev/null; then
            ok "editable install OK in $svc"
        elif docker compose exec -T "$svc" pip install --quiet --no-deps /app/dojo_epss_pkg 2>/dev/null; then
            ok "non-editable install OK in $svc"
        else
            err "pip install failed in $svc — running it loudly so you can see the real error:"
            docker compose exec -T "$svc" pip install --no-deps /app/dojo_epss_pkg || true
            die "Aborting. See the error above."
        fi
    done

    log "Migrating database …"
    docker compose exec -T uwsgi python manage.py migrate dojo_epss --noinput \
        || die "migrate failed. Run 'docker compose exec uwsgi python manage.py migrate' first to bring dojo schema up to date, then re-run this script."
    ok "migrations applied."

    log "Restarting Django + Celery containers …"
    docker compose restart "${CONTAINERS[@]}" >/dev/null
    ok "containers restarted."
}

# ---------------------------------------------------------------------------
# PROD-mode install
# ---------------------------------------------------------------------------
install_prod() {
    # In prod, the image is custom-built. The package source goes into the
    # build context; the Dockerfile + compose override are taken from the
    # package's docker/ subfolder.
    rsync_pkg
    write_prod_local_settings

    local OVERRIDE="$PKG_LOCAL/docker/docker-compose.override.dojo-epss.yml"
    [[ -f "$OVERRIDE" ]] \
        || die "Prod override compose file missing at $OVERRIDE — was the package source up to date?"

    log "Building overlay image dojo-epss-django:local …"
    docker compose -f docker-compose.yml -f "$OVERRIDE" build \
        || die "Image build failed. See output above."
    ok "image built."

    log "Recreating containers with the new image (postgres, valkey, nginx left untouched) …"
    docker compose -f docker-compose.yml -f "$OVERRIDE" up -d
    ok "containers recreated."

    log "Waiting for uwsgi to become responsive …"
    for i in {1..30}; do
        if docker compose exec -T uwsgi python -c "import dojo_epss" >/dev/null 2>&1; then
            ok "uwsgi is ready and can import dojo_epss."
            break
        fi
        sleep 2
        [[ $i -eq 30 ]] && warn "uwsgi didn't become responsive in 60s — continuing anyway, check 'docker compose logs uwsgi'."
    done

    log "Migrating database …"
    docker compose exec -T uwsgi python manage.py migrate dojo_epss --noinput \
        || die "migrate failed. Check the uwsgi container logs and re-run --mode prod."
    ok "migrations applied."

    cat <<EOM

  NOTE — prod mode: From now on, ALWAYS launch DefectDojo with the override file
  so the dojo-epss-django:local image is used:

    docker compose -f docker-compose.yml \\
                   -f $OVERRIDE \\
                   up -d
EOM
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
uninstall() {
    log "Uninstalling dojo_epss …"

    if docker compose ps --services --filter status=running 2>/dev/null | grep -q '^uwsgi$'; then
        log "Dropping dojo_epss tables …"
        docker compose exec -T uwsgi python manage.py migrate dojo_epss zero --noinput \
            || warn "migrate zero failed (probably already removed)"
        for svc in "${CONTAINERS[@]}"; do
            docker compose exec -T "$svc" pip uninstall -y dojo-epss 2>/dev/null \
                && ok "uninstalled dojo-epss in $svc" \
                || warn "uninstall failed in $svc (probably not installed)"
        done
    else
        warn "compose stack not running; skipping container steps."
    fi

    reverse_patches
    remove_local_settings_block

    log "Removing $PKG_LOCAL …"
    rm -rf "$PKG_LOCAL"

    if docker compose ps --services --filter status=running 2>/dev/null | grep -q '^uwsgi$'; then
        log "Restarting containers …"
        docker compose restart "${CONTAINERS[@]}" >/dev/null
    fi
    ok "dojo_epss uninstalled."
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if [[ "$ACTION" == "uninstall" ]]; then
    uninstall
    exit 0
fi

case "$MODE" in
    dev)  install_dev ;;
    prod) install_prod ;;
    *)    die "Unknown mode: $MODE (expected dev or prod)" ;;
esac

cat <<'EOM'

----------------------------------------------------------------------
  dojo_epss installation complete.

 Open URL  →  log in  →  look for "EPSS" in the sidebar.


  Quick-start:
    1. EPSS → Settings   → flip "Enabled" on, save.
    2. EPSS → Manual Run → "Test FIRST.org API connectivity".
    3. EPSS → Manual Run → "Fetch and Compare from FIRST.org" or CSV equivalent.
    4. Optional: enable KEV settings, then run "Fetch KEV and Update Findings".
    5. Open Findings list → EPSS Update / KEV fields should be visible.

  To uninstall later, from this same folder:
    bash install-dojo-epss.sh --uninstall
----------------------------------------------------------------------
EOM
