# DOJO EPSS

Continuous threat monitoring Django library for DefectDojo.

Dojo EPSS enriches your existing DefectDojo Findings with real-world exploitability signals. It scans CVEs already present in DefectDojo against FIRST.org EPSS data, CISA KEV data, and ransomware usage indicators so teams can continuously understand which vulnerabilities deserve priority.

The library is built for Django-DefectDojo and is designed to be additive: it provides its own Django app, management UI, scheduled jobs, manual actions, audit logs, and API output while keeping DefectDojo's core models and business logic intact.

## Features

- EPSS scan against existing DefectDojo Findings
- KEV scan using CISA JSON or CSV feeds by default
- Ransomware usage signal from KEV-compatible sources
- First-found KEV date tracking without overwriting existing dates on later scans
- Manual fetch and compare actions from the EPSS / KEV UI
- UI-controlled scheduled scans using DefectDojo's Celery beat and workers
- Configurable EPSS source: FIRST.org API or daily CSV
- Configurable KEV source URL and source format
- Finding scope controls for eligible EPSS updates
- EPSS / KEV dashboard and update logs
- Additive EPSS Update / KEV indicators on the Findings list
- Swagger-visible API endpoint for Finding match data
- Docker installer for DefectDojo dev and production-style deployments

## What It Does

Dojo EPSS helps vulnerability teams move beyond static severity. It continuously enriches Findings with exploitability and threat intelligence signals that can change over time.

The library:

- extracts CVEs from DefectDojo Findings
- fetches EPSS scores and percentiles from FIRST.org
- compares EPSS records with existing Findings
- checks whether Finding CVEs are listed as Known Exploited Vulnerabilities
- checks whether those CVEs are known to be used in ransomware campaigns
- updates supported Finding fields positively and safely
- records every run in audit-friendly update logs
- exposes results in the UI and API

Dojo EPSS does not import a vulnerability catalog for its own sake. It focuses on the CVEs already present in your DefectDojo environment so the output reflects your actual vulnerability posture.

## Data Sources

Default sources:

- EPSS API: `https://api.first.org/data/v1/epss`
- EPSS CSV: `https://epss.empiricalsecurity.com`
- KEV JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- KEV CSV: `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`

The Settings page lets administrators point EPSS and KEV sources to compatible internal mirrors.

## Dependencies

Dependency line:

```toml
dependencies = ["Django>=4.2", "requests>=2.28"]
```

Runtime dependencies:

- Python `>=3.11`
- Django `>=4.2`
- requests `>=2.28`
- DefectDojo's existing Celery stack for scheduled/background jobs

Optional dependencies:

- Celery `>=5.3` for non-DefectDojo standalone task usage
- pytest, pytest-django, and responses for tests

DefectDojo pins many runtime packages centrally, so this library keeps dependency floors intentionally light.

## Installation

Clone the repository first:

```bash
git clone https://github.com/madhav-dhungana/Dojo-EPSS.git
```

Then run the installer from the root of your DefectDojo checkout.

Example:

```bash
cd ~/DojoLive/django-DefectDojo

bash "/path/to/Dojo-EPSS/install-dojo-epss.sh" \
     --source "/path/to/Dojo-EPSS" \
     --mode prod
```

For production-style Docker deployments, use `--mode prod`.

For development deployments where the DefectDojo checkout is bind-mounted into containers at `/app`, use `--mode dev`.

You can verify dev-mode suitability with:

```bash
docker compose exec uwsgi test -f /app/docker-compose.yml && echo "dev mode OK"
```

If that command does not print `dev mode OK`, use `--mode prod`.

## Installer Modes

### Production Mode

Production mode builds a Docker overlay image named `dojo-epss-django:local`.

It:

- copies the library into the Docker build context
- installs Dojo EPSS into the image
- applies the additive UI template patches inside the image
- writes the required Django settings overlay
- recreates Django and Celery services with the new image
- runs Dojo EPSS migrations

After installing in production mode, always start DefectDojo with the generated override file:

```bash
docker compose -f docker-compose.yml \
               -f dojo_epss_pkg/docker/docker-compose.override.dojo-epss.yml \
               up -d
```

### Development Mode

Development mode is for a DefectDojo checkout bind-mounted into containers.

It:

- copies the library into `./dojo_epss_pkg`
- applies additive template patches to the host checkout
- writes the Dojo EPSS settings block to `dojo/settings/local_settings.py`
- installs the package inside running Django/Celery containers
- runs migrations
- restarts services

Use development mode only when `/app/docker-compose.yml` exists inside the `uwsgi` container.

## First Run

After installation:

1. Log in to DefectDojo as a superuser.
2. Open `EPSS / KEV Settings`.
3. Enable the module.
4. Choose one EPSS source: FIRST.org fetch or daily CSV download.
5. Enable KEV checks if you want KEV and ransomware enrichment.
6. Save settings.
7. Open `Manual Run`.
8. Run `Fetch and Compare from FIRST.org` or `Download CSV and Compare`.
9. Optionally run `Fetch KEV and Update Findings`.
10. Review the dashboard, Finding Matches, Update Logs, and Findings list.

## Uninstall

Dojo EPSS includes a clean uninstall path. Run the uninstall command from the root of your DefectDojo checkout:

```bash
cd ~/DojoLive/django-DefectDojo

bash "/path/to/Dojo-EPSS/install-dojo-epss.sh" --uninstall
```

The uninstaller will:

- migrate Dojo EPSS database tables back to zero
- uninstall the `dojo-epss` Python package from running Django/Celery containers when possible
- reverse the additive DefectDojo template patches
- remove the Dojo EPSS settings block from `dojo/settings/local_settings.py`
- remove the local `dojo_epss_pkg` copy
- restart Django/Celery containers when the stack is running

The uninstall process is designed to remove Dojo EPSS cleanly without breaking Django-DefectDojo core files or unrelated DefectDojo data. It only targets Dojo EPSS-owned tables, package files, settings block, and template patch additions.

## Scheduling

Dojo EPSS uses DefectDojo's existing Celery worker and Celery beat setup.

The installer adds one static hourly dispatcher task:

```python
dojo_epss.schedule_dispatcher_task
```

The dispatcher checks the EPSS / KEV Settings page and only runs scans when the configured interval is due.

Supported UI intervals:

- Disabled
- Every 12 hours
- Every 24 hours

This keeps the Celery beat configuration stable while letting administrators control scan timing from the UI.

## Manual Actions

Manual actions are available from the EPSS / KEV Manual Run page:

- Fetch and Compare from FIRST.org
- Download CSV and Compare
- Fetch KEV and Update Findings
- Auto-update eligible Findings
- Test FIRST.org API connectivity

Manual actions are superuser-only and write update logs.

## API

Dojo EPSS exposes a Swagger-visible API endpoint:

```http
GET /api/v2/dojo_epss/finding-matches/
```

Supported query filters:

- `status`
- `finding_id`
- `cve_id`
- `kev=true`
- `ransomware=true`

The response includes EPSS match data and a KEV snapshot when available.

## Permissions

Read-only EPSS / KEV pages are available to staff, superusers, or users with:

```text
dojo_epss.view_epss_dashboard
```

Settings and manual write actions require a superuser.

Detailed update-log request parameters, source URLs, and error details are visible to superusers only.

## Security Notes

EPSS and KEV source URLs are configurable so organizations can use internal mirrors. Treat those settings as trusted administrator inputs.

The library:

- does not use `eval` or shell execution in application code
- protects manual POST actions with CSRF and superuser checks
- uses bounded HTTP retry behavior
- records failed external calls in update logs instead of breaking normal DefectDojo pages
- updates Findings with focused `save(update_fields=[...])` writes

## License

Dojo EPSS is released under the BSD-3-Clause License.

See [LICENSE](LICENSE).

## Author

Madhav Dhungana

## Project Links

- Homepage: `https://github.com/madhav-dhungana/Dojo-EPSS`
- Source: `https://github.com/madhav-dhungana/Dojo-EPSS`
