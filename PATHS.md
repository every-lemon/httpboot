# KagNode httpboot paths

New installations use project-scoped application, configuration, state and log directories. Upstream operating-system locations are retained.

- `/usr/lib/httpboot-source` → `/opt/kagnode/httpboot/source`
- `/etc/httpboot-build` → `/etc/kagnode/httpboot-builder`
- `/etc/httpboot` → `/etc/kagnode/httpboot`
- `/var/lib/httpboot-builder-v2` → `/var/lib/kagnode/httpboot-builder`
- `/var/lib/httpboot-build-cache` → `/var/cache/kagnode/httpboot`
- `/var/lib/httpboot-server` → `/var/lib/kagnode/httpboot-server`
- `/var/lib/httpboot` → `/var/lib/kagnode/httpboot`
- `/opt/httpboot` → `/opt/kagnode/httpboot`
- `/var/log/httpboot` → `/var/log/kagnode/httpboot`

Existing installations are not migrated automatically. Stop the listed application and data-writing services, take your normal external backup, and inspect `python3 scripts/migrate-paths.py` (dry-run). Then run with `--apply` only after reviewing its exact paths. The journal permits resuming an interrupted copy. The tool retains original directories and verifies copied content, ownership and modes before adding compatibility links. Install the matching new application release and review service configuration before starting it.

`--rollback` restores retained originals and preserves any post-migration writes in a separately named tree for review; it does not silently merge newer data into the old state. `--root` is for disposable fixture tests. No servers, images, Client sessions or user saves were migrated by publishing this release. Never run this migrator against another project that happens to use a similarly named directory.
