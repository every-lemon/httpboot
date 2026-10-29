# HTTP Boot 3.1.15-beta.1 installation

This beta supports Ubuntu 24.04 Servers and amd64 Builders. Virtual boot
qualification is separate from physical firmware and device validation.
Use a separate test Server. Existing installations retain the legacy service until
all enrolled Clients have moved; never remove their existing download or NFS paths
as an installation shortcut.

## Release downloads

Download assets from the `3.1.15-beta.1` GitHub release and run `sha256sum -c SHA256SUMS`
in the directory containing the downloaded files. Install one package:

    sudo apt install ./httpboot-server_3.1.15-beta.1_all.deb
    # Or, on a full amd64 Ubuntu Builder:
    sudo apt install ./httpboot-server-builder_3.1.15-beta.1_amd64.deb

The Debian package version is `3.1.15~beta.1`; the public release name is
`3.1.15-beta.1`. The two package variants are alternatives. No accounts, credentials
or desktop images are included. Generate images locally as described below.

Existing `3.1.15~dev14` installations sort newer in Debian's version ordering.
Back up the database and package, review the release, and explicitly install this
beta package with `sudo dpkg -i /path/to/httpboot-server_3.1.15-beta.1_all.deb`.
Check services and account/session preservation before removing the old package.
Do not restore an old database over later verified saves during package rollback.

## Roles and prerequisites

Server and Builder can share an Ubuntu 24.04 amd64 Builder. Clients target amd64 UEFI.
The Server-only package is architecture-independent and supports amd64 and ARM64
Servers. The combined package requires amd64. ARM64 Client/build support is future work.
Automatic v2 image schedules currently require a combined Server/Builder; separate
Builders use manual build, transfer and publication. See the implementation status
for remaining remote orchestration and USB-import integration work.

Build either package on the source host:

    python3 packaging/build-server-deb.py --output /tmp/httpboot-server.deb
    python3 packaging/build-server-deb.py --with-builder --output /tmp/httpboot-server-builder.deb

Install one package with `sudo apt install /path/to/package.deb`. The combined
variant requests Builder dependencies too. The package installs units without
starting them. Initialize the dedicated CA and open arrow-key setup:

    sudo httpboot-server init-pki --address SERVER_IP
    sudo httpboot-server setup
    sudo systemctl enable --now httpboot-server

The authenticated API listens on 9444. Only /v2/activation accepts anonymous
requests. Image downloads require a verified Client certificate whose public key
matches the enrolled record, not just matching hardware or certificate subject.
Serve only the universal boot.efi bootstrap on a separate public HTTP location;
keep the Server state directory outside every public web root. The native UEFI
HTTP URL points at that same bootstrap used as EFI/BOOT/BOOTX64.EFI on USB/SD.
Firmware menus and Secure Boot policy remain firmware-controlled.

For the optional local web console:

    sudo httpboot-server console

Open the printed localhost URL. Its fragment token is not sent in HTTP requests
and authorizes approvals in the local console. The console lists health, pending
Clients and bounded diagnostic reports. It does not expose passwords or homes.

## Accounts and permissions

Create password hashes in a protected file; do not put hashes in command arguments.

    sudo httpboot-server account alice --uid 1000 --gid 1000 --hash-file /root/alice.hash --access edit
    sudo httpboot-server clients
    sudo httpboot-server approve PAIRING_CODE
    sudo httpboot-server assign alice CLIENT_ID
    sudo httpboot-server set-rules alice /path/to/persistence-rules.json

Permissions are `none`, `status`, or `edit`. Essential data-loss warnings remain
available to every user. The Client root service and Server independently enforce
edits. OS administrator rights are a separate account setting: `account
--system-admin` grants sudo, while `--no-system-admin` removes that membership on
the next boot. New accounts default to no sudo access; migration preserves the
original administrator setting. The Client provisions only assigned account records into RAM. PAM acquires
an exclusive persistent session before restoring the home; writes stay blocked
until restore succeeds. Another Client cannot take over a session. After verifying
that an old Client will not return with pending work:

    sudo httpboot-server release-session alice

The old token immediately loses write authority. Failed logout saves keep the
session and RAM files; a later login on that same Client continues that RAM session.
To move an account after it has logged out, run `httpboot-server unassign alice
OLD_CLIENT_ID`, then `httpboot-server assign alice NEW_CLIENT_ID`. Removing an
assignment refuses an active session; it never silently takes over pending RAM work.

## Image preparation and publication

On a full Builder, install prerequisites listed by the combined package and run:

    sudo httpboot-builder --server https://SERVER_IP:9444 --ca /path/to/public-ca.pem --output /path/to/new-release --validate-startup

Build stages, APT downloads and package indexes are retained under
/var/lib/httpboot-build-cache. The shared desktop contains no deployment users,
password hashes, Server URL or device key. The separately generated bootstrap
contains the Server URL and public CA. Installation/runtime app bundles remain
separate from app data. General defaults do not preinstall personal applications.

The build refuses container execution. It emits artifacts marked `validation:
required`; it does not publish them or fabricate startup proof. Publishing requires
matching successful boot proof with schema 2, architecture amd64,
startup_verified=true, recovery_verified=true, assigned_login_verified=true,
native_http_pairing_verified=true and the exact artifact size/SHA256 map:

    sudo httpboot-server publish-image RELEASE /path/to/new-release --proof /path/to/qualified-proof.json

The v2 qualifier first uses OVMF HTTP Boot to download the bootstrap and register
a fresh device-generated key, checking the pairing screen against the Server's
pending approval record. It then boots an enrolled removable-media Client against
an isolated mutual-TLS Server, checks an assigned account's real PAM login,
restore/save/logout, and boots cached recovery with that Server stopped. It emits
qualification-v2.json only after all these checks pass. Publication checks the
exact artifact hashes, kernel and validator revision. The old v1 validator is not
evidence for v2 startup. Virtual qualification does not replace physical firmware,
SD/USB cold-boot or hardware tests.
Never hand-write a successful proof file.

Use `httpboot-server bootstrap-http --port 8080` to serve only the current boot.efi.
Use `sudo httpboot-server setup` → **Create/update Client USB or SD**, or
`sudo httpboot-server create-media`, for an arrow-key USB writer. It uses the active
qualified release, excludes system and Server data disks, shows model/serial/size,
and requires `ERASE /dev/DEVICE` before formatting. The reuse option preserves
existing identities and unrelated files. It unmounts, remounts read-only, and checks
bootstrap/recovery hashes before reporting that removal is safe. New media still
requires first-boot pairing approval and account assignment.

Use `httpboot-server enroll-media /mounted/fat32` for an already-mounted card; this
command does not format disks. Existing approved device keys are renewed under the
current authority before offline recovery is staged. Recovery generations commit
before the default bootstrap changes, preserving the old startup files after an
interrupted copy. Keep enrolled identities and pinned releases when
moving cards. Normal startup can transition once to the selected image's matching
verified kernel; a failed transition returns to recovery choices.

Pairing generates a device key on the Client. Marked USB/SD media can retain that
key and a signed recovery cache under `httpboot-v2/identity`. Mount options keep
keys root-private. Without accessible identity/cache storage, native HTTP boot
uses a temporary key and cannot offer persistent enrollment or offline recovery.
TPM-backed identity is not yet implemented. Normal startup retries once, then
requires explicit recovery selection. Cached recovery is checked against its
Server-signed manifest and public CA and is limited to 1,500,000,000 bytes.

## Persistence, applications and printing

Selected folders are limited to the user's home; the chooser shows hidden folders.
Safe relative links within a selected folder are preserved without traversing
them. Escaping links, cycles, symlinked parent paths and special files are rejected. For a shared-image application's
data, select the application-data option and its executable name. The closed-folder
rule waits until that process has exited and no same-user process holds files in
the folder. Ordinary document folders show verified transfer, not a claim that
arbitrary live application databases were backed up cleanly. Changes coalesce after two quiet seconds. Chunks are uploaded
only if missing on the Server. Snapshot manifests commit atomically after content
verification. Previous snapshots remain readable after transfer or commit failure.
Pending work remains in RAM and retries automatically. Administrators can configure
`httpboot-server pending-media CLIENT_ID policy.json` with a filesystem `uuid`,
absolute `mountpoint`, and age public `recipient`. The user can export encrypted
pending work only to that approved mounted filesystem. This is explicitly an
unverified pending archive; retain the age private key separately for recovery.

Approve Flatpak source URLs with `httpboot-server sources HTTPS_URL ...`. In the
HTTP Boot app, choose Keep app only or Keep app and data. App-only mode saves
application/runtime bundles under .local/share/httpboot/flatpak-bundles/APP_ID.
Additional downloads stored in .var/app/APP_ID belong to private app data and reset
unless that folder is also selected. Running database apps must close before a
clean save. A local app/runtime bundle round trip is covered by a real Flatpak/OSTree test.
Hardware-dependent extensions and the actual Sober installation still require
Client validation.

The image recipe includes CUPS, driverless discovery and IPP-over-USB. HTTP Boot
lists printers, default selection, test printing, queue state and cancellation of
your own jobs. Only allowlisted printer configuration is persisted, never spool
files or completed documents. Physical printer validation remains outstanding.

Driver imports are administrator-reviewed binary packages or firmware; no DKMS or
arbitrary source builds. Use `httpboot-import-drivers --media MOUNT --store STORE`.
Pass `--drivers STORE` to the Builder to apply approved payloads. Firmware can
survive compatible kernel changes; compiled modules require the exact kernel
vermagic. A rejected import prevents publication and retains the previous image.
Physical USB and driver tests remain required.

Run `python3 /usr/lib/httpboot-source/httpboot/sober_check.py` as the affected user.
The collector classifies bounded installer log text without exporting raw logs,
checks remaining processes, RAM/storage, permissions, profile ownership and graphics
initialization. It does not remove installation data or kill Sober. Four retained
private snapshot logs were checked without finding the classified failure patterns;
this does not establish the cause or replace testing on the affected physical Client.

## Scheduling, retention and migration

Fresh schedule defaults are 04:00 UTC; select the deployment's timezone explicitly:

    sudo httpboot-server schedules --file /path/to/maintenance-policy.json

Existing legacy update agents read /etc/httpboot/maintenance-policy.json and retain
Asia/Taipei when that file is absent. Host packages and image refresh have separate
enable switches and daily gates. Image refresh requires a healthy matching Builder.
The new Server claim API prevents duplicate/conflicting claims. Configure the local
Builder with `httpboot-server configure-builder builder.json` (server, ca, cache,
output, optional jobs/drivers/private_base/legacy_config), then enable the timer:

    sudo systemctl enable --now httpboot-server-maintenance.timer

The executor defers host maintenance while Client sessions, downloads or the legacy
transition are active. Image preparation publishes only after boot qualification.
Required host restarts are reported, never forced.

Cleanup is limited to registered images older than 30 days, retaining at least
three, the active image and every explicit pin. Pin deployed, rollback and enrolled
media references before enabling cleanup:

    sudo httpboot-server pin-image RELEASE enrolled-card:IDENTIFIER
    sudo httpboot-server cleanup
    sudo httpboot-server cleanup --apply

APT archives, indexes, build roots, checkpoints, app caches and user snapshots are
not image-cleanup candidates. Configure separate snapshot retention with
`httpboot-server snapshot-retention --keep 5` (minimum 2). Old snapshot manifests
are removed only after a replacement commits; verified blobs remain reusable.
`cleanup-tools` handles recorded successful legacy tool versions, protecting
current, previous, pending and active operations; unrecognized history is retained.

For an isolated authority import, preserving legacy data in place:

    sudo httpboot-server migrate-legacy --etc /etc/httpboot --legacy-state /var/lib/httpboot

The importer backs up the new database, validates legacy IDs/hashes, and commits
accounts, assignments, devices and a migration marker together. It copies only the
old CA's public certificate into Client trust. It does not rewrite existing images,
homes or snapshots. Import completed legacy saves with:

    sudo httpboot-server import-legacy-saves /etc/httpboot/server.json

The importer validates completion markers, inventory and file hashes, refuses
active v2 sessions, and leaves every source snapshot intact. Links that cross a selected folder boundary require review; safe relative links
within that folder are preserved. To preserve installed applications in a separate private image,
use Builder `--private-base old-filesystem.squashfs --legacy-config server.json`.
Only the staging copy is scrubbed of deployment accounts, hashes and legacy Client
services; identities come from Server assignments. This private migration output
is separate from the clean public image.

Keep legacy services available until all enrolled Clients have successfully booted
and saved through v2. The final restrictive reverse-proxy/NFS cutover must be
applied to the actual deployment after that verification; it has not been applied
by this source build. Fresh v2 installations expose only bootstrap anonymously.
Rollback keeps the old image, original data and authority backup. Do not force a
restart or release a session whose RAM work has not been accounted for.


## Startup repairs and Client diagnostics (development 8)

Use `sudo httpboot-server approve-client` or **Client approvals** in setup to
review a pairing code and select existing accounts in one transaction. Approval
without assignments remains supported by the compatibility CLI, but startup
waits for an assigned account. `approval-defaults --accounts NAME ...` sets
private wizard preselection; it never creates or automatically approves users.
A Client key is the identity. Matching hardware alone cannot merge approvals.

The startup checks writable identity storage before requesting approval. With
multiple boot volumes it uses the firmware partition identifier when available,
otherwise asks you to select a volume. Temporary enrollment is an explicit choice.
Keep the original USB identity directory when updating boot files.

**Hardware diagnostics / save report** collects PCI/USB IDs, bound drivers,
network interface names and filtered driver errors. It excludes network names,
passwords and document contents. Approved Clients send these over any working
network, including Ethernet. With no network, reports queue on accessible boot
media. **Export diagnostic report to USB** writes to an explicitly mounted USB;
on the Server use `httpboot-server import-report FILE`. `boot-health` and the
local console show recent reports, assignments and duplicate hardware records.
Imported reports are advisory and do not authenticate a Client.

## Deferred follow-up: remote amd64 Builder

Remote scheduling and Server-managed driver uploads are development prototypes,
not enabled in the current repair rollout. Their configuration menu entries are
hidden, and Server submission endpoints reject use unless explicitly enabled
for development. Complete and qualify this work separately after the reported
boot, network and login failures are resolved. The following describes the
prototype interface for that follow-up, not current deployment instructions.

Install the matching `--with-builder` package on Ubuntu 24.04 amd64. Create a
root-owned, mode 0600 `/etc/httpboot/builder-v2.json` like this (replace example
addresses and paths):

```json
{"state":"/var/lib/httpboot-builder-v2","address":"192.0.2.20",
 "profiles":{"clean":{"server":"https://192.0.2.10:9444",
 "ca":"/etc/httpboot/server-ca.pem","cache":"/var/lib/httpboot-build-cache"}}}
```

A private profile may additionally specify `private_base` and `legacy_config`;
keep both on the Builder under root-only permissions. API jobs only select a
preconfigured profile. They cannot submit commands or account password hashes.
Enable `httpboot-builder-v2.service`. The privileged supervisor runs image
preparation; a dedicated unprivileged process serves authenticated HTTPS on 9091.

Transfer `/var/lib/httpboot-builder-v2/token` to a root-only file on the Server
using an authenticated private channel. Obtain the SHA256 certificate fingerprint
on the Builder with `openssl x509 -in /var/lib/httpboot-builder-v2/tls/server.pem
-outform DER | sha256sum`. Create a mode 0600 Server JSON containing `url`,
`fingerprint` (64 lowercase hex characters), `token_file` and `profile`. Run
`httpboot-server configure-remote-builder FILE`. The Server checks the pinned
certificate and matching revision before accepting the configuration. Never
publish this token or place it in the public bootstrap.

The existing image-update schedule submits durable jobs. Jobs survive service
restarts, reuse package checkpoints, expose stage events, and resume artifact
transfers. The Server independently validates qualification before publication.
Failed jobs retain their local logs and checkpoints; a later scheduled run uses
a new job. An interrupted active job retains its existing Builder configuration.
Host maintenance defers while image preparation or Client work is active.

USB imports from an approved Client may be uploaded for review through recovery.
Use `driver-imports` then `review-driver ID --approve` on the Server. Approval
records provenance and compatibility; only approved files enter later builds.
Compiled modules still need a matching kernel. Driver source/DKMS builds are not
supported. Physical hardware verification remains necessary after virtual boot
qualification.

### SSH key persistence

Every account inherits enabled SSH persistence by default. Its private `.ssh`
folder is restored before login and saved through the authenticated per-user
snapshot service. Private/public keys, config and known_hosts persist; runtime
agent/control sockets are skipped. Owner-only permissions are retained.
The Server setup menu provides **SSH key persistence**, with a global default
and per-account overrides. Equivalent commands:

```sh
httpboot-server ssh-persistence --default --no-enabled
httpboot-server ssh-persistence caleb --enabled
httpboot-server ssh-persistence caleb --inherit
```

Disabling blocks subsequent SSH snapshot saves and restores; it does not delete
existing keys in a running Client or previous verified Server backups.

The Server package includes its bootstrap service. Starting or restarting the authority also starts its local console and bootstrap endpoint. Daemon logs omit the console credential; the credential remains in the root-only `console-token` file in Server state.
