# Third-party components

The MIT license applies to HTTP Boot project source. It does not relicense Ubuntu,
the Linux kernel, firmware, Flatpak applications, fonts or distribution packages.
The public source and Server Debian packages include DejaVu Sans Mono and its
license under `httpboot/assets/fonts/` (installed under
`/usr/lib/httpboot-source/httpboot/assets/fonts/`). Other package dependencies
are installed separately by APT under their original licenses.

Generated desktop and recovery images retain distribution copyright and license
files under /usr/share/doc/PACKAGE/copyright. The Builder emits
packages-desktop.tsv and packages-recovery.tsv with binary package, version,
architecture, source package and source version. The kernel and firmware copied
from the desktop into recovery retain their notices under
/usr/share/doc/httpboot-copied-kernel-firmware. Consult those
inventories and the distribution's corresponding sources before redistributing
binary images; the project MIT license alone is not permission to redistribute
all bundled components.

The browser uses GTK and WebKitGTK; printing uses CUPS, cups-filters, ipp-usb and
Avahi; application persistence uses Flatpak and OSTree; encrypted pending work uses
age. Python, OpenSSL, systemd, Linux, Ubuntu packages, fonts and themes retain their
own licenses. No personal application binaries are bundled in the clean source or
preselected by the generic image recipe. Administrator-imported firmware/drivers
and private-image migrations require separate provenance and license review.

Behavioral references:

- [Sober troubleshooting](https://vinegarhq.org/Sober/Troubleshooting.html)
- [OpenPrinting IPP-over-USB](https://openprinting.github.io/projects/03-ipp-usb)
- [Flatpak single-file bundles](https://docs.flatpak.org/en/latest/single-file-bundles.html)

These pages are linked for documentation, not copied into the product. No Sober
upstream failure is represented as repaired without evidence from an affected
Client. Physical graphics and printer validation remain separate release gates.
