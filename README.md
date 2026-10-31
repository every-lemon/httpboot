<p align="center"><img src="https://raw.githubusercontent.com/every-lemon/kagnode-logos/main/svg/http-boot-light.svg" width="440" alt="KagNode. HTTP Boot"></p>

# KagNode HTTP Boot

Open-source HTTP Boot Server, Builder and Client tooling. The Client boots an image delivered over the network with the project's existing activation, account, persistence and recovery workflows. Startup shows the KagNode symbol in blue when color is supported, with a plain text fallback for unattended consoles and `NO_COLOR`.

This repository is the public source export. It contains no private release images, signing secrets, Client credentials or saved user data. The existing local Server console is retained; no hosted cloud control plane is implied.

## Install and update

Read [installation instructions](docs/INSTALL-v2.md) before using the packages. Version **3.1.16-beta.2** is a branding/path preview. Existing 3.1.15 releases and their verification records remain in history. This preview does not replace a qualified desktop image or claim new physical hardware qualification.

New paths are under `/opt/kagnode/httpboot`, `/etc/kagnode/httpboot`, `/var/lib/kagnode/httpboot` and related Server/Builder project directories. Existing systems need the explicit migration procedure in [PATHS.md](PATHS.md). It preserves original data and compatibility links, can resume interrupted copies and supports rollback while retaining newer writes for review. No running Server, Builder, Client session or saved data is migrated by publishing source.

## Build and verify

Use Ubuntu 24.04 and the dependencies in the CI workflow. Build packages with `packaging/build-server-deb.py`; `packaging/public-source.py` creates an allowlisted source archive. Run `python3 -m unittest discover -s tests -p 'test_v2*.py' -v`. Image builds and hardware qualification are separate operations with their own resource requirements and evidence.

## License

Current combined release and new original work: **AGPL-3.0-only**. Earlier MIT-covered code retains the notice in `LICENSES/MIT-legacy.txt`; third-party code and fonts retain their own licenses. Prior MIT releases remain usable under their original grants. [Brand policy](BRAND-POLICY.md) does not forbid forks or rebranding permitted by software licensing.

[KagNode](https://nebulacoder.com) · [Developer](https://developer.nebulacoder.com) · [Logos](https://github.com/every-lemon/kagnode-logos)
