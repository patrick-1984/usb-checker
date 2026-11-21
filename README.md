# USB Checker

USB Checker guides a direct read-only safety check of a USB drive on a dedicated Linux host. It closes the kernel USB gate before insertion, checks USB device and interface classes, and runs bounded partition and malware triage on supported storage without making a media image. It writes local JSON and text reports.

## Install on the Linux host

Use Debian or Ubuntu on aarch64 or x86-64 with systemd and apt. Installation uses signed ClamAV 1.4.7 packages and distribution packages for Sleuth Kit. Definitions come from the ClamAV CDN through FreshClam.

```sh
base=https://github.com/patrick-1984/usb-checker/releases/download/v0.1.0
curl -fSLO "$base/install.sh"
curl -fSLO "$base/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
sudo sh ./install.sh
sudo usb-check doctor
```

## Check a USB drive

Leave the drive unplugged and run `sudo usb-check check` on the host. For an SSH target, allocate a terminal with `ssh -t`. Insert one device directly when the checker says the gate is armed. After the direct check or refusal, physically unplug the device and type `removed` when prompted. Leave the host powered on while the gate is held.

```sh
sudo usb-check check
```

The job survives an SSH disconnect. Use `sudo usb-check gate-status` and `sudo usb-check status CASE` to recover. If insertion times out and the device is connected later, run `sudo usb-check resume CASE` to check the one new device under the original gate. USB Checker deauthorizes the device once the check finishes. The report is available before removal. Physically remove the device before running `sudo usb-check removed CASE` to restore USB. Its journal stays under `/run/usb-checker` until restoration. Device authorization resets under normal host boot policy.

## Plugin

In Claude Code, add the `patrick-1984/marketplace` marketplace, install `usb-checker@patrick-1984`, and ask it to check a USB drive on the prepared target. The repository also includes a Codex plugin manifest and MCP configuration. The plugin runs on the controller and connects to a local installation or via SSH using an existing trusted host key and root access or noninteractive sudo.

## Reports

Reports live in root-private directories under `/var/lib/usb-checker/cases`. Read a report with `sudo usb-check report CASE` and refresh definitions with `sudo usb-check update-signatures`.

The supported device has one configuration and one SCSI bulk-only mass-storage interface. USB hubs, composite devices, UAS-only devices, and multiple storage LUNs are refused. The Linux USB core reads descriptors and the approved storage driver reads sectors. The application excludes `/dev/sda`, previously present disks, mounted or claimed storage, and devices outside the approved interface. It opens the selected block device read-only and verifies the kernel read-only flag. USB filesystems remain unmounted.

Sleuth Kit and ClamAV run as an unprivileged dynamic user with IP networking disabled and read-only access to the one verified USB block device. The report covers the partition table, samples of unallocated gaps, and bounded scans of supported filesystems. The scanner uses RAM scratch for up to 128 files, 8 MiB per file and 32 MiB total. It retains only the report and case status. Missing or stale definitions, unsupported filesystems, unreadable files and reached limits yield partial coverage. The tool does not execute files, upload data, or inspect USB firmware. `nothing-found` means these checks found no indicators.

The USB authorization design follows the [Linux kernel USB authorization documentation](https://docs.kernel.org/usb/authorization.html). The installer verifies ClamAV with the [Cisco Talos release signing key](https://docs.clamav.net/manual/Installing.html#verifying-clamavnet-downloads-with-gpg).
