# USB Checker

USB Checker guides a direct read-only safety check of a USB drive on a dedicated Linux host. It closes the kernel USB gate before insertion, checks USB device and interface classes, and runs bounded partition and malware triage on supported storage without making a media image. It writes local JSON and text reports.

## Install on the Linux host

Use Debian or Ubuntu on aarch64 or x86-64 with systemd and apt. Installation uses signed ClamAV 1.4.7 packages and distribution packages for Sleuth Kit. Definitions come from the ClamAV CDN through FreshClam.

```sh
base=https://github.com/patrick-1984/usb-checker/releases/download/v0.1.1
curl -fSLO "$base/install.sh"
curl -fSLO "$base/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
sudo sh ./install.sh
sudo usb-check doctor
```

## Check a USB drive

Leave the drive unplugged and start the guided check on the host. Insert one device directly when the checker says the gate is armed. Physically unplug it and type `removed` at the prompt.

```sh
sudo usb-check check
```

For example, if `orangepi3b` is your SSH host alias and you connect as root, allocate a terminal for the prompt.

```sh
ssh -t root@orangepi3b usb-check check
```

### Resume or finish a case

The job survives an SSH disconnect. After reconnecting to the host, use `gate-status` to find the held case ID. Replace the example ID below with the one from your check.

```sh
sudo usb-check gate-status
case_id=8df42193a7c80216
sudo usb-check status "$case_id"
```

Run the command that matches the case status and what is plugged in.

| Situation | Command |
|---|---|
| An incomplete case is `held` after an insertion timeout and exactly one new device is now connected directly. | `sudo usb-check resume "$case_id"` |
| The case status contains a result, even if the drive is still connected. | `sudo usb-check report "$case_id"` |
| The case is at `remove` or `held` and you physically unplugged the drive. | `sudo usb-check removed "$case_id"` |
| A completed case is `held`, the original drive is out, and one replacement is connected directly. | `sudo usb-check next "$case_id"` |

If you are replacing a drive and the case is still at `remove`, wait for it to reach `held` before running `next`. The removal wait lasts up to 10 minutes. Use the new case ID returned by `next` for later commands.

USB Checker deauthorizes a checked drive before showing the removal prompt. Keep the host powered on while the gate is held. A reboot resets the USB authorization policy.

## Plugin

In Claude Code, add the `patrick-1984/marketplace` marketplace, install `usb-checker@patrick-1984`, and ask it to check a USB drive on the prepared target. The repository also includes a Codex plugin manifest and MCP configuration. The plugin runs on the controller and connects to a local installation or via SSH using an existing trusted host key and root access or noninteractive sudo.

## Reports

Reports live in root-private directories under `/var/lib/usb-checker/cases`. Refresh definitions with `sudo usb-check update-signatures`.

The supported device has one configuration and one SCSI bulk-only mass-storage interface. USB hubs, composite devices, UAS-only devices, and multiple storage LUNs are refused. The Linux USB core reads descriptors and the approved storage driver reads sectors. The application excludes `/dev/sda`, previously present disks, mounted or claimed storage, and devices outside the approved interface. It opens the selected block device read-only and verifies the kernel read-only flag. USB Checker suppresses the host’s standard automount paths, rejects mounted or claimed storage, and holds an exclusive read-only descriptor during its check. Use a dedicated triage host without additional storage consumers. Linux creates the block node before the checker verifies the read-only flag.

Sleuth Kit and ClamAV run as an unprivileged dynamic user with IP networking disabled and read-only access to the one verified USB block device. The report covers the partition table, samples of unallocated gaps, and bounded scans of supported filesystems. Filesystem triage has a one-minute collection budget, up to 128 extraction attempts, 8 MiB per candidate and 32 MiB total. Scratch data uses tmpfs and follows the host’s swap policy. USB Checker retains the report and case status. Missing or stale definitions, unsupported filesystems, unreadable files and reached limits yield partial coverage. The tool does not execute files, upload data, or inspect USB firmware. `nothing-found` means these checks found no indicators.

The USB authorization design follows the [Linux kernel USB authorization documentation](https://docs.kernel.org/usb/authorization.html). The installer verifies ClamAV with the [Cisco Talos release signing key](https://docs.clamav.net/manual/Installing.html#verifying-clamavnet-downloads-with-gpg).
