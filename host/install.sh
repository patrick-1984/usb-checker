#!/bin/sh
set -eu
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
if [ "$(id -u)" != 0 ]; then
    echo "Run this installer with sudo." >&2
    exit 1
fi
if [ "$(uname -s)" != Linux ] || [ ! -x /usr/bin/apt-get ]; then
    echo "USB Checker requires Linux with apt and systemd." >&2
    exit 1
fi
case "$(uname -m)" in
    aarch64)
        clam_arch=aarch64; clam_digest=5b2cc6dc1b33847736fa86bb1293afc462241cdecbb6a9f64b434dd90b1ac214
        deb_arch=arm64; triplet=aarch64-linux-gnu; loader=ld-linux-aarch64.so.1
        libc_digest=01f4330719fd4f65580e16ea5a0527f372fca750e8f588d26deaf09f2d3b1cf4 ;;
    x86_64)
        clam_arch=x86_64; clam_digest=3bbb8ac72e9f9238d51ec6d52d8c34ab78967061ce6d15908fcbe4c4fb2bea3a
        deb_arch=amd64; triplet=x86_64-linux-gnu; loader=ld-linux-x86-64.so.2
        libc_digest=ba4f88f73dbc3ae9055f3c20f4523bfdbaf1ad13ff95e258924f77d20b4fbedf ;;
    *) echo "USB Checker supports aarch64 and x86_64." >&2; exit 1 ;;
esac
stage=$(mktemp -d)
link_stage=
release_stage=
trap 'find "$stage" -depth -delete; if [ -n "$link_stage" ]; then find "$link_stage" -depth -delete; fi; if [ -n "$release_stage" ]; then find "$release_stage" -depth -delete; fi' EXIT
trap 'exit 1' HUP INT TERM
case "${1:-}" in
    --local)
        src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
        payload_digest=$(cd "$src" && sha256sum usb-check usb_checker/*.py | sha256sum | cut -d ' ' -f 1)
        ;;
    "") 
        sed '1,/^__USB_CHECKER_PAYLOAD__$/d' "$0" | base64 -d > "$stage/source.tar.gz"
        payload_digest='@PAYLOAD_SHA256@'
        printf '%s  %s\n' "$payload_digest" "$stage/source.tar.gz" | sha256sum -c -
        tar -xzf "$stage/source.tar.gz" -C "$stage"
        src="$stage"
        ;;
    *) echo "Usage: install.sh" >&2; exit 1 ;;
esac
state=/run/usb-checker
install -d -m 0700 "$state"
exec 9>"$state/lock"
flock -n 9 || { echo "A USB Checker job is running." >&2; exit 1; }
if [ -e "$state/gate.json" ]; then
    echo "Restore the USB gate before updating. Run usb-check gate-status." >&2
    exit 1
fi
cli=/usr/local/bin/usb-check
if [ -e "$cli" ] || [ -L "$cli" ]; then
    case "$(readlink "$cli" || true)" in
        /opt/usb-checker/releases/*/usb-check) ;;
        *) echo "An unmanaged usb-check command already exists." >&2; exit 1 ;;
    esac
fi
if ! dpkg-query -W -f='${Status}\n' python3 sleuthkit curl ca-certificates gpgv 2>/dev/null | awk '
    $0 == "install ok installed" { n++ } END { exit n != 5 }'; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 sleuthkit curl ca-certificates gpgv
fi
if ! command -v gpg >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gpg
fi
clam_version=1.4.7
base=/opt/usb-checker
clam_dir="$base/clamav/$clam_version"
clam_package="clamav-$clam_version.linux.$clam_arch.deb"
clam_url="https://github.com/Cisco-Talos/clamav/releases/download/clamav-$clam_version/$clam_package"
install -d -m 0755 "$base/clamav" "$base/releases"
install -d -m 0711 /var/lib/usb-checker
install -d -m 0700 /var/lib/usb-checker/cases
getent passwd usb-checker-db >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin usb-checker-db
install -d -m 0755 -o usb-checker-db /var/lib/usb-checker/definitions
if ! test -x "$clam_dir/usr/local/bin/clamscan"; then
    curl --proto '=https' -fSsL --max-time 600 "$clam_url" -o "$stage/clamav.deb"
    curl --proto '=https' -fSsL --max-time 60 "$clam_url.sig" -o "$stage/clamav.deb.sig"
    printf '%s  %s\n' "$clam_digest" "$stage/clamav.deb" | sha256sum -c -
    install -d -m 0700 "$stage/gnupg"
    gpg --batch --homedir "$stage/gnupg" --dearmor --output "$stage/talos.gpg" "$src/cisco-talos.asc"
    gpgv --homedir "$stage/gnupg" --keyring "$stage/talos.gpg" "$stage/clamav.deb.sig" "$stage/clamav.deb"
    dpkg-deb -x "$stage/clamav.deb" "$stage/clamav"
    if ! LD_LIBRARY_PATH="$stage/clamav/usr/local/lib" "$stage/clamav/usr/local/bin/clamscan" --version 2>"$stage/loader-error"; then
        grep -q GLIBC_ "$stage/loader-error" || { cat "$stage/loader-error" >&2; exit 1; }
        curl --proto '=https' -fSsL --max-time 120 \
            "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u14_${deb_arch}.deb" -o "$stage/libc.deb"
        printf '%s  %s\n' "$libc_digest" "$stage/libc.deb" | sha256sum -c -
        dpkg-deb -x "$stage/libc.deb" "$stage/compat"
        mv "$stage/compat/lib/$triplet" "$stage/clamav/usr/local/compat"
        "$stage/clamav/usr/local/compat/$loader" --library-path \
            "$stage/clamav/usr/local/lib:$stage/clamav/usr/local/compat" "$stage/clamav/usr/local/bin/clamscan" --version
    fi
    mv -T "$stage/clamav" "$clam_dir"
fi
version=0.1.0
release="$base/releases/$version-$payload_digest"
if [ ! -d "$release" ]; then
    release_stage=$(mktemp -d "$base/releases/.candidate.XXXXXX")
    chmod 0755 "$release_stage"
    install -d -m 0755 "$release_stage/usb_checker"
    for source in "$src"/usb_checker/*.py; do
        install -m 0644 "$source" "$release_stage/usb_checker/"
    done
    install -m 0755 "$src/usb-check" "$release_stage/usb-check"
    "$release_stage/usb-check" doctor
    mv -T "$release_stage" "$release"
    release_stage=
else
    for source in "$src"/usb_checker/*.py; do
        cmp -s "$source" "$release/usb_checker/${source##*/}" ||
            { echo "The staged USB Checker package differs from the installer payload." >&2; exit 1; }
    done
    cmp -s "$src/usb-check" "$release/usb-check" ||
        { echo "The staged USB Checker command differs from the installer payload." >&2; exit 1; }
    "$release/usb-check" doctor
fi
link_stage=$(mktemp -d /usr/local/bin/.usb-check.XXXXXX)
ln -s "$release/usb-check" "$link_stage/usb-check"
mv -fT "$link_stage/usb-check" "$cli"
flock -u 9
"$cli" update-signatures || echo "Definitions could not be refreshed. See usb-check doctor." >&2
"$cli" doctor
