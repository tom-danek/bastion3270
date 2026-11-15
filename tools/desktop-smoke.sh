#!/usr/bin/env bash
# Starts the Linux desktop client inside a container of an older distribution under a virtual X
# display and checks that it opens its window. Used by the release workflow on the built binary;
# runs locally the same way:
#
#   tools/desktop-smoke.sh target/x86_64-unknown-linux-gnu/release/bastion3270-gui rockylinux/rockylinux:8
#
# Needs docker or podman. Exit status 0 = the window was open and the client still ran after
# several seconds.
set -euo pipefail

binary=$(realpath "$1")
image=$2
engine=$(command -v docker || command -v podman)

# The script that runs inside the container: graphics libraries the client loads at run time,
# Xvfb with Mesa's software OpenGL, then the client for 10 seconds.
inner=$(cat <<'EOF'
set -u
. /etc/os-release
case "$ID" in
  debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq xvfb x11-utils libgl1 libegl1 libgl1-mesa-dri libxkbcommon-x11-0 \
      libxcursor1 libxi6 libxrandr2 libx11-xcb1 > /dev/null ;;
  *)
    dnf install -y -q xorg-x11-server-Xvfb mesa-dri-drivers mesa-libEGL mesa-libGL \
      libxkbcommon-x11 libXcursor libXi libXrandr > /dev/null
    dnf install -y -q xwininfo > /dev/null 2>&1 || dnf install -y -q xorg-x11-utils > /dev/null ;;
esac
echo "$PRETTY_NAME, $(ldd --version | head -1)"
Xvfb :99 -screen 0 1280x1024x24 > /tmp/xvfb.log 2>&1 &
sleep 2
export DISPLAY=:99
timeout 10 /app/bastion3270-gui > /tmp/client.log 2>&1 &
client=$!
sleep 7
window=$(xwininfo -root -tree | grep -c '"bastion3270"' || true)
status=0
wait "$client" || status=$?
cat /tmp/client.log
# 124: still running when `timeout` stopped it.
if [ "$window" -ge 1 ] && [ "$status" -eq 124 ]; then
  echo "OK: the window was open and the client was still running"
else
  echo "FAILED: window found $window time(s), client exit status $status"
  exit 1
fi
EOF
)

"$engine" run --rm -v "$binary:/app/bastion3270-gui:ro" "$image" bash -c "$inner"
