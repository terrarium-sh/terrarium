#!/bin/sh
# Installs terra from beside this script, without the network.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! [ -f "$here/terra" ]; then
  echo "terrarium: $here does not contain terra - run this script from the extracted release archive" >&2
  exit 1
fi

bin=/usr/local/bin
if [ "$(uname -s)" = Darwin ] && [ -d /opt/homebrew/bin ]; then
  bin=/opt/homebrew/bin
fi

if [ -e "$bin/terra" ] && ! [ -f "$bin/terra" ] && ! [ -L "$bin/terra" ]; then
  echo "terrarium: $bin/terra exists but is not a regular file - move it aside first" >&2
  exit 1
fi
if install -d "$bin" 2>/dev/null &&
   install -m 755 "$here/terra" "$bin/terra" 2>/dev/null; then
  :
else
  printf 'install to %s needs root privileges - run sudo install? [y/N] ' "$bin"
  { read -r answer </dev/tty; } 2>/dev/null || answer=
  case "$answer" in
    y | Y | yes | Yes)
      sudo=$(command -v sudo || true)
      if [ -z "$sudo" ]; then
        echo "terrarium: sudo is unavailable" >&2
        exit 1
      fi
      "$sudo" install -d "$bin" &&
        "$sudo" install -m 755 "$here/terra" "$bin/terra"
      ;;
    *)
      echo "installation was not completed" >&2
      exit 1
      ;;
  esac
fi
installed_version=$("$bin/terra" --version 2>/dev/null || true)
echo "installed ${installed_version:-terra} at $bin/terra"
