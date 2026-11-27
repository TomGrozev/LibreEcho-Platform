#!/usr/bin/env bash
set -euo pipefail

USAGE="usage: package_feature.sh <waked-binary> <models-root> <payload-out> <manifest-out>"
WAKED="${1:?$USAGE}"
MODELS_ROOT="${2:?$USAGE}"
PAYLOAD="${3:?$USAGE}"
MANIFEST="${4:?$USAGE}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
COMMON_LICENSE_DIR="$(dirname "$SCRIPT_DIR")/third-party-licenses"
PIPELINE_ROOT="${LIBREECHO_PIPELINE_ROOT:?ERROR: set LIBREECHO_PIPELINE_ROOT explicitly}"
PACKAGER="$PIPELINE_ROOT/package_feature_payload.sh"
MODEL_LICENSE="$SCRIPT_DIR/MICROWAKEWORD-LICENSE.txt"
MODEL_NOTICE="$SCRIPT_DIR/MICROWAKEWORD-NOTICE.txt"

# microWakeWord model files are published by the pinned micro-wake-word-models
# source. The two models the daemon always loads are hash-pinned so a stale or
# substituted pair cannot ship silently; other staged models are installed as
# present because the owner picks those at runtime.
declare -A REVIEWED_MODEL_SHA256=(
  [alexa]=9011a8155b04de858c48038529235cbc0e42e9fca05a55bf588cb80a653a723b
  [vad]=7aa4db6d5fb7c5358609f6931e7847d303c16a43d178638bc14104f50d7eff5f
)

for input in "$WAKED" "$MODEL_LICENSE" "$MODEL_NOTICE"; do
  [[ -f "$input" && ! -L "$input" ]] || {
    echo "ERROR: wakeword input is missing or is a symlink: $input" >&2
    exit 1
  }
done
[[ -d "$MODELS_ROOT" && ! -L "$MODELS_ROOT" ]] || {
  echo "ERROR: wakeword models root is missing or is a symlink: $MODELS_ROOT" >&2
  exit 1
}
[[ -d "$COMMON_LICENSE_DIR" && ! -L "$COMMON_LICENSE_DIR" ]] || {
  echo "ERROR: common wakeword runtime license bundle is missing" >&2
  exit 1
}
[[ -x "$PACKAGER" ]] || {
  echo "ERROR: feature packager is missing: $PACKAGER" >&2
  exit 1
}

file -b "$WAKED" | grep -Eq 'ELF 32-bit.*ARM.*statically linked' || {
  echo "ERROR: wakeword daemon is not a static ARM32 executable" >&2
  exit 1
}
if readelf -l "$WAKED" | grep -q 'Requesting program interpreter'; then
  echo "ERROR: wakeword daemon has a dynamic interpreter" >&2
  exit 1
fi

models=()
shopt -s nullglob
for entry in "$MODELS_ROOT"/*; do
  [[ -L "$entry" ]] && {
    echo "ERROR: wakeword model entry is a symlink: $entry" >&2
    exit 1
  }
  [[ -d "$entry" ]] || {
    echo "ERROR: wakeword models root holds a non-directory entry: $entry" >&2
    exit 1
  }
  name="$(basename -- "$entry")"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
    echo "ERROR: invalid microWakeWord model name: $name" >&2
    exit 1
  }
  for extension in tflite json; do
    [[ -f "$entry/$name.$extension" && ! -L "$entry/$name.$extension" ]] || {
      echo "ERROR: microWakeWord model $name lacks a regular $name.$extension" >&2
      exit 1
    }
  done
  tflite_size="$(stat -c %s "$entry/$name.tflite")"
  [[ "$tflite_size" -ge 1024 && "$tflite_size" -le 8388608 ]] || {
    echo "ERROR: microWakeWord model $name.tflite is outside the accepted size" >&2
    exit 1
  }
  # A FlatBuffer TFLite model carries the "TFL3" identifier after its root
  # offset; a mislabelled .tflite would otherwise reach the device and fail at
  # load time.
  [[ "$(dd if="$entry/$name.tflite" bs=1 skip=4 count=4 2>/dev/null)" == TFL3 ]] || {
    echo "ERROR: microWakeWord model $name.tflite is not a TFLite FlatBuffer" >&2
    exit 1
  }
  if [[ -n "${REVIEWED_MODEL_SHA256[$name]:-}" ]]; then
    [[ "$(sha256sum "$entry/$name.tflite" | awk '{print $1}')" == \
       "${REVIEWED_MODEL_SHA256[$name]}" ]] || {
      echo "ERROR: microWakeWord model $name.tflite is not the reviewed model" >&2
      exit 1
    }
  fi
  models+=("$name")
done
for required in alexa vad; do
  [[ -d "$MODELS_ROOT/$required" ]] || {
    echo "ERROR: required microWakeWord model is missing: $required" >&2
    exit 1
  }
done

root="$(mktemp -d /tmp/libreecho-wakeword-feature.XXXXXX)"
trap 'rm -rf "$root"' EXIT
model_root="$root/usr/local/share/libreecho/wakeword"
license_root="$root/usr/local/share/licenses/libreecho-microwakeword"
runtime_license_root="$license_root/runtime"
install -d "$root/usr/local/sbin" "$model_root" "$license_root" \
  "$runtime_license_root"
install -m 0755 "$WAKED" "$root/usr/local/sbin/libreecho-waked"
for name in "${models[@]}"; do
  install -d "$model_root/$name"
  install -m 0644 "$MODELS_ROOT/$name/$name.tflite" \
    "$model_root/$name/$name.tflite"
  install -m 0644 "$MODELS_ROOT/$name/$name.json" \
    "$model_root/$name/$name.json"
done
install -m 0644 "$MODEL_LICENSE" "$license_root/LICENSE.txt"
install -m 0644 "$MODEL_NOTICE" "$license_root/NOTICE.txt"
for notice in RUNTIME-NOTICES.txt SpeexDSP-COPYING.txt; do
  [[ -f "$COMMON_LICENSE_DIR/$notice" && \
     ! -L "$COMMON_LICENSE_DIR/$notice" ]] || {
    echo "ERROR: common runtime license input is missing: $notice" >&2
    exit 1
  }
  install -m 0644 "$COMMON_LICENSE_DIR/$notice" \
    "$runtime_license_root/$notice"
done

"$PACKAGER" wakeword "$root" "$PAYLOAD" "$MANIFEST"
