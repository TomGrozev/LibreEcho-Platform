#!/usr/bin/env python3
"""Generate the microWakeWord operator translation unit and public header.

``micro_wake_word_operators.config`` is the only operator list. This script
turns it into one C++ translation unit that exports:

* ``libreecho::microwakeword::RegisterSupportedOps`` which registers exactly
  the listed operators on a ``tflite::MicroMutableOpResolver<N>``.
* ``le_mww_is_supported_operator``, a C-callable name check for the model
  validator, accepting either the resolver name or the TFLite builtin name.

Usage:
    generate_micro_wake_word_operators.py <config> <output-dir>

The output directory receives ``include/microwakeword/operators.h`` and
``src/operators.cc``.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

EXPECTED_OPERATOR_COUNT = 20
RESOLVER_NAME = re.compile(r"^[A-Z][A-Za-z0-9]*$")
TFLITE_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")

HEADER = """\
/* Generated from micro_wake_word_operators.config. Do not edit. */
#ifndef LIBREECHO_MICROWAKEWORD_OPERATORS_H_
#define LIBREECHO_MICROWAKEWORD_OPERATORS_H_

#ifdef __cplusplus
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"

namespace libreecho {{
namespace microwakeword {{

constexpr int kSupportedOperatorCount = {count};

// Registers every supported operator. Returns kTfLiteOk when all registrations
// succeed.
TfLiteStatus RegisterSupportedOps(
    ::tflite::MicroMutableOpResolver<kSupportedOperatorCount>& resolver);

}}  // namespace microwakeword
}}  // namespace libreecho

extern "C" {{
#endif

int le_mww_supported_operator_count(void);
int le_mww_is_supported_operator(const char* name);
const char* le_mww_supported_operator_name(int index);
const char* le_mww_supported_tflite_operator_name(int index);

#ifdef __cplusplus
}}
#endif

#endif  // LIBREECHO_MICROWAKEWORD_OPERATORS_H_
"""

SOURCE = """\
/* Generated from micro_wake_word_operators.config. Do not edit. */
#include "microwakeword/operators.h"

#include <cstring>

namespace {{
const char* const kResolverNames[] = {{
{resolver_names}
}};
const char* const kTfliteNames[] = {{
{tflite_names}
}};
}}  // namespace

namespace libreecho {{
namespace microwakeword {{

TfLiteStatus RegisterSupportedOps(
    ::tflite::MicroMutableOpResolver<kSupportedOperatorCount>& resolver) {{
  TfLiteStatus status = kTfLiteOk;
{registrations}
  return status;
}}

}}  // namespace microwakeword
}}  // namespace libreecho

extern "C" {{

int le_mww_supported_operator_count(void) {{
  return {count};
}}

int le_mww_is_supported_operator(const char* name) {{
  if (name == nullptr) {{
    return 0;
  }}
  for (int index = 0; index < {count}; ++index) {{
    if (std::strcmp(name, kResolverNames[index]) == 0 ||
        std::strcmp(name, kTfliteNames[index]) == 0) {{
      return 1;
    }}
  }}
  return 0;
}}

const char* le_mww_supported_operator_name(int index) {{
  if (index < 0 || index >= {count}) {{
    return nullptr;
  }}
  return kResolverNames[index];
}}

const char* le_mww_supported_tflite_operator_name(int index) {{
  if (index < 0 || index >= {count}) {{
    return nullptr;
  }}
  return kTfliteNames[index];
}}

}}  // extern "C"
"""


def load_operators(config: Path) -> list[tuple[str, str]]:
    operators: list[tuple[str, str]] = []
    seen_resolver: set[str] = set()
    seen_tflite: set[str] = set()
    for number, raw in enumerate(config.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2:
            raise ValueError(f"{config}:{number}: expected two columns")
        resolver_name, tflite_name = fields
        if not RESOLVER_NAME.fullmatch(resolver_name):
            raise ValueError(f"{config}:{number}: bad resolver name: {resolver_name}")
        if not TFLITE_NAME.fullmatch(tflite_name):
            raise ValueError(f"{config}:{number}: bad TFLite name: {tflite_name}")
        if resolver_name in seen_resolver or tflite_name in seen_tflite:
            raise ValueError(f"{config}:{number}: duplicate operator")
        seen_resolver.add(resolver_name)
        seen_tflite.add(tflite_name)
        operators.append((resolver_name, tflite_name))
    if len(operators) != EXPECTED_OPERATOR_COUNT:
        raise ValueError(
            f"{config}: expected {EXPECTED_OPERATOR_COUNT} operators, "
            f"found {len(operators)}"
        )
    return operators


def render(operators: list[tuple[str, str]]) -> tuple[str, str]:
    count = len(operators)
    resolver_names = "\n".join(f'    "{name}",' for name, _ in operators)
    tflite_names = "\n".join(f'    "{name}",' for _, name in operators)
    registrations = "\n".join(
        f"  if (status == kTfLiteOk) {{\n"
        f"    status = resolver.Add{name}();\n"
        f"  }}"
        for name, _ in operators
    )
    header = HEADER.format(count=count)
    source = SOURCE.format(
        count=count,
        resolver_names=resolver_names,
        tflite_names=tflite_names,
        registrations=registrations,
    )
    return header, source


def write_outputs(config: Path, output: Path) -> None:
    operators = load_operators(config)
    header, source = render(operators)
    include_dir = output / "include" / "microwakeword"
    source_dir = output / "src"
    include_dir.mkdir(parents=True, exist_ok=True)
    source_dir.mkdir(parents=True, exist_ok=True)
    (include_dir / "operators.h").write_text(header, encoding="utf-8")
    (source_dir / "operators.cc").write_text(source, encoding="utf-8")
    print(
        f"PASS operators_generated count={len(operators)} "
        f"header={include_dir / 'operators.h'}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    write_outputs(args.config, args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"FAIL operators_generated error={error}", file=sys.stderr)
        raise SystemExit(1) from error
