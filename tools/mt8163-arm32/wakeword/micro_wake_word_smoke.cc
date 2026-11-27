// Loads one microWakeWord .tflite model with the archives built by
// build_micro_wake_word.sh, allocates its tensors in a caller-sized arena and
// runs one invoke. Used by test_build_micro_wake_word.py under qemu-arm.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "microwakeword/operators.h"
#include "tensorflow/lite/micro/micro_allocator.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/micro/micro_resource_variable.h"
#include "tensorflow/lite/micro/schema/schema_generated.h"

namespace {

bool ReadFile(const char* path, std::vector<uint8_t>* bytes) {
  FILE* file = std::fopen(path, "rb");
  if (file == nullptr) {
    std::fprintf(stderr, "cannot open %s\n", path);
    return false;
  }
  if (std::fseek(file, 0, SEEK_END) != 0) {
    std::fclose(file);
    return false;
  }
  const long size = std::ftell(file);
  if (size <= 0 || std::fseek(file, 0, SEEK_SET) != 0) {
    std::fclose(file);
    return false;
  }
  bytes->resize(static_cast<size_t>(size));
  const size_t read = std::fread(bytes->data(), 1, bytes->size(), file);
  std::fclose(file);
  return read == bytes->size();
}

const char* BaseName(const char* path) {
  const char* slash = std::strrchr(path, '/');
  return slash == nullptr ? path : slash + 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s <tensor-arena-bytes> <model.tflite>\n",
                 argv[0]);
    return 2;
  }
  char* end = nullptr;
  const unsigned long arena_size = std::strtoul(argv[1], &end, 10);
  if (end == argv[1] || *end != '\0' || arena_size == 0) {
    std::fprintf(stderr, "bad arena size: %s\n", argv[1]);
    return 2;
  }

  std::vector<uint8_t> model_bytes;
  if (!ReadFile(argv[2], &model_bytes)) {
    return 1;
  }
  const tflite::Model* model = tflite::GetModel(model_bytes.data());
  if (model == nullptr || model->version() != 3) {
    std::fprintf(stderr, "not a TFLite v3 model: %s\n", argv[2]);
    return 1;
  }

  const auto* operator_codes = model->operator_codes();
  if (operator_codes == nullptr) {
    std::fprintf(stderr, "model has no operator codes\n");
    return 1;
  }
  for (unsigned int index = 0; index < operator_codes->size(); ++index) {
    const auto* code = operator_codes->Get(index);
    const char* name = tflite::EnumNameBuiltinOperator(
        static_cast<tflite::BuiltinOperator>(code->builtin_code()));
    if (name == nullptr || le_mww_is_supported_operator(name) == 0) {
      std::fprintf(stderr, "unsupported operator in model: %s\n",
                   name == nullptr ? "<unknown>" : name);
      return 1;
    }
  }

  tflite::MicroMutableOpResolver<libreecho::microwakeword::kSupportedOperatorCount>
      resolver;
  if (libreecho::microwakeword::RegisterSupportedOps(resolver) != kTfLiteOk) {
    std::fprintf(stderr, "operator registration failed\n");
    return 1;
  }

  std::vector<uint8_t> arena(arena_size);
  tflite::MicroAllocator* allocator =
      tflite::MicroAllocator::Create(arena.data(), arena.size());
  if (allocator == nullptr) {
    std::fprintf(stderr, "cannot create allocator\n");
    return 1;
  }
  tflite::MicroResourceVariables* variables =
      tflite::MicroResourceVariables::Create(allocator, 8);
  if (variables == nullptr) {
    std::fprintf(stderr, "cannot create resource variables\n");
    return 1;
  }
  tflite::MicroInterpreter interpreter(model, resolver, allocator, variables,
                                       nullptr);
  if (interpreter.AllocateTensors() != kTfLiteOk) {
    std::fprintf(stderr, "AllocateTensors failed in %lu bytes\n", arena_size);
    return 1;
  }
  TfLiteTensor* input = interpreter.input(0);
  if (input == nullptr) {
    std::fprintf(stderr, "model has no input tensor\n");
    return 1;
  }
  std::memset(input->data.raw, 0, input->bytes);
  if (interpreter.Invoke() != kTfLiteOk) {
    std::fprintf(stderr, "Invoke failed\n");
    return 1;
  }
  const TfLiteTensor* output = interpreter.output(0);
  if (output == nullptr || output->bytes == 0) {
    std::fprintf(stderr, "model has no output tensor\n");
    return 1;
  }
  std::printf("model=%s arena_size=%lu arena_used=%zu operators=%d\n",
              BaseName(argv[2]), arena_size, interpreter.arena_used_bytes(),
              le_mww_supported_operator_count());
  return 0;
}
