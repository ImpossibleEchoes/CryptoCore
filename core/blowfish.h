#pragma once

#include "utils.h"

#include <cstdint>

int process_file_blowfish_internal(const char* in_path, const char* out_path, const uint8_t* key, int key_len, int is_encrypt, ProgressCallback callback);