#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define radic_malloc(sz) malloc(sz)
#define radic_free(ptr) free(ptr)

typedef enum {

    radic_err_none = 0,
    radic_err_nullptr, // nullptr was encountered during execution
    radic_err_checksum, // checksum failed to validate
    radic_err_msgorder, // out-of-order message detected
    radic_err_memory, // out of memory
    radic_err_packet, // packet has invalid data

} radic_err_t;