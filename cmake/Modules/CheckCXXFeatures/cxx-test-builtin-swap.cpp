#include <stdint.h>

int main() {
    uint16_t u16 = __builtin_bswap16(0x9812U);
    uint32_t u32 = __builtin_bswap32(0x9812ad81U);
    uint64_t u64 = __builtin_bswap64(0x9812ad81f61a890dU);
    return (u16 > 0 && u32 > 0 && u64 > 0) ? 0 : 1;
}