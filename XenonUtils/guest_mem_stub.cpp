#include <cstdint>

extern "C" uint8_t* MmGetGuestBase()
{
    // Tools don’t run the runtime guest memory; report null base.
    return nullptr;
}

extern "C" uint64_t MmGetGuestLimit()
{
    // Full 32-bit guest address space.
    return 0x100000000ull;
}

