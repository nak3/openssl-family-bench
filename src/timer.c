#include "ofb/bench.h"

#if defined(_WIN32)
#include <windows.h>

uint64_t
ofb_now_ns(void)
{
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;

    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t) (counter.QuadPart / frequency.QuadPart) * 1000000000ULL +
           (uint64_t) (counter.QuadPart % frequency.QuadPart) * 1000000000ULL /
               (uint64_t) frequency.QuadPart;
}
#else
#include <time.h>

uint64_t
ofb_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t) now.tv_sec * 1000000000ULL + (uint64_t) now.tv_nsec;
}
#endif
