/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <sys/time.h>
#endif
#include "timestamp.h"

namespace Tins {

const int MICROSECONDS_IN_SECOND = 1000000;

Timestamp Timestamp::current_time() {
    #ifdef _WIN32
        FILETIME file_time;
        GetSystemTimeAsFileTime(&file_time);
        uint64_t timestamp = file_time.dwHighDateTime;
        timestamp = timestamp << 32;
        timestamp |= file_time.dwLowDateTime;
        // Convert to microseconds
        timestamp /= 10;
        // Change the epoch to POSIX epoch
        timestamp -= 11644473600000000ULL;
        return Timestamp(timestamp);
    #else
        timeval tv;
        gettimeofday(&tv, 0);
        return tv;
    #endif
}

Timestamp::Timestamp()
: timestamp_(0) {

}

Timestamp::Timestamp(const timeval& time_val) {
    timestamp_ = static_cast<uint64_t>(time_val.tv_sec) * MICROSECONDS_IN_SECOND
                 + time_val.tv_usec;
}

Timestamp::Timestamp(uint64_t value)
: timestamp_(value) {

}

Timestamp::seconds_type Timestamp::seconds() const {
    return static_cast<seconds_type>(timestamp_ / MICROSECONDS_IN_SECOND);
}

Timestamp::microseconds_type Timestamp::microseconds() const {
    return timestamp_ % MICROSECONDS_IN_SECOND;
}

} // Tins
