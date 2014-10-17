/*
 * Copyright (c) 2014, Matias Fontanini
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

#ifndef TINS_TIMESTAMP_H
#define TINS_TIMESTAMP_H

#ifdef WIN32
    #include <winsock2.h>
#else
    #include <sys/time.h>
#endif
#include "cxxstd.h"
#if TINS_IS_CXX11
    #include <chrono>
#endif

namespace Tins {
/**
 * \brief Represents a packet timestamp.
 */
class Timestamp {
public:
    #ifdef WIN32
        typedef long seconds_type;
        typedef long microseconds_type;
    #else
        typedef time_t seconds_type;
        typedef suseconds_t microseconds_type;
    #endif
    
    /**
     * \brief Constructs a Timestamp which will hold the current time.
     */
    static Timestamp current_time() {
        #ifdef WIN32
            //fixme
            return Timestamp();
        #else
            timeval tv;
            gettimeofday(&tv, 0);
            return tv;
        #endif
    }
    
    /**
     * Default constructs the timestamp.
     */
    Timestamp() : tv() {}

    #if TINS_IS_CXX11
        /**
         * Constructs a Timestamp from a std::chrono::duration.
         */
        template<typename Rep, typename Period>
        Timestamp(const std::chrono::duration<Rep, Period>& ts) {
            using std::chrono::duration_cast;
            using std::chrono::microseconds;
            using std::chrono::seconds;

            tv.tv_sec = duration_cast<seconds>(ts).count();
            tv.tv_usec = duration_cast<microseconds>(
                ts - seconds(tv.tv_sec)).count();
        }
    #endif
    
    /**
     * Constructs a timestamp from a timeval object.
     * \param time_val The timeval object.
     */
    Timestamp(const timeval &time_val) : tv(time_val) {}
    
    /**
     * Returns the amount of seconds in this timestamp.
     */
    seconds_type seconds() const {
        return tv.tv_sec;
    }
    
    /**
     * Returns the amount of microseconds in this timestamp.
     */
    microseconds_type microseconds() const {
        return tv.tv_usec;
    }
    
    #if TINS_IS_CXX11
        /**
         * Converts this Timestamp to a std::chrono::microseconds
         */
        operator std::chrono::microseconds() const {
            return std::chrono::seconds(seconds()) +
                std::chrono::microseconds(microseconds());
        }
    #endif
private:
    timeval tv;
};
}

#endif // TINS_TIMESTAMP_H
