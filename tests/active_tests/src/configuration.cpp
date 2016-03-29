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

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    #include <sys/param.h>
#endif

#include "configuration.h"

using std::string;

using Tins::NetworkInterface;

Configuration::Configuration() {
    #ifdef _WIN32
        current_platform_ = WINDOWS;
    #elif defined(BSD) || defined(__FreeBSD_kernel__)
        current_platform_ = BSD_OS;
    #else
        current_platform_ = LINUX;
    #endif
}

void Configuration::interface(const NetworkInterface& interface) {
    interface_ = interface;
}

void Configuration::source_port(uint16_t value) {
    source_port_ = value;
}

void Configuration::destination_port(uint16_t value) {
    destination_port_ = value;
}

const NetworkInterface& Configuration::interface() const {
    return interface_;
}

uint16_t Configuration::source_port() const {
    return source_port_;
}

uint16_t Configuration::destination_port() const {
    return destination_port_;
}

Configuration::Platform Configuration::current_platform() const {
    return current_platform_;
}
