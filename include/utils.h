#ifndef __UTILS_H
#define __UTILS_H


#include <string>
#include <stdint.h>

namespace Tins {
    /* Utils namespace. */
    namespace Utils {
        uint32_t ip_to_int(const std::string &ip);
        std::string ip_to_string(uint32_t ip);
    };
};

#endif
