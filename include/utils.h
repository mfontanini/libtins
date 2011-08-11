#ifndef __UTILS_H
#define __UTILS_H


#include <string>
#include <stdint.h>

namespace Tins {
    /* Utils namespace. */
    namespace Utils {
        uint32_t ip_to_int(const std::string &ip);
        std::string ip_to_string(uint32_t ip);

        uint32_t resolve_ip(const std::string &to_resolve);

        inline uint32_t net_to_host_l(uint32_t address) {
            return (((address & 0xff000000) >> 24) | ((address & 0x00ff0000) >> 8)  |
                    ((address & 0x0000ff00) << 8)  | ((address & 0x000000ff) << 24));
        }

        inline uint32_t net_to_host_s(uint16_t address) {
            return ((address & 0xff00) >> 8)  | ((address & 0x00ff) << 8);
        }
    };
};

#endif
