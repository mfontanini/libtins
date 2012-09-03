#ifndef TINS_SMALL_UINT_H
#define TINS_SMALL_UINT_H

#include <stdint.h>
#include <stdexcept>

namespace Tins {
template<size_t n>
class small_uint {
private:
    template<bool cond, typename OnTrue, typename OnFalse>
    struct if_then_else {
        typedef OnTrue type;
    };

    template<typename OnTrue, typename OnFalse>
    struct if_then_else<false, OnTrue, OnFalse>  {
        typedef OnFalse type;
    };

    template<size_t i>
    struct best_type {
        typedef typename if_then_else<
            (i <= 8),
            uint8_t,
            typename if_then_else<
                (i <= 16),
                uint16_t,
                typename if_then_else<
                    (i <= 32),
                    uint32_t,
                    uint64_t
                >::type
            >::type
        >::type type;
    };
    
    template<uint64_t base, uint64_t pow>
    struct power {
        static const uint64_t value = base * power<base, pow - 1>::value;
    };
    
    template<uint64_t base>
    struct power<base, 0> {
        static const uint64_t value = 1;
    };
public:
    class value_to_large : public std::exception {
    public:
        const char *what() const throw() {
            return "Value is too large";
        }
    };

    typedef typename best_type<n>::type repr_type;
    static const repr_type max_value = power<2, n>::value - 1;
    
    small_uint() : value() {}
    
    small_uint(repr_type val) {
        if(val > max_value)
            throw value_to_large();
        value = val;
    }
    
    operator repr_type() const {
        return value;
    }
private:
    repr_type value;
};

} // namespace Tins
#endif // TINS_SMALL_UINT_H
