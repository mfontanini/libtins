// Example code taken from http://en.cppreference.com/w/cpp/utility/declval

#include <utility>
#include <iostream>
 
struct Default { int foo() const { return 1; } };
 
struct NonDefault
{
    NonDefault(const NonDefault&) { }
    int foo() const { return 1; }
};
 
int main()
{
    decltype(Default().foo()) n1 = 1;                   // type of n1 is int
    decltype(std::declval<NonDefault>().foo()) n2 = n1; // type of n2 is int
    return (n1 == 1 && n2 == 1) ? 0 : 1;
}