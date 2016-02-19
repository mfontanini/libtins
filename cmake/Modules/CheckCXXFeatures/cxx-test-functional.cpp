#include <functional>

int add(int x, int y) {
    return x + y;
}

int main() {
    std::function<int(int, int)> func;
    func = std::bind(&add, std::placeholders::_1, std::placeholders::_2);
    return (func(2, 2) == 4) ? 0 : 1;
}