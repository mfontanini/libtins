#include <chrono>

using namespace std::chrono;

int main() {
    system_clock::time_point tp = system_clock::now();
    milliseconds ms = duration_cast<milliseconds>(tp.time_since_epoch());
    return (ms.count() > 0) ? 0 : 1;
}