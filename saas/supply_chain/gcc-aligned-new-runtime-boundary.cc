// Runtime regression cases from GCC commit
// 59d235ffa5a69231eb42e5290d52dc8c90d28b7a (CVE-2026-95619).
#include <cassert>
#include <cstdint>
#include <new>

static void check(std::size_t size, std::size_t alignment) {
  auto align = static_cast<std::align_val_t>(alignment);
  bool rejected = false;
  try {
    void* result = ::operator new(size, align);
    ::operator delete(result, align);
  } catch (const std::bad_alloc&) {
    rejected = true;
  }
  assert(rejected);
  void* result = ::operator new(size, align, std::nothrow);
  assert(result == nullptr);
}

int main() {
  check(static_cast<std::size_t>(-9), 32);
  check(SIZE_MAX, 8);
  check(SIZE_MAX, 32);
  check(SIZE_MAX, 1024);
  check(SIZE_MAX, 65536);
  check(SIZE_MAX - 1, 16);
  check(SIZE_MAX - 1025, 1024);
  check(SIZE_MAX - 1024, 1024);
  check(SIZE_MAX - 65536, 65536);
}
