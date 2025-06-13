# hashsigs-cpp

A C++ implementation of WOTS+ (Winternitz One-Time Signature) scheme.

## Building

To build the library:

```bash
mkdir build
cd build
cmake ..
make
```

For release build:

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Testing

Run all tests:

```bash
cd build
make test
```

Or run the test executable directly:

```bash
./tests/wotsplus_test
```

For test output and backtrace:

```bash
GTEST_COLOR=1 ./tests/wotsplus_test --gtest_color=yes
```

## Development Requirements

- CMake 3.10 or higher
- C++17 or higher
- Google Test
- nlohmann/json

## Project Structure

```
.
├── include/       # Header files
│   ├── constants.hpp
│   ├── public_key.hpp
│   └── wotsplus.hpp
├── src/          # Implementation files
│   ├── keccak.cpp
│   └── wotsplus.cpp
└── tests/        # Test vectors and unit tests
    ├── wotsplus_test.cpp
    └── test_vectors/
```

## License

AGPL-3.0, see LICENSE
