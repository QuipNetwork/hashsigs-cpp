# Add test executable
add_executable(hashsigs_tests
    wotsplus_test.cpp
)

# Copy test vectors to build directory
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vectors/wotsplus_keccak256.json
    ${CMAKE_CURRENT_BINARY_DIR}/wotsplus_keccak256.json
    COPYONLY
)

# Link against the library and GTest
target_link_libraries(hashsigs_tests
    PRIVATE
    hashsigs
    GTest::GTest
    GTest::Main
    nlohmann_json::nlohmann_json
)

# Add tests
add_test(NAME hashsigs_tests COMMAND hashsigs_tests)

# Set test properties
set_tests_properties(hashsigs_tests PROPERTIES
    ENVIRONMENT "GTEST_COLOR=1"
) 