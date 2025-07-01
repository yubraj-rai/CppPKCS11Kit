cmake_minimum_required(VERSION 3.10)
project(CppPKCS11Kit CXX)

# Set C++ Standard to C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define variables for PKCS#11 library path and user PIN
# These will be passed from the command line:
# cmake .. -DPKCS11_LIBRARY_PATH_VAR="/usr/lib/softhsm/libsofthsm2.so" -DUSER_PIN_VAR="1234"
option(PKCS11_LIBRARY_PATH_VAR "Path to the PKCS#11 shared library (e.g., /usr/lib/softhsm/libsofthsm2.so)" "")
option(USER_PIN_VAR "User PIN for the PKCS#11 token" "")

if(NOT PKCS11_LIBRARY_PATH_VAR)
    message(FATAL_ERROR "PKCS11_LIBRARY_PATH_VAR is not set. Please provide the path to your PKCS#11 library. Example: cmake .. -DPKCS11_LIBRARY_PATH_VAR=\"/usr/lib/softhsm/libsofthsm2.so\"")
endif()

if(NOT USER_PIN_VAR)
    message(FATAL_ERROR "USER_PIN_VAR is not set. Please provide the user PIN for your PKCS#11 token. Example: cmake .. -DUSER_PIN_VAR=\"1234\"")
endif()

# Configure app_config.h from app_config.h.in
configure_file(
    ${CMAKE_SOURCE_DIR}/config/app_config.h.in
    ${CMAKE_BINARY_DIR}/app_config.h
)

# Add include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR} # For the generated app_config.h
    /usr/include/softhsm/ # Path to pkcs11.h on Ubuntu with libsofthsm2-dev
    # Add any other necessary include paths for PKCS#11 headers if they are not system-wide
)

# Find necessary libraries
find_package(Threads REQUIRED) # For thread support

# Add the main application executable
add_executable(${PROJECT_NAME}
    src/main.cpp
    src/core/pkcs11_wrapper.cpp
    src/core/crypto_manager.cpp
    src/utils/hex_utils.cpp
)

# Link main application libraries
target_link_libraries(${PROJECT_NAME}
    Threads::Threads
    ${PKCS11_LIBRARY_PATH_VAR} # Link against the specified PKCS#11 library
)

# Set output directory for executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add compiler flags for warnings and optimizations (good for production)
if(CMAKE_CXX_COMPILER_ID MATCHES "(GNU|Clang)")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror # Treat warnings as errors in production
        -O2 # Optimization level 2
        # -D_GLIBCXX_DEBUG # Enable debug checks for STL (useful during development, but can impact performance)
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4 # Warning level 4
        /WX # Treat warnings as errors
        /O2 # Optimization level 2
    )
endif()

# --- Google Test Integration ---
option(BUILD_TESTS "Build the test executable" ON) # Option to enable/disable tests

if(BUILD_TESTS)
    enable_testing() # Enable CTest

    # Find Google Test
    # If GTest is not found system-wide, CMake will try to download it
    find_package(GTest CONFIG REQUIRED)
    # IMPORTANT: Explicitly include the GoogleTest module to make its commands available
    include(GoogleTest)

    # Add the test executable
    add_executable(crypto_tests
        test/crypto_tests.cpp
        src/core/pkcs11_wrapper.cpp # Link source files directly for tests
        src/core/crypto_manager.cpp
        src/utils/hex_utils.cpp
    )

    # Link test executable to Google Test and project's own libraries
    target_link_libraries(crypto_tests
        GTest::gtest_main # Links gtest and gtest_main
        Threads::Threads
        ${PKCS11_LIBRARY_PATH_VAR}
    )

    # Ensure tests can find generated config header
    target_include_directories(crypto_tests PRIVATE ${CMAKE_BINARY_DIR})

    # Add compiler flags for tests (can be different from main app if needed)
    if(CMAKE_CXX_COMPILER_ID MATCHES "(GNU|Clang)")
        target_compile_options(crypto_tests PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            # -Werror # Tests might intentionally trigger warnings, so -Werror is often disabled for tests
            -O0 # No optimization for easier debugging of tests
            -D_GLIBCXX_DEBUG # Enable debug checks for STL in tests
        )
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        target_compile_options(crypto_tests PRIVATE
            /W4
            # /WX
            /Od # No optimization
        )
    endif()

    # Automatically discover tests for CTest
    gtest_discover_tests(crypto_tests)
endif()