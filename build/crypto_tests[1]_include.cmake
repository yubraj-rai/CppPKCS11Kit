if(EXISTS "/home/yubraj/CppPKCS11Kit/build/crypto_tests[1]_tests.cmake")
  include("/home/yubraj/CppPKCS11Kit/build/crypto_tests[1]_tests.cmake")
else()
  add_test(crypto_tests_NOT_BUILT crypto_tests_NOT_BUILT)
endif()
