cmake_minimum_required(VERSION 3.22.1)
project("securelink_core" LANGUAGES C CXX)

# Biblioteca nativa pré-compilada (construída via script separado)
add_library(securelink_core SHARED IMPORTED)
set_target_properties(securelink_core PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libsecurelink_core.so
)

# Linka com libs necessárias do Android
target_link_libraries(securelink_core
    android
    log
    c++_shared
)