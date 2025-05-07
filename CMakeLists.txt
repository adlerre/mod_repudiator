cmake_minimum_required(VERSION 3.28)
project(mod_repudiator C)

set(CMAKE_C_STANDARD 11)

include_directories(
        /opt/homebrew/include
        /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/apache2
        /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/apr-1
)

add_library(libpcre2 SHARED IMPORTED GLOBAL)
add_library(libmaxminddb SHARED IMPORTED GLOBAL)

find_library(libpcre2_path NAMES libpcre2-8.a HINTS /opt/homebrew/lib REQUIRED NO_CMAKE_SYSTEM_PATH)
find_library(libmaxminddb_path NAMES libmaxminddb.a HINTS /opt/homebrew/lib REQUIRED NO_CMAKE_SYSTEM_PATH)

message(">>>>>> libpcre2_path = ${libpcre2_path}")
set_property(TARGET libpcre2 PROPERTY IMPORTED_LOCATION ${libpcre2_path})

message(">>>>>> libmaxminddb_path = ${libmaxminddb_path}")
set_property(TARGET libmaxminddb PROPERTY IMPORTED_LOCATION ${libmaxminddb_path})

add_library(mod_repudiator SHARED mod_repudiator.c)

target_link_libraries(mod_repudiator
        PRIVATE libpcre2
        PRIVATE libmaxminddb
)

install(TARGETS mod_repudiator
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})