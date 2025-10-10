cmake_minimum_required(VERSION 3.10)
project(AnyIntruder C)

# 编译选项
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type" FORCE)
endif()

option(BUILD_SHARED_LIBS "Build as shared library instead of executable" OFF)
option(ENABLE_DEBUG_SYMBOLS "Enable debug symbols" OFF)

if(ENABLE_DEBUG_SYMBOLS)
  add_compile_options(-g)
endif()

# 使用 pkg-config 查找依赖
find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP libpcap)
pkg_check_modules(NCURSES ncurses)

if(NOT PCAP_FOUND)
  message(FATAL_ERROR "libpcap not found. Install libpcap-dev or run pkg-config for libpcap.")
endif()

if(NOT NCURSES_FOUND)
  message(STATUS "ncurses not found by pkg-config. UI will be disabled if ncurses missing.")
endif()

# include 与 link flags
include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_compile_options(${PCAP_CFLAGS_OTHER})

if(NCURSES_FOUND)
  include_directories(${NCURSES_INCLUDE_DIRS})
  link_directories(${NCURSES_LIBRARY_DIRS})
  add_compile_options(${NCURSES_CFLAGS_OTHER})
endif()

# 源文件（按需修改）
set(SRCS
  src/main.c
  src/monitor.c
  src/logger.c
  src/ui.c
)

# 生成目标
add_executable(anyintruder ${SRCS})

# 链接库
target_link_libraries(anyintruder ${PCAP_LIBRARIES})
if(NCURSES_FOUND)
  target_link_libraries(anyintruder ${NCURSES_LIBRARIES})
else()
  message(WARNING "ncurses not found. UI may fail to build or run.")
endif()

# 安装规则
set(INSTALL_BIN_DIR bin)
install(TARGETS anyintruder
  RUNTIME DESTINATION ${INSTALL_BIN_DIR}
)

# 生成 compile_commands.json 便于 IDE
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 易用的 convenient targets
add_custom_target(check-deps
  COMMAND ${CMAKE_COMMAND} -E echo "libpcap: ${PCAP_LIBRARIES}"
)

message(STATUS "CMake configured. PCAP libs: ${PCAP_LIBRARIES}")
