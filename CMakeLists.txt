cmake_minimum_required(VERSION 3.16)
project(PacketLens LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Qt MOC ────────────────────────────────────────────────────────────────────
# Qt's Meta-Object Compiler (MOC) must run automatically on any class that
# uses Q_OBJECT.  CMAKE_AUTOMOC handles this transparently.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# ── Qt6 Widgets ───────────────────────────────────────────────────────────────
find_package(Qt6 COMPONENTS Widgets REQUIRED)

# ── libpcap ───────────────────────────────────────────────────────────────────
find_library(PCAP_LIB pcap REQUIRED)

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    tcp_parser.cpp
    sniffer_backend.cpp
    connection_model.cpp
    main_window.cpp
)

set(HEADERS
    tcp_parser.h
    flow_manager.h
    sniffer_backend.h
    connection_model.h
    main_window.h
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(packetlens ${SOURCES} ${HEADERS})

target_link_libraries(packetlens
    PRIVATE
        Qt6::Widgets
        ${PCAP_LIB}
        pthread
)

# Needed on Linux to read /proc/net/tcp as root
target_compile_options(packetlens PRIVATE -Wall -Wextra)
