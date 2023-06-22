
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginS7Comm)

include(ZeekPlugin)

zeek_plugin_begin(ICS S7Comm ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/Iso_Over_TCP.cc src/S7Comm.cc src/S7CommPlus.cc)
zeek_plugin_bif(src/events.bif src/types.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(
        scripts/__load__.zeek
        scripts/__preload__.zeek
        scripts/types.zeek
        scripts/ICS/S7Comm/__load__.zeek
)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
