
cmake_minimum_required(VERSION 2.8)

project(BroPluginIso_Over_TCP)

include(BroPlugin)

bro_plugin_begin(Bro Iso_Over_TCP)
bro_plugin_bif(src/events.bif src/types.bif src/functions.bif)
bro_plugin_cc(src/Plugin.cc src/Iso_Over_TCP.cc src/S7Comm.cc src/S7CommPlus.cc)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
