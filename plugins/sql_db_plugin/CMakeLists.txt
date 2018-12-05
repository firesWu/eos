###############################################################################
# CMake module to search for SOCI library
#
# WARNING: This module is experimental work in progress.
#
# This module defines:
#  SOCI_INCLUDE_DIRS        = include dirs to be used when using the soci library
#  SOCI_LIBRARY             = full path to the soci library
#  SOCI_VERSION             = the soci version found (not yet. soci does not provide that info.)
#  SOCI_FOUND               = true if soci was found
#
# This module respects:
#  LIB_SUFFIX         = (64|32|"") Specifies the suffix for the lib directory
#
# For each component you specify in find_package(), the following variables are set.
#
#  SOCI_${COMPONENT}_PLUGIN = full path to the soci plugin
#  SOCI_${COMPONENT}_FOUND
#
# Copyright (c) 2011 Michael Jansen <info@michael-jansen.biz>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#
###############################################################################
#
### Global Configuration Section
#
SET(_SOCI_ALL_PLUGINS    mysql odbc postgresql sqlite3)
SET(_SOCI_REQUIRED_VARS  SOCI_INCLUDE_DIR SOCI_LIBRARY)

#
### FIRST STEP: Find the soci headers.
#
FIND_PATH(
    SOCI_INCLUDE_DIR soci.h
    PATH "/usr/local"
    PATH_SUFFIXES "" "soci"
    DOC "Soci (http://soci.sourceforge.net) include directory")
MARK_AS_ADVANCED(SOCI_INCLUDE_DIR)

SET(SOCI_INCLUDE_DIRS ${SOCI_INCLUDE_DIR})

#
### SECOND STEP: Find the soci core library. Respect LIB_SUFFIX
#
FIND_LIBRARY(
    SOCI_LIBRARY
    NAMES soci_core
    HINTS ${SOCI_INCLUDE_DIR}/..
    PATH_SUFFIXES lib${LIB_SUFFIX})
MARK_AS_ADVANCED(SOCI_LIBRARY)

GET_FILENAME_COMPONENT(SOCI_LIBRARY_DIR ${SOCI_LIBRARY} PATH)
MARK_AS_ADVANCED(SOCI_LIBRARY_DIR)

#
### THIRD STEP: Find all installed plugins if the library was found
#
IF(SOCI_INCLUDE_DIR AND SOCI_LIBRARY)

    MESSAGE(STATUS "Soci found: Looking for plugins")
    FOREACH(plugin IN LISTS _SOCI_ALL_PLUGINS)

        FIND_LIBRARY(
            SOCI_${plugin}_PLUGIN
            NAMES soci_${plugin}
            HINTS ${SOCI_INCLUDE_DIR}/..
            PATH_SUFFIXES lib${LIB_SUFFIX})
        MARK_AS_ADVANCED(SOCI_${plugin}_PLUGIN)

        IF(SOCI_${plugin}_PLUGIN)
            MESSAGE(STATUS "    * Plugin ${plugin} found ${SOCI_${plugin}_PLUGIN}.")
            SET(SOCI_${plugin}_FOUND True)
        ELSE()
            MESSAGE(STATUS "    * Plugin ${plugin} not found.")
            SET(SOCI_${plugin}_FOUND False)
        ENDIF()

    ENDFOREACH()

    #
    ### FOURTH CHECK: Check if the required components were all found
    #
    FOREACH(component ${Soci_FIND_COMPONENTS})
        IF(NOT SOCI_${component}_FOUND)
            MESSAGE(SEND_ERROR "Required component ${component} not found.")
        ENDIF()
    ENDFOREACH()

ENDIF()

#
### ADHERE TO STANDARDS
#
#include(FindPackageHandleStandardArgs)
#FIND_PACKAGE_HANDLE_STANDARD_ARGS(Soci DEFAULT_MSG ${_SOCI_REQUIRED_VARS})

FIND_LIBRARY(
    MYSQLCLIENT
    NAMES mysqlclient
    HINTS /usr/local/lib /usr/lib
    PATH_SUFFIXES lib${LIB_SUFFIX})
MARK_AS_ADVANCED(MYSQLCLIENT)

if( MYSQLCLIENT EQUAL NO_DEFAULT_PATH )
    message(STATUS "Database MYSQL plugin: disabled")
    return()
endif()

message(STATUS "Database SQL plugin: enabled")
file(GLOB HEADERS "include/eosio/sql_db_plugin/*.hpp")
include_directories(${CMAKE_CURRENT_SOURCE_DIR} include db)

add_library(sql_db_plugin
    db/database.cpp
    db/accounts_table.cpp
    db/transactions_table.cpp
    db/blocks_table.cpp
    db/actions_table.cpp
    sql_db_plugin.cpp
    )

target_link_libraries(sql_db_plugin
    chain_plugin
    eosio_chain
    ${SOCI_LIBRARY}
    ${MYSQLCLIENT}
    )
target_include_directories( sql_db_plugin
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
#add_subdirectory(test)

