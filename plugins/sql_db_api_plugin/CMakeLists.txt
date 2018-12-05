file( GLOB HEADERS "include/eosio/sql_db_api_plugin/*.hpp" )
add_library( sql_db_api_plugin
             sql_db_api_plugin.cpp
             ${HEADERS} )

target_link_libraries( sql_db_api_plugin sql_db_plugin chain_plugin http_plugin appbase )
target_include_directories( sql_db_api_plugin PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
