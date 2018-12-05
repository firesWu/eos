/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once
#include <eosio/sql_db_plugin/sql_db_plugin.hpp>
#include <eosio/http_plugin/http_plugin.hpp>

#include <appbase/application.hpp>
#include <eosio/chain/controller.hpp>

namespace eosio {
   using eosio::chain::controller;
   using std::unique_ptr;
   using namespace appbase;

   class sql_db_api_plugin : public plugin<sql_db_api_plugin> {
      public:
        APPBASE_PLUGIN_REQUIRES((sql_db_plugin)(http_plugin))

        sql_db_api_plugin();
        virtual ~sql_db_api_plugin();

        virtual void set_program_options(options_description&, options_description&) override;

        void plugin_initialize(const variables_map&);
        void plugin_startup();
        void plugin_shutdown();
   };

}
