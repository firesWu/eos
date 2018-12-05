/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#include <eosio/sql_db_api_plugin/sql_db_api_plugin.hpp>
#include <eosio/chain/exceptions.hpp>

#include <fc/io/json.hpp>

namespace eosio {

static appbase::abstract_plugin& _sql_db_api_plugin = app().register_plugin<sql_db_api_plugin>();

using namespace eosio;

sql_db_api_plugin::sql_db_api_plugin(){}
sql_db_api_plugin::~sql_db_api_plugin(){}

void sql_db_api_plugin::set_program_options(options_description&, options_description&) {}
void sql_db_api_plugin::plugin_initialize(const variables_map&) {}

#define CALL(api_name, api_handle, api_namespace, call_name) \
{std::string("/v1/" #api_name "/" #call_name), \
   [this, api_handle](string, string body, url_response_callback cb) mutable { \
          try { \
             if (body.empty()) body = "{}"; \
             auto result = api_handle.call_name(fc::json::from_string(body).as<api_namespace::call_name ## _params>()); \
             cb(200, fc::json::to_string(result)); \
          } catch (...) { \
             http_plugin::handle_exception(#api_name, #call_name, body, cb); \
          } \
       }}

#define CHAIN_RO_CALL(call_name) CALL(sql_db, ro_api, sql_db_apis::read_only, call_name)

void sql_db_api_plugin::plugin_startup() {
   ilog( "starting sql_db_api_plugin" );
   auto ro_api = app().get_plugin<sql_db_plugin>().get_read_only_api();

   app().get_plugin<http_plugin>().add_api({
       CHAIN_RO_CALL(get_tokens),
       CHAIN_RO_CALL(get_all_tokens),
       CHAIN_RO_CALL(get_hold_tokens),
       CHAIN_RO_CALL(get_userresource),
       CHAIN_RO_CALL(get_refund),
       CHAIN_RO_CALL(get_pending_proposals),
       CHAIN_RO_CALL(get_pending_proposal),
       CHAIN_RO_CALL(get_my_proposals),
       CHAIN_RO_CALL(get_proxies_info)
   });
}

void sql_db_api_plugin::plugin_shutdown() {}

}
