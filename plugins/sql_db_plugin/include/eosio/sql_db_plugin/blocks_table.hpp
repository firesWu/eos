#pragma once

#include <eosio/sql_db_plugin/table.hpp>

#include <chrono>

#include <eosio/chain/block_state.hpp>

namespace eosio {

class blocks_table : public mysql_table {
    public:
        blocks_table(){};

        // void add(chain::signed_block_ptr block);
        void add( std::shared_ptr<soci::session>, const chain::block_state_ptr& );
        bool irreversible_set( std::shared_ptr<soci::session>, std::string , bool  );

};

} // namespace


