#pragma once

#include <eosio/sql_db_plugin/table.hpp>
#include <eosio/chain/transaction_metadata.hpp>

namespace eosio {

class transactions_table : public mysql_table {
    public:
        transactions_table(){};

        void add( std::shared_ptr<soci::session>, chain::transaction  );
        void irreversible_set( std::shared_ptr<soci::session>, std::string , bool , std::string  );
        bool find_transaction( std::shared_ptr<soci::session>, std::string );

    };

} // namespace


