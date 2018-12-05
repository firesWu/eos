#pragma once

#include <eosio/sql_db_plugin/table.hpp>

namespace eosio {

using std::string;

class accounts_table  : public mysql_table {
    public:
        accounts_table(){};

        void add(std::shared_ptr<soci::session> , string );
        bool exist(std::shared_ptr<soci::session>, string );
        void add_eosio(std::shared_ptr<soci::session>, string ,string );

};

} // namespace

