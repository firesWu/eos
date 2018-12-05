#pragma once

#include <eosio/sql_db_plugin/table.hpp>

#include <vector>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include <eosio/chain/block_state.hpp>
#include <eosio/chain/eosio_contract.hpp>
#include <eosio/chain/abi_def.hpp>
#include <eosio/chain/asset.hpp>
#include <eosio/chain/abi_serializer.hpp>

namespace eosio {

using std::string;
using std::vector;

struct system_contract_arg{
    system_contract_arg() = default;
    system_contract_arg(const chain::account_name& to, const chain::account_name& from, const chain::account_name& receiver, const chain::account_name& payer, const chain::account_name& name)
    :to(to), from(from), receiver(receiver), payer(payer), name(name)
    {}
    chain::account_name to;
    chain::account_name from;
    chain::account_name receiver;
    chain::account_name payer;
    chain::account_name name;
    chain::account_name account;
};

class actions_table : public mysql_table {
    public:
        actions_table(){}

        bool add( std::shared_ptr<soci::session>, chain::action , chain::transaction_id_type , chain::block_timestamp_type , std::vector<std::string> ); 
        void parse_actions( std::shared_ptr<soci::session>, chain::action );
        string add_data( std::shared_ptr<soci::session>, chain::action );
        soci::rowset<soci::row> get_assets( std::shared_ptr<soci::session>, int ,int );
        soci::rowset<soci::row> get_assets( std::shared_ptr<soci::session> );
        soci::rowset<soci::row> get_proposal(std::shared_ptr<soci::session>, string );

        static const chain::account_name newaccount;
        static const chain::account_name setabi;
};


} // namespace

FC_REFLECT( eosio::system_contract_arg                        , (to)(from)(receiver)(payer)(name)(account) )



