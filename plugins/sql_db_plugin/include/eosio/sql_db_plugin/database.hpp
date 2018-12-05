#pragma once
#include <soci/soci.h>

#include <eosio/chain/config.hpp>
#include <eosio/chain/block_state.hpp>
#include <eosio/chain/transaction.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain/types.hpp>

#include <eosio/sql_db_plugin/accounts_table.hpp>
#include <eosio/sql_db_plugin/transactions_table.hpp>
#include <eosio/sql_db_plugin/blocks_table.hpp>
#include <eosio/sql_db_plugin/actions_table.hpp>
#include <eosio/sql_db_plugin/session_pool.hpp>

#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>

namespace eosio {

class sql_database {
    public:
        sql_database(const std::string& uri, uint32_t block_num_start, size_t pool_size);
        sql_database(const std::string& uri, uint32_t block_num_start, size_t pool_size, std::vector<std::string>, std::vector<std::string>);
        
        void wipe();
        bool is_started();
        void consume_block_state( const chain::block_state_ptr& );
        void consume_irreversible_block_state( const chain::block_state_ptr& , boost::mutex::scoped_lock& , boost::condition_variable& condition,boost::atomic<bool>& exit);

        void consume_transaction_metadata( const chain::transaction_metadata_ptr& );
        void consume_transaction_trace( const chain::transaction_trace_ptr& );

        void dfs_inline_traces( std::shared_ptr<soci::session>, vector<chain::action_trace>,  chain::transaction_id_type, chain::block_timestamp_type );

        std::shared_ptr<soci_session_pool> m_session_pool;
        std::unique_ptr<actions_table> m_actions_table;
        std::unique_ptr<accounts_table> m_accounts_table;
        std::unique_ptr<blocks_table> m_blocks_table;
        std::unique_ptr<transactions_table> m_transactions_table;
        std::string system_account;
        uint32_t m_block_num_start;
        std::vector<std::string> m_action_filter_on;
        std::vector<std::string> m_contract_filter_out;

    };

} // namespace

