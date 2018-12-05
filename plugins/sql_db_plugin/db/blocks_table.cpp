// #include "blocks_table.hpp"
#include <eosio/sql_db_plugin/blocks_table.hpp>

#include <fc/log/logger.hpp>

namespace eosio {

    void blocks_table::add( std::shared_ptr<soci::session> m_session, const chain::block_state_ptr&  bs ) {

        auto block = bs->block;
        const auto block_id_str = block->id().str();
        const auto previous_block_id_str = block->previous.str();
        const auto transaction_mroot_str = block->transaction_mroot.str();
        const auto action_mroot_str = block->action_mroot.str();
        const auto timestamp = std::chrono::seconds{block->timestamp.operator fc::time_point().sec_since_epoch()}.count();
        const auto num_transactions = (int)bs->trxs.size();


        try{
            *m_session << "REPLACE INTO blocks(id, block_number, prev_block_id, timestamp, transaction_merkle_root, action_merkle_root,"
                "producer, version, confirmed, num_transactions) VALUES (:id, :in, :pb, FROM_UNIXTIME(:ti), :tr, :ar, :pa, :ve, :pe, :nt)",
                soci::use(block_id_str),
                soci::use(block->block_num()),
                soci::use(previous_block_id_str),
                soci::use(timestamp),
                soci::use(transaction_mroot_str),
                soci::use(action_mroot_str),
                soci::use(block->producer.to_string()),
                soci::use(block->schedule_version),
                soci::use(block->confirmed),
                soci::use(num_transactions);

            if (block->new_producers) {
                const auto new_producers = fc::json::to_string(block->new_producers->producers);
                *m_session << "UPDATE blocks SET new_producers = :np WHERE id = :id",
                        soci::use(new_producers),
                        soci::use(block_id_str);
            }
        } catch(soci::mysql_soci_error e) {
            wlog("soci::error: ${e}",("e",e.what()) );
        } catch(std::exception e) {
            wlog( "add blocks failed. ${e}",("e",e.what()) );
        } catch(...) {
            wlog( "add blocks failed. " );
        }
    }

    bool blocks_table::irreversible_set( std::shared_ptr<soci::session> m_session, std::string block_id, bool irreversible ){
        
        int amount = 0;
        try{
            soci::statement st = ( m_session->prepare << "UPDATE blocks SET irreversible = :irreversible WHERE id = :id",
                    soci::use(irreversible?1:0),
                    soci::use(block_id) );
            st.execute(true);
            amount = st.get_affected_rows();
            if(amount==0){
                *m_session << "select count(*) from blocks where irreversible = 0 and id = :id ",
                    soci::into(amount),
                    soci::use(block_id);
                if(amount==0) return true;
            }
            // wlog( "${amount}",("amount",amount) );
        } catch(soci::mysql_soci_error e) {
            wlog("soci::error: ${e}",("e",e.what()) );
        } catch(std::exception e) {
            wlog( "update block irreversible failed.block id:${id},error: ${e}",("id",block_id)("e",e.what()) );
        } catch(...) {
            wlog("update block irreversible failed. ${id}",("id",block_id));
        }
        return amount > 0;
    }

} // namespace
