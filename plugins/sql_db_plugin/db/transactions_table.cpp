// #include "transactions_table.hpp"
#include <eosio/sql_db_plugin/transactions_table.hpp>

#include <chrono>
#include <fc/log/logger.hpp>

namespace eosio {

    void transactions_table::add( std::shared_ptr<soci::session> m_session, chain::transaction transaction ) {

        const auto transaction_id_str = transaction.id().str();
        const auto expiration = std::chrono::seconds{transaction.expiration.sec_since_epoch()}.count();
        try{
            *m_session << "INSERT INTO transactions(id, ref_block_num, ref_block_prefix, expiration, pending, created_at, updated_at, num_actions) "
                        "VALUES (:id, :rbi, :rb, FROM_UNIXTIME(:ex), :pe, FROM_UNIXTIME(:ca), FROM_UNIXTIME(:ua), :na)",
                soci::use(transaction_id_str),
                soci::use(transaction.ref_block_num),
                soci::use(transaction.ref_block_prefix),
                soci::use(expiration),
                soci::use(0),
                soci::use(expiration),
                soci::use(expiration),
                soci::use(transaction.total_actions());
        } catch(soci::mysql_soci_error e) {
            wlog("soci::error: ${e}",("e",e.what()) );
        } catch (std::exception e) {
            wlog("insert transaction failed. ${id}",("id",transaction_id_str));
            wlog("${e}",("e",e.what()));
        } catch(...){
            wlog("insert transaction failed. ${id}",("id",transaction_id_str));
        }
    }

    void transactions_table::irreversible_set( std::shared_ptr<soci::session> m_session, std::string block_id, bool irreversible, std::string transaction_id_str) {

        try{
            *m_session << "UPDATE transactions SET block_id = :block_id, irreversible = :irreversible WHERE id = :id ",
                soci::use(block_id),
                soci::use(irreversible?1:0),
                soci::use(transaction_id_str);
        } catch(soci::mysql_soci_error e) {
            wlog("soci::error: ${e}",("e",e.what()) );
        } catch (std::exception e) {
            wlog("update transaction failed ${id}",("id",transaction_id_str));
            wlog("${e}",("e",e.what()));
        } catch(...) {
            wlog("update transaction failed ${id}",("id",transaction_id_str));
        }
    }

    bool transactions_table::find_transaction( std::shared_ptr<soci::session> m_session, std::string transaction_id_str) {
        
        int amount;
        try{
            *m_session << "SELECT COUNT(*) FROM transactions WHERE id = :id",
                soci::into(amount),
                soci::use(transaction_id_str);
        } catch(soci::mysql_soci_error e) {
            wlog("soci::error: ${e}",("e",e.what()) );
        } catch(...) {
            amount = 0;
            wlog("find transaction failed. ${id}",("id",transaction_id_str));
        }
        return amount > 0;
    }

} // namespace
