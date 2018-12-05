// #include "accounts_table.hpp"
#include <eosio/sql_db_plugin/accounts_table.hpp>
#include <fc/log/logger.hpp>

namespace eosio {

void accounts_table::add(std::shared_ptr<soci::session> m_session, string name) {
    try {
        *m_session << "REPLACE INTO accounts (name) VALUES (:name)",
            soci::use(name);
    } catch(soci::mysql_soci_error e) {
        wlog("soci::error: ${e}",("e",e.what()) );
    } catch (std::exception const & e) {
        wlog( "exception: ${e}",("e",e.what()) );
    } catch (...){
        wlog( "unknow exception" );
    }
    
}

void accounts_table::add_eosio(std::shared_ptr<soci::session> m_session, string name,string abi) {
    try {
        *m_session << "INSERT INTO accounts (name,abi) VALUES (:name,:abi)",
            soci::use(name),soci::use(abi);
    } catch(soci::mysql_soci_error e) {
        wlog("soci::error: ${e}",("e",e.what()) );
    } catch (std::exception const & e) {
        wlog( "exception: ${e}",("e",e.what()) );
    } catch (...){
        wlog( "unknow exception" );
    } 
}

bool accounts_table::exist(std::shared_ptr<soci::session> m_session, string name)
{
    int amount;
    try {
        *m_session << "SELECT COUNT(*) FROM accounts WHERE name = :name", soci::into(amount), soci::use(name);
    } catch(soci::mysql_soci_error e) {
        wlog("soci::error: ${e}",("e",e.what()) );
    } catch (std::exception const & e) {
        amount = 0;
    }
    return amount > 0;
}

} // namespace
