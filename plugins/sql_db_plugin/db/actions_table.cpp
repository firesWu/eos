// #include "actions_table.hpp"
#include <eosio/sql_db_plugin/actions_table.hpp>
#include <cmath>
#include <chrono>

namespace eosio {

    bool actions_table::add( std::shared_ptr<soci::session> m_session, chain::action action, chain::transaction_id_type transaction_id, chain::block_timestamp_type block_time, std::vector<std::string> filter_out ) {

        if( std::find(filter_out.begin(), filter_out.end(), action.name.to_string())!=filter_out.end() ){

            chain::abi_def abi;
            std::string abi_def_account;
            chain::abi_serializer abis;
            soci::indicator ind;
            const auto transaction_id_str = transaction_id.str();
            const auto timestamp = std::chrono::seconds{block_time.operator fc::time_point().sec_since_epoch()}.count();

            string json = add_data( m_session, action );
            system_contract_arg dataJson = fc::json::from_string(json).as<system_contract_arg>();
            string json_auth = fc::json::to_string(action.authorization);

            try{
                *m_session << "INSERT INTO actions(account, created_at, name, data, authorization, transaction_id, eosto, eosfrom, receiver, payer, newaccount, sellram_account) "
                                "VALUES (:ac, FROM_UNIXTIME(:ca), :na, :da, :auth, :ti, :to, :form, :receiver, :payer, :newaccount, :sellram_account) ",
                    soci::use(action.account.to_string()),
                    soci::use(timestamp),
                    soci::use(action.name.to_string()),
                    soci::use(json),
                    soci::use(json_auth),
                    soci::use(transaction_id_str),
                    soci::use(dataJson.to.to_string()),
                    soci::use(dataJson.from.to_string()),
                    soci::use(dataJson.receiver.to_string()),
                    soci::use(dataJson.payer.to_string()),
                    soci::use(dataJson.name.to_string()),
                    soci::use(dataJson.account.to_string());
            } catch(soci::mysql_soci_error e) {
                wlog("soci::error: ${e}",("e",e.what()) );
            } catch(...) {
                wlog("insert action failed in ${n}::${a}",("n",action.account.to_string())("a",action.name.to_string()));
                wlog("${data}",("data",fc::json::to_string(action)));
            }

            try {
                parse_actions( m_session, action );
            }  catch(fc::exception& e) {
                wlog("fc exception: ${e}",("e",e.what()));
            } catch(soci::mysql_soci_error e) {
                wlog("soci::error: ${e}",("e",e.what()) );
            } catch(std::exception& e){
                wlog(e.what());
            } catch(...){
                wlog("Unknown excpetion.");
            }
            return true;
        }
        return false;
    }

    void actions_table::parse_actions( std::shared_ptr<soci::session> m_session, chain::action action ) {

        chain::abi_def abi;
        std::string abi_def_account;
        chain::abi_serializer abis;
        soci::indicator ind;
        fc::variant abi_data;

        *m_session << "SELECT abi FROM accounts WHERE name = :name", soci::into(abi_def_account, ind), soci::use(action.account.to_string());

        if (!abi_def_account.empty()) {
            abi = fc::json::from_string(abi_def_account).as<chain::abi_def>();
        } else if (action.account == chain::config::system_account_name) {
            abi = chain::eosio_contract_abi(abi);
        } else {
            return ; // no ABI no party. Should we still store it?
        }

        abis.set_abi(abi, max_serialization_time);
        abi_data = abis.binary_to_variant(abis.get_action_type(action.name), action.data, max_serialization_time);

        if(action.account == chain::config::system_account_name) {

            if( action.name == newaccount ){
                auto action_data = action.data_as<chain::newaccount>();
                *m_session << "INSERT INTO accounts (name) VALUES (:name) on  DUPLICATE key UPDATE name = :name",
                        soci::use(action_data.name.to_string()),soci::use(action_data.name.to_string());

                for (const auto& key_owner : action_data.owner.keys) {
                    string permission_owner = "owner";
                    string public_key_owner = static_cast<string>(key_owner.key);
                    *m_session << "INSERT INTO accounts_keys(account, public_key, permission) VALUES (:ac, :ke, :pe) ",
                            soci::use(action_data.name.to_string()),
                            soci::use(public_key_owner),
                            soci::use(permission_owner);
                }

                for (const auto& key_active : action_data.active.keys) {
                    string permission_active = "active";
                    string public_key_active = static_cast<string>(key_active.key);
                    *m_session << "INSERT INTO accounts_keys(account, public_key, permission) VALUES (:ac, :ke, :pe) ",
                            soci::use(action_data.name.to_string()),
                            soci::use(public_key_active),
                            soci::use(permission_active);
                }

            }else if( action.name == N(voteproducer) ){

                auto voter = abi_data["voter"].as<chain::name>().to_string();
                auto proxy = abi_data["proxy"].as<chain::name>().to_string();
                auto producers = fc::json::to_string( abi_data["producers"] );

                try{
                    *m_session << "INSERT INTO votes ( voter, proxy, producers )  VALUES( :vo, :pro, :pd ) "
                            "on  DUPLICATE key UPDATE proxy = :pro, producers =  :pd ",
                            soci::use(voter),
                            soci::use(proxy),
                            soci::use(producers),
                            soci::use(proxy),
                            soci::use(producers);
                } catch(soci::mysql_soci_error e) {
                    wlog("soci::error: ${e}",("e",e.what()) );
                } catch(std::exception e) {
                    wlog(" ${voter} ${proxy} ${producers}",("voter",voter)("proxy",proxy)("producers",producers));
                    wlog( "${e}",("e",e.what()) );
                } catch(...) {
                    wlog(" ${voter} ${proxy} ${producers}",("voter",voter)("proxy",proxy)("producers",producers));
                }

            }

        } else if( action.account == N(eosio.msig) ) {
            if( action.name == N(propose) ){
                auto proposer = abi_data["proposer"].as<chain::name>().to_string();
                auto proposal_name = abi_data["proposal_name"].as<chain::name>().to_string();
                auto requested = fc::json::to_string(abi_data["requested"]);//abi_data["requested"].as< vector<chain::permission_level> >();

                try{
                    *m_session << "INSERT INTO proposal ( proposer, proposal_name, requested_approvals )  VALUES( :pro, :proname, :req ) "
                            "on  DUPLICATE key UPDATE proposer = :pro, proposal_name =  :proname, requested_approvals =  :req ",
                            soci::use(proposer),
                            soci::use(proposal_name),
                            soci::use(requested),
                            soci::use(proposer),
                            soci::use(proposal_name),
                            soci::use(requested);
                } catch(soci::mysql_soci_error e) {
                    wlog("soci::error: ${e}",("e",e.what()) );
                } catch(std::exception e) {
                    wlog( "${e}",("e",e.what()) );
                } catch(...) {
                    wlog("${pro} ${pro_name} ${request}",("pro",proposer)("pro_name",proposal_name)("request",requested));
                }

            } else if( action.name == N(cancel) || action.name == N(exec) ) {
                auto proposer = abi_data["proposer"].as<chain::name>().to_string();
                auto proposal_name = abi_data["proposal_name"].as<chain::name>().to_string();

                try{
                    *m_session << "DELETE FROM proposal WHERE proposer = :pro and proposal_name = :proname ",
                            soci::use(proposer),
                            soci::use(proposal_name);
                } catch(soci::mysql_soci_error e) {
                    wlog("soci::error: ${e}",("e",e.what()) );
                } catch(std::exception e) {
                    wlog( "${e}",("e",e.what()) );
                } catch(...) {
                    wlog("${pro} ${pro_name}",("pro",proposer)("pro_name",proposal_name));
                }

            }

        } else {

            if( action.name == N(create) ){

                auto issuer = abi_data["issuer"].as<chain::name>().to_string();
                auto maximum_supply = abi_data["maximum_supply"].as<chain::asset>();

                if(issuer.empty() || maximum_supply.get_amount() <= 0){
                    return ;
                }

                string insertassets;
                try{
                    insertassets = "REPLACE INTO assets(supply, max_supply, symbol_precision, symbol,  issuer, contract_owner) VALUES( :am, :mam, :pre, :sym, :issuer, :owner)";
                    *m_session << insertassets,
                            soci::use( 0 ),
                            soci::use( maximum_supply.get_amount() ),
                            soci::use( maximum_supply.decimals() ),
                            soci::use( maximum_supply.get_symbol().name() ),
                            soci::use( issuer ),
                            soci::use( action.account.to_string() );
                } catch(soci::mysql_soci_error e) {
                    wlog("soci::error: ${e}",("e",e.what()) );
                } catch(std::exception e) {
                    wlog("${e}",("e",e.what()));
                } catch (...) {
                    wlog("${sql}",("sql",insertassets) );
                    wlog( "create asset failed. ${issuer} ${maximum_supply}",("issuer",issuer)("maximum_supply",maximum_supply) );
                }
            }
        }

    }


    string actions_table::add_data(std::shared_ptr<soci::session> m_session, chain::action action){
        string json_str = "{}";

        if(action.data.size() ==0 ){
            ilog("data size is 0.");
             return json_str;
        }

        try{
            //当为set contract时 存储abi
            if( action.account == chain::config::system_account_name ){
                if( action.name == setabi ){
                    auto setabi = action.data_as<chain::setabi>();
                    try{
                        const chain::abi_def& abi_def = fc::raw::unpack<chain::abi_def>(setabi.abi);
                        json_str = fc::json::to_string( abi_def );

                        try{
                            *m_session << "INSERT INTO accounts ( name, abi )  VALUES( :name, :abi ) on  DUPLICATE key UPDATE abi = :abi, updated_at =  NOW() "
                                ,soci::use(setabi.account.to_string()),soci::use(json_str),soci::use(json_str);
                            // ilog("update abi ${n}",("n",action.account.to_string()));
                        } catch(soci::mysql_soci_error e) {
                            wlog("soci::error: ${e}",("e",e.what()) );
                        }catch(...){
                            wlog("insert account abi failed");
                        }

                        return json_str;
                    }catch(fc::exception& e){
                        wlog("get setabi data wrong ${e}",("e",e.what()));
                    }
                }
            }

            chain::abi_def abi;
            std::string abi_def_account;
            chain::abi_serializer abis;
            soci::indicator ind;
            //get account abi
            *m_session << "SELECT abi FROM accounts WHERE name = :name", soci::into(abi_def_account, ind), soci::use(action.account.to_string());

            if(!abi_def_account.empty()){
                try {
                    abi = fc::json::from_string(abi_def_account).as<chain::abi_def>();
                    abis.set_abi( abi, max_serialization_time );
                    auto binary_data = abis.binary_to_variant( abis.get_action_type(action.name), action.data, max_serialization_time);
                    json_str = fc::json::to_string(binary_data);
                    return json_str;
                } catch(...) {
                    wlog("unable to convert account abi to abi_def for ${s}::${n} :${abi}",("s",action.account)("n",action.name)("abi",action.data));
                    wlog("analysis data failed");
                }
            }else{
                wlog("${n} abi is null.",("n",action.account));
            }

        } catch(soci::mysql_soci_error e) {
            wlog("soci::error: ${e}",("e",e.what()) );
        }catch( std::exception& e ) {
            ilog( "Unable to convert action.data to ABI: ${s}::${n}, std what: ${e}",
                    ("s", action.account)( "n", action.name )( "e", e.what()));
        } catch( ... ) {
            ilog( "Unable to convert action.data to ABI: ${s}::${n}, unknown exception",
                    ("s", action.account)( "n", action.name ));
        }
        return json_str;
    }

    soci::rowset<soci::row> actions_table::get_assets(std::shared_ptr<soci::session> m_session, int startNum,int pageSize){
        soci::rowset<soci::row> rs = ( m_session->prepare << "select contract_owner, issuer, symbol_precision, symbol from assets order by id limit :st,:pt ",
            soci::use(startNum),soci::use(pageSize));
        return rs;
    }

    soci::rowset<soci::row> actions_table::get_assets(std::shared_ptr<soci::session> m_session){
        soci::rowset<soci::row> rs = ( m_session->prepare << "select contract_owner, issuer, symbol_precision, symbol from assets order by id ");
        return rs;
    }

    soci::rowset<soci::row> actions_table::get_proposal(std::shared_ptr<soci::session> m_session, string account){
        string acc = "\"actor\":\"" + account + "\"";
        soci::rowset<soci::row> rs = ( m_session->prepare << "select proposer, proposal_name from proposal where requested_approvals like '%" + acc + "%' order by id ");
        return rs;
    }

    const chain::account_name actions_table::newaccount = chain::newaccount::get_name();
    const chain::account_name actions_table::setabi = chain::setabi::get_name();

} // namespace