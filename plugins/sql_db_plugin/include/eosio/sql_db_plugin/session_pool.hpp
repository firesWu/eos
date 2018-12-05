#pragma once
#include <soci/soci.h>
#include <soci/mysql/soci-mysql.h>
#include <soci/connection-pool.h>
#include <mysql.h>

namespace eosio{

    class soci_session_pool {
        public:
            std::shared_ptr<soci::connection_pool> c_pool_ptr;
            
            soci_session_pool(size_t pool_size,const std::string& uri){
                c_pool_ptr = std::make_shared<soci::connection_pool>(pool_size); 
                for(size_t i=0 ; i < pool_size; i++){
                    soci::session& sql = c_pool_ptr->at(i);
                    sql.open(uri);
                }
            }

            void reconnect(soci::session& sql){
                try{
                    sql << "select 1;";
                } catch (std::exception& e) {
                    sql.reconnect();
                } catch(...) {
                    sql.reconnect();
                }
            }

            soci::session& get_session(size_t& pos){
                pos = c_pool_ptr->lease();
                soci::session& sql = c_pool_ptr->at(pos);
                reconnect(sql);
                return sql;
            }

            void release(size_t pos){
                c_pool_ptr->give_back(pos);
            }

            void reconnect(std::shared_ptr<soci::session> sql_ptr){
                soci::mysql_session_backend * mysqlBackEnd = static_cast<soci::mysql_session_backend *>(sql_ptr->get_backend());
                int i = mysql_ping(mysqlBackEnd->conn_);
                if(i==1){
                    sql_ptr->reconnect();
                }
            }

            std::shared_ptr<soci::session> get_session(){
                auto sql_ptr = std::make_shared<soci::session>(*c_pool_ptr);
                try{// ubuntu os  try catch will lose, so direct reconnect

                    reconnect(sql_ptr);
                } catch (std::exception& e) {
                    reconnect(sql_ptr);
                } catch(...) {
                    reconnect(sql_ptr);
                }

                return sql_ptr;
            }

    };


}


