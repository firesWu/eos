#pragma once

#include <memory>
#include <soci/soci.h>
#include<soci/mysql/soci-mysql.h>
#include <fc/io/json.hpp>
#include <fc/variant.hpp>
#include <fc/time.hpp>

namespace eosio{

class mysql_table{
    public:
        fc::microseconds max_serialization_time = fc::microseconds(150*1000);

};

}