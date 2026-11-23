#pragma once

#include <tao/json.hpp>


namespace banyan {


void runHarvester();

// Ask the harvester to replan now (tenant added, universe changed)
void harvesterWake();

tao::json::value harvesterStatus();


}
