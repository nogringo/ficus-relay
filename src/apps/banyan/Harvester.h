#pragma once

#include <string>
#include <vector>

#include <tao/json.hpp>

#include "golpe.h"

#include "Bytes32.h"


namespace banyan {


void runHarvester();

// Ask the harvester to replan now (tenant added, universe changed)
void harvesterWake();

tao::json::value harvesterStatus();

// Returns an empty string for URLs the harvester should not use
std::string normalizeHarvestUrl(std::string_view input);

// Fetch these profiles from the bootstrap relays, for zap checks on people outside every universe
void harvesterWantProfiles(const std::vector<Bytes32> &pubkeys);

// An event a client published on a virtual relay: sent to its author's write relays if they are in that universe
void harvesterPublish(uint64_t tenantId, std::string packedStr, std::string jsonStr);


}
