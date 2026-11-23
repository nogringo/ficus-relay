#pragma once

#include <cstdint>


namespace banyan {


struct PruneResult {
    uint64_t scanned = 0; // events whose author is in no universe
    uint64_t deleted = 0; // or that would be deleted, in a dry run
    uint64_t harvestStatesReset = 0;
};

// Deletes the events no virtual relay serves and the trust engine does not read
PruneResult pruneEvents(bool dryRun);

void runPruner();


}
