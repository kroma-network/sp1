#include "sp1-core/include/baby_bear_poseidon2_prover_data.h"

#include <string.h>

#include "sp1-core/src/baby_bear_poseidon2.rs.h"

namespace tachyon::sp1_api::baby_bear_poseidon2 {

ProverData::~ProverData() {
  tachyon_sp1_baby_bear_poseidon2_field_merkle_tree_destroy(tree_);
}

void ProverData::write_commit(rust::Slice<TachyonBabyBear> values) const {
  for (size_t i = 0; i < values.size(); ++i) {
    memcpy(&values[i], &commitment_[i], sizeof(uint32_t));
  }
}

std::unique_ptr<ProverData> ProverData::clone() const {
  return std::make_unique<ProverData>(
      tachyon_sp1_baby_bear_poseidon2_field_merkle_tree_clone(tree_));
}

}  // namespace tachyon::sp1_api::baby_bear_poseidon2
