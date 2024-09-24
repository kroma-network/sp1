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

rust::Vec<uint8_t> ProverData::serialize() const {
  rust::Vec<uint8_t> ret;
  size_t size;
  tachyon_sp1_baby_bear_poseidon2_field_merkle_tree_serialize(tree_, nullptr,
                                                              &size);
  // NOTE(chokobole): |rust::Vec<uint8_t>| doesn't have |resize()|.
  ret.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(0);
  }
  tachyon_sp1_baby_bear_poseidon2_field_merkle_tree_serialize(tree_, ret.data(),
                                                              &size);
  return ret;
}

std::unique_ptr<ProverData> ProverData::clone() const {
  return std::make_unique<ProverData>(
      tachyon_sp1_baby_bear_poseidon2_field_merkle_tree_clone(tree_));
}

std::unique_ptr<ProverData> deserialize_prover_data(
    rust::Slice<const uint8_t> data) {
  return std::make_unique<ProverData>(
      tachyon_sp1_baby_bear_poseidon2_field_merkle_tree_deserialize(
          data.data(), data.size()));
}

}  // namespace tachyon::sp1_api::baby_bear_poseidon2
