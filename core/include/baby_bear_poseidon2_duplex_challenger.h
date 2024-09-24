#ifndef CORE_INCLUDE_BABY_BEAR_POSEIDON2_DUPLEX_CHALLENGER_H_
#define CORE_INCLUDE_BABY_BEAR_POSEIDON2_DUPLEX_CHALLENGER_H_

#include <stdint.h>

#include <memory>

#include <tachyon/c/zk/air/sp1/baby_bear_poseidon2_duplex_challenger.h>

#include "rust/cxx.h"

namespace tachyon::sp1_api::baby_bear_poseidon2 {

struct TachyonBabyBear;

class DuplexChallenger {
 public:
  DuplexChallenger();
  explicit DuplexChallenger(
      tachyon_sp1_baby_bear_poseidon2_duplex_challenger* challenger)
      : challenger_(challenger) {}
  DuplexChallenger(const DuplexChallenger& other) = delete;
  DuplexChallenger& operator=(const DuplexChallenger& other) = delete;
  ~DuplexChallenger();

  tachyon_sp1_baby_bear_poseidon2_duplex_challenger* challenger() {
    return challenger_;
  }

  void observe(const TachyonBabyBear& value);
  rust::Box<TachyonBabyBear> sample();
  rust::Vec<uint8_t> write_hint() const;
  std::unique_ptr<DuplexChallenger> clone() const;

 private:
  tachyon_sp1_baby_bear_poseidon2_duplex_challenger* challenger_;
};

std::unique_ptr<DuplexChallenger> new_duplex_challenger();

}  // namespace tachyon::sp1_api::baby_bear_poseidon2

#endif  // CORE_INCLUDE_BABY_BEAR_POSEIDON2_DUPLEX_CHALLENGER_H_
