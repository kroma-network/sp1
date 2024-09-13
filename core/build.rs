fn main() {
    let src_files = [
        "src/baby_bear_poseidon2_commitment_vec.cc",
        "src/baby_bear_poseidon2_domains.cc",
        "src/baby_bear_poseidon2_duplex_challenger.cc",
        "src/baby_bear_poseidon2_fri_proof.cc",
        "src/baby_bear_poseidon2_lde_vec.cc",
        "src/baby_bear_poseidon2_opened_values.cc",
        "src/baby_bear_poseidon2_opening_points.cc",
        "src/baby_bear_poseidon2_opening_proof.cc",
        "src/baby_bear_poseidon2_prover_data_vec.cc",
        "src/baby_bear_poseidon2_prover_data.cc",
        "src/baby_bear_poseidon2_two_adic_fri_pcs.cc",
    ];
    cxx_build::bridges(["src/baby_bear_poseidon2.rs"])
        .files(src_files)
        .flag_if_supported("-std=c++17")
        .compile("sp1-core");

    let mut dep_files = vec![
        "include/baby_bear_poseidon2_commitment_vec.h",
        "include/baby_bear_poseidon2_domains.h",
        "include/baby_bear_poseidon2_duplex_challenger.h",
        "include/baby_bear_poseidon2_fri_proof.h",
        "include/baby_bear_poseidon2_lde_vec.h",
        "include/baby_bear_poseidon2_opened_values.h",
        "include/baby_bear_poseidon2_opening_points.h",
        "include/baby_bear_poseidon2_opening_proof.h",
        "include/baby_bear_poseidon2_prover_data_vec.h",
        "include/baby_bear_poseidon2_prover_data.h",
        "include/baby_bear_poseidon2_two_adic_fri_pcs.h",
        "src/baby_bear_poseidon2.rs",
    ];
    dep_files.extend_from_slice(&src_files);
    for file in dep_files {
        println!("cargo:rerun-if-changed={file}");
    }

    println!("cargo:rustc-link-lib=dylib=tachyon");
}
