pub mod mpt;
pub mod preflight;
pub mod provider_db;

use anyhow::Context;
use guest_lib::{builder::OptimismStrategy, consts::ChainSpec, input::BlockBuildInput};
use guest_primitives::transactions::optimism::OptimismTxEssence;
use preflight::Preflight;
use std::path::{Path, PathBuf};

fn cache_file_path(cache_dir: &String, block_no: u64, ext: &str) -> PathBuf {
    let dir = Path::new(cache_dir);
    std::fs::create_dir_all(cache_dir).expect("Could not create directory");
    dir.join(block_no.to_string()).with_extension(ext)
}

pub async fn new_block_build_input(
    chain_spec: &ChainSpec,
    rpc_url: Option<String>,
    cache_dir: Option<String>,
    block_no: u64,
) -> BlockBuildInput<OptimismTxEssence> {
    let chain_spec = chain_spec.clone();
    let cache_path = cache_dir.map(|dir| cache_file_path(&dir, block_no, "json.gz"));

    let preflight_result = tokio::task::spawn_blocking(move || {
        OptimismStrategy::preflight_with_external_data(&chain_spec, cache_path, rpc_url, block_no)
    })
    .await
    .unwrap();
    let preflight_data = preflight_result.context("preflight failed").unwrap();

    // Create the guest input from [Init]
    preflight_data
        .clone()
        .try_into()
        .context("invalid preflight data")
        .unwrap()
}
