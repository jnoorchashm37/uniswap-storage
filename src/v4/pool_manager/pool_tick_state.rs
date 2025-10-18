use std::collections::HashMap;

use alloy_primitives::{Address, B256, U256, aliases::I24, keccak256};
use alloy_sol_types::SolValue;
use futures::StreamExt;

use crate::{
    StorageSlotFetcher,
    types::TickData,
    v4::{
        pool_manager::{
            pool_state::pool_manager_pool_state_slot,
            tick_bitmap::{next_tick_gt, normalize_tick, tick_initialized},
        },
        utils::{max_valid_tick, min_valid_tick},
    },
};

// tick state
pub const POOL_MANAGER_POOL_TICK_OFFSET_SLOT: u8 = 4;
pub const POOL_MANAGER_POOL_TICK_BITMAP_OFFSET_SLOT: u8 = 5;
pub const POOL_MANAGER_POOL_TICK_FEE_GROWTH_OUTSIDE0_X128_SLOT_OFFSET: u8 = 1;
pub const POOL_MANAGER_POOL_TICK_FEE_GROWTH_OUTSIDE1_X128_SLOT_OFFSET: u8 = 2;

pub fn pool_manager_pool_tick_slot(pool_id: U256, tick: I24) -> B256 {
    let inner = U256::from_be_bytes(pool_manager_pool_state_slot(pool_id).0)
        + U256::from(POOL_MANAGER_POOL_TICK_OFFSET_SLOT);
    keccak256((tick, inner).abi_encode())
}

pub fn pool_manager_pool_tick_bitmap_slot(pool_id: U256, word_position: i16) -> B256 {
    let inner = U256::from_be_bytes(pool_manager_pool_state_slot(pool_id).0)
        + U256::from(POOL_MANAGER_POOL_TICK_BITMAP_OFFSET_SLOT);
    keccak256((word_position, inner).abi_encode())
}

pub async fn pool_manager_pool_tick_fee_growth_outside<F: StorageSlotFetcher>(
    slot_fetcher: &F,
    pool_manager_address: Address,
    pool_id: B256,
    tick: I24,
    block_number: Option<u64>,
) -> eyre::Result<(U256, U256)> {
    let pool_tick_slot = pool_manager_pool_tick_slot(pool_id.into(), tick);
    let pool_tick_slot_base = U256::from_be_slice(pool_tick_slot.as_slice());

    let fee_growth_outside0_x128_slot = pool_tick_slot_base
        + U256::from(POOL_MANAGER_POOL_TICK_FEE_GROWTH_OUTSIDE0_X128_SLOT_OFFSET);
    let fee_growth_outside1_x128_slot = pool_tick_slot_base
        + U256::from(POOL_MANAGER_POOL_TICK_FEE_GROWTH_OUTSIDE1_X128_SLOT_OFFSET);

    let (fee_growth_outside0_x128, fee_growth_outside1_x128) = futures::try_join!(
        slot_fetcher.storage_at(
            pool_manager_address,
            fee_growth_outside0_x128_slot.into(),
            block_number
        ),
        slot_fetcher.storage_at(
            pool_manager_address,
            fee_growth_outside1_x128_slot.into(),
            block_number
        )
    )?;

    Ok((fee_growth_outside0_x128, fee_growth_outside1_x128))
}

pub async fn pool_manager_load_tick_map<F: StorageSlotFetcher>(
    slot_fetcher: &F,
    pool_manager_address: Address,
    pool_id: B256,
    tick_spacing: I24,
    start_tick: Option<I24>,
    end_tick: Option<I24>,
    block_number: Option<u64>,
) -> eyre::Result<HashMap<I24, TickData>> {
    let start_tick = start_tick
        .map(|t| normalize_tick(t, tick_spacing))
        .unwrap_or(min_valid_tick(tick_spacing));
    let end_tick = end_tick
        .map(|t| normalize_tick(t, tick_spacing))
        .unwrap_or(max_valid_tick(tick_spacing));

    let mut ct = start_tick;
    let mut initialized_ticks = Vec::new();
    while ct <= end_tick {
        let (_, tick) = next_tick_gt(
            slot_fetcher,
            pool_manager_address,
            tick_spacing,
            pool_id,
            ct,
            true,
            block_number,
        )
        .await?;
        initialized_ticks.push(tick);
        ct = tick;
    }

    let mut tick_data_loading_stream = futures::stream::iter(initialized_ticks)
        .map(async |tick| {
            let tick = I24::unchecked_from(tick);

            pool_manager_load_tick_data(
                slot_fetcher,
                pool_manager_address,
                tick_spacing,
                pool_id,
                tick,
                block_number,
            )
            .await
            .map(|d| (tick, d))
        })
        .buffer_unordered(1000);

    let mut loaded_tick_data = HashMap::new();
    while let Some(val) = tick_data_loading_stream.next().await {
        let (k, v) = val?;
        loaded_tick_data.insert(k, v);
    }

    Ok(loaded_tick_data)
}

pub async fn pool_manager_load_tick_data<F: StorageSlotFetcher>(
    slot_fetcher: &F,
    pool_manager_address: Address,
    tick_spacing: I24,
    pool_id: B256,
    tick: I24,
    block_number: Option<u64>,
) -> eyre::Result<TickData> {
    let pool_tick_slot = pool_manager_pool_tick_slot(pool_id.into(), tick);
    let pool_tick_slot_base = U256::from_be_slice(pool_tick_slot.as_slice());

    let liquidity_slot = pool_tick_slot_base;
    let fee_growth_outside0_x128_slot = pool_tick_slot_base
        + U256::from(POOL_MANAGER_POOL_TICK_FEE_GROWTH_OUTSIDE0_X128_SLOT_OFFSET);
    let fee_growth_outside1_x128_slot = pool_tick_slot_base
        + U256::from(POOL_MANAGER_POOL_TICK_FEE_GROWTH_OUTSIDE1_X128_SLOT_OFFSET);

    let (liquidity, fee_growth_outside0_x128, fee_growth_outside1_x128, is_initialized) = futures::try_join!(
        slot_fetcher.storage_at(pool_manager_address, liquidity_slot.into(), block_number),
        slot_fetcher.storage_at(
            pool_manager_address,
            fee_growth_outside0_x128_slot.into(),
            block_number
        ),
        slot_fetcher.storage_at(
            pool_manager_address,
            fee_growth_outside1_x128_slot.into(),
            block_number
        ),
        tick_initialized(
            slot_fetcher,
            pool_manager_address,
            tick_spacing,
            pool_id,
            tick,
            block_number,
        )
    )?;

    let liquidity_bytes: [u8; 32] = liquidity.to_be_bytes();

    Ok(TickData {
        tick,
        is_initialized,
        liquidity_net: i128::from_be_bytes(liquidity_bytes[..16].try_into().unwrap()),
        liquidity_gross: u128::from_be_bytes(liquidity_bytes[16..].try_into().unwrap()),
        fee_growth_outside0_x128,
        fee_growth_outside1_x128,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{V4_POOL_MANAGER_ADDRESS, eth_provider},
        v4::V4PoolKey,
    };
    use alloy_primitives::{address, aliases::U24};

    #[tokio::test]
    async fn test_pool_manager_pool_tick_fee_growth_outside() {
        let provider = eth_provider().await;
        let block_number = 0;

        let pool_key = V4PoolKey {
            currency0: address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"),
            currency1: address!("0xfff9976782d46cc05630d1f6ebab18b2324d6b14"),
            fee: U24::from(0x800000),
            tickSpacing: I24::unchecked_from(10),
            hooks: address!("0x0000000AA8c2Fb9b232F78D2B286dC2aE53BfAD4"),
        };

        let results = pool_manager_pool_tick_fee_growth_outside(
            &provider,
            V4_POOL_MANAGER_ADDRESS,
            pool_key.into(),
            I24::unchecked_from(190088),
            Some(block_number),
        )
        .await
        .unwrap();

        assert_eq!(results, (U256::default(), U256::default()));
    }

    #[tokio::test]
    async fn test_pool_manager_load_tick_map() {
        let provider = eth_provider().await;
        let block_number = 0;

        let pool_key = V4PoolKey {
            currency0: address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"),
            currency1: address!("0xfff9976782d46cc05630d1f6ebab18b2324d6b14"),
            fee: U24::from(0x800000),
            tickSpacing: I24::unchecked_from(10),
            hooks: address!("0x0000000AA8c2Fb9b232F78D2B286dC2aE53BfAD4"),
        };

        let tick_spacing = pool_key.tickSpacing;
        let pool_id = pool_key.into();

        let results = pool_manager_load_tick_map(
            &provider,
            V4_POOL_MANAGER_ADDRESS,
            pool_id,
            tick_spacing,
            None,
            None,
            Some(block_number),
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 8);
    }

    #[tokio::test]
    async fn test_pool_manager_load_tick_data() {
        let provider = eth_provider().await;
        let block_number = 0;

        let pool_key = V4PoolKey {
            currency0: address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"),
            currency1: address!("0xfff9976782d46cc05630d1f6ebab18b2324d6b14"),
            fee: U24::from(0x800000),
            tickSpacing: I24::unchecked_from(10),
            hooks: address!("0x0000000AA8c2Fb9b232F78D2B286dC2aE53BfAD4"),
        };

        let results = pool_manager_load_tick_data(
            &provider,
            V4_POOL_MANAGER_ADDRESS,
            I24::unchecked_from(10),
            pool_key.into(),
            I24::unchecked_from(0),
            Some(block_number),
        )
        .await
        .unwrap();

        assert_eq!(results.is_initialized, true);
        assert_eq!(results.liquidity_gross, 0);
        assert_eq!(results.liquidity_net, 0);
    }
}
