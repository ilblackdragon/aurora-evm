use crate::engine::{hash, CHAIN_ID, GAS};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use primitive_types::{H160, U256};
use rand::{rngs::OsRng, RngCore};
use rlp::{Rlp, RlpStream};

pub fn secret() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn key_id(secret: &str) -> [u8; 32] {
    hash(secret.as_bytes())
}
pub fn fixture_identity(seed: u8) -> (H160, String) {
    let bytes = [seed; 32];
    let key = SigningKey::from_bytes((&bytes).into()).unwrap();
    (
        address(key.verifying_key()),
        format!("0x{}", hex::encode(bytes)),
    )
}
fn address(key: &VerifyingKey) -> H160 {
    H160::from_slice(&hash(&key.to_encoded_point(false).as_bytes()[1..])[12..])
}
pub struct SignedTx {
    pub sender: H160,
    pub to: H160,
    pub nonce: U256,
    pub data: Vec<u8>,
    pub hash: [u8; 32],
    pub gas: u64,
}
// Demo supports canonical EIP-155 legacy transactions with zero value/gas price.
// Authentication never comes from the URL's claimed `from` or unsigned calldata.
pub fn decode(raw: &[u8]) -> Result<SignedTx, ()> {
    if raw.len() > 65536 {
        return Err(());
    }
    let r = Rlp::new(raw);
    if !r.is_list()
        || r.item_count().map_err(|_| ())? != 9
        || r.payload_info().map_err(|_| ())?.total() != raw.len()
    {
        return Err(());
    }
    let nonce: U256 = r.val_at(0).map_err(|_| ())?;
    let price: U256 = r.val_at(1).map_err(|_| ())?;
    let gas: U256 = r.val_at(2).map_err(|_| ())?;
    let to: Vec<u8> = r.val_at(3).map_err(|_| ())?;
    let value: U256 = r.val_at(4).map_err(|_| ())?;
    let data: Vec<u8> = r.val_at(5).map_err(|_| ())?;
    let v: U256 = r.val_at(6).map_err(|_| ())?;
    let rr: U256 = r.val_at(7).map_err(|_| ())?;
    let ss: U256 = r.val_at(8).map_err(|_| ())?;
    if to.len() != 20
        || !value.is_zero()
        || !price.is_zero()
        || gas < U256::from(21000)
        || gas > GAS.into()
    {
        return Err(());
    }
    let base = U256::from(CHAIN_ID * 2 + 35);
    if v != base && v != base + 1 {
        return Err(());
    }
    let mut canonical = RlpStream::new_list(9);
    canonical
        .append(&nonce)
        .append(&price)
        .append(&gas)
        .append(&to)
        .append(&value)
        .append(&data)
        .append(&v)
        .append(&rr)
        .append(&ss);
    if canonical.out().as_ref() != raw {
        return Err(());
    }
    let mut signing = RlpStream::new_list(9);
    signing
        .append(&nonce)
        .append(&price)
        .append(&gas)
        .append(&to)
        .append(&value)
        .append(&data)
        .append(&CHAIN_ID)
        .append(&0u8)
        .append(&0u8);
    let signature =
        Signature::from_scalars(rr.to_big_endian(), ss.to_big_endian()).map_err(|_| ())?;
    if signature.normalize_s().is_some() {
        return Err(());
    }
    let recovery = RecoveryId::try_from(u8::try_from((v - base).low_u64()).map_err(|_| ())?)
        .map_err(|_| ())?;
    let key = VerifyingKey::recover_from_prehash(&hash(&signing.out()), &signature, recovery)
        .map_err(|_| ())?;
    Ok(SignedTx {
        sender: address(&key),
        to: H160::from_slice(&to),
        nonce,
        data,
        hash: hash(raw),
        gas: gas.low_u64(),
    })
}
