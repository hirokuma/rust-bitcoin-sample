use std::str::FromStr;

use bitcoin::key::Keypair;
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey, Signing};
use bitcoin::{Address, Amount, Network};

pub const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
pub const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
pub const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000);

pub const ADDRESS_OUT_V0: &str = "bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf";
pub const ADDRESS_OUT_V1: &str = "bc1p0dq0tzg2r780hldthn5mrznmpxsxc0jux5f20fwj0z3wqxxk6fpqm7q0va";

pub fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> Keypair {
    let sk = SecretKey::new(&mut rand::thread_rng());
    Keypair::from_secret_key(secp, &sk)
}

pub fn receivers_address(addr: &str) -> Address {
    Address::from_str(addr)
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}
