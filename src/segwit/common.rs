use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, IntoDerivationPath, Xpriv};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey, Signing};
use bitcoin::{Address, Amount, Network};

pub const XPRIV: &str = "xprv9tuogRdb5YTgcL3P8Waj7REqDuQx4sXcodQaWTtEVFEp6yRKh1CjrWfXChnhgHeLDuXxo2auDZegMiVMGGxwxcrb2PmiGyCngLxvLeGsZRq";
pub const BIP86_DERIVATION_PATH: &str = "m/86'/0'/0'";
pub const MASTER_FINGERPRINT: &str = "9680603f";

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

pub fn get_external_address_xpriv<C: Signing>(
    secp: &Secp256k1<C>,
    master_xpriv: Xpriv,
    index: u32,
) -> Xpriv {
    let derivation_path =
        BIP86_DERIVATION_PATH.into_derivation_path().expect("valid derivation path");
    let child_xpriv = master_xpriv
        .derive_priv(secp, &derivation_path)
        .expect("valid child xpriv");
    let external_index = ChildNumber::from_normal_idx(0).unwrap();
    let idx = ChildNumber::from_normal_idx(index).expect("valid index number");

    child_xpriv
        .derive_priv(secp, &[external_index, idx])
        .expect("valid xpriv")
}

pub fn get_internal_address_xpriv<C: Signing>(
    secp: &Secp256k1<C>,
    master_xpriv: Xpriv,
    index: u32,
) -> Xpriv {
    let derivation_path =
        BIP86_DERIVATION_PATH.into_derivation_path().expect("valid derivation path");
    let child_xpriv = master_xpriv
        .derive_priv(secp, &derivation_path)
        .expect("valid child xpriv");
    let internal_index = ChildNumber::from_normal_idx(1).unwrap();
    let idx = ChildNumber::from_normal_idx(index).expect("valid index number");

    child_xpriv
        .derive_priv(secp, &[internal_index, idx])
        .expect("valid xpriv")
}
