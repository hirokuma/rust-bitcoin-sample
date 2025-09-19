use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Message, Secp256k1, SecretKey, Signing};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, WPubkeyHash, Witness,
};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000);

fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> Keypair {
    let sk = SecretKey::new(&mut rand::thread_rng());
    Keypair::from_secret_key(secp, &sk)
}

fn receivers_address() -> Address {
    Address::from_str("bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf")
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}

fn dummy_unspent_transaction_output(wpkh: &WPubkeyHash) -> (OutPoint, TxOut) {
    let script_pubkey = ScriptBuf::new_p2wpkh(wpkh);
    let out_point = OutPoint {
        txid: Txid::all_zeros(),
        vout: 0,
    };
    let utxo = TxOut {
        value: DUMMY_UTXO_AMOUNT,
        script_pubkey,
    };

    (out_point, utxo)
}

fn main() {
    let secp = Secp256k1::new();

    let keypair = senders_keys(&secp);
    let address = receivers_address();
    let pk = PublicKey::new(keypair.public_key());
    let wpkh = pk.wpubkey_hash().expect("key is compressed");
    let sk = keypair.secret_key();

    let (dummy_out_point, dummy_utxo) = dummy_unspent_transaction_output(&wpkh);

    let input = TxIn {
        previous_output: dummy_out_point,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let spend = TxOut {
        value: SPEND_AMOUNT,
        script_pubkey: address.script_pubkey(),
    };
    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };
    let input_index = 0;

    let sighash_type = EcdsaSighashType::All;
    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .p2wpkh_signature_hash(
            input_index, 
            &dummy_utxo.script_pubkey, 
            dummy_utxo.value,
            sighash_type)
        .expect("failed to create sighash");

    let msg = Message::from(sighash);
    let signature = secp.sign_ecdsa(&msg, &sk);
    let signature = bitcoin::ecdsa::Signature { signature, sighash_type };
    *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &pk.inner);

    let tx = sighasher.into_transaction();
    println!("{:#?}", tx);
}
