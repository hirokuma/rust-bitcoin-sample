use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedKeypair, UntweakedPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{Message, Secp256k1, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction,  OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

use super::common::{
    ADDRESS_OUT_V1, DUMMY_UTXO_AMOUNT, SPEND_AMOUNT, CHANGE_AMOUNT,
    senders_keys, receivers_address,
};

fn dummy_unspent_transaction_output<C: Verification>(
    secp: &Secp256k1<C>,
    internal_key: UntweakedPublicKey,
) -> (OutPoint, TxOut) {
    let script_pubkey = ScriptBuf::new_p2tr(secp, internal_key, None);
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

pub fn segwit_v1() {
    let secp = Secp256k1::new();

    let keypair = senders_keys(&secp);
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (dummy_out_point, dummy_utxo) = dummy_unspent_transaction_output(&secp, internal_key);
    let address = receivers_address(ADDRESS_OUT_V1);

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
        script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };
    let input_index = 0;

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![dummy_utxo];
    let prevouts = Prevouts::All(&prevouts);
    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked.to_keypair());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };
    sighasher.witness_mut(input_index).unwrap().push(&signature.to_vec());

    let tx = sighasher.into_transaction();
    println!("{:#?}", tx);
}
