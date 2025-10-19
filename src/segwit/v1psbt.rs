use std::collections::BTreeMap;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    hashes::Hash,
    key::UntweakedPublicKey,
    locktime::absolute,
    secp256k1::{Secp256k1, Verification},

    transaction, Network, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence, 
    TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey
};

use super::common;
use common::{
    ADDRESS_OUT_V1, DUMMY_UTXO_AMOUNT, SPEND_AMOUNT, CHANGE_AMOUNT,
};

fn dummy_unspent_transaction_output<C: Verification>(
    secp: &Secp256k1<C>,
    internal_key: UntweakedPublicKey,
) -> Vec<(OutPoint, TxOut)> {
    let script_pubkey = ScriptBuf::new_p2tr(secp, internal_key, None);
    let out_point = OutPoint {
        txid: Txid::all_zeros(),
        vout: 0,
    };
    let utxo = TxOut {
        value: DUMMY_UTXO_AMOUNT,
        script_pubkey,
    };

    vec![(out_point, utxo)]
}

pub fn segwit_v1() -> Transaction {
    let secp = Secp256k1::new();

    let keypair = common::senders_keys(&secp);
    let priv_key = PrivateKey::new(keypair.secret_key(), Network::Bitcoin);
    let (internal_key, _) = keypair.x_only_public_key();
    let dummy_utxos = dummy_unspent_transaction_output(&secp, internal_key);
    let address = common::receivers_address(ADDRESS_OUT_V1);

    let input = TxIn {
        previous_output: dummy_utxos[0].0,
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

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("Could not create PSBT");
    let mut xonly_key_map: BTreeMap<XOnlyPublicKey, PrivateKey> = BTreeMap::new();
    xonly_key_map.insert(internal_key, priv_key);
    let key_source = (Fingerprint::default(), DerivationPath::default());
    let mut tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<bitcoin::TapLeafHash>, (Fingerprint, DerivationPath))> = std::collections::BTreeMap::new();
    // No tap script tree for this example; use an empty TapLeafHash vec as a placeholder.
    tap_key_origins.insert(internal_key, (vec![], key_source));
    psbt.inputs[0].tap_key_origins = tap_key_origins;
    psbt.inputs[0].witness_utxo = Some(dummy_utxos[0].1.clone());
    psbt.inputs[0].tap_internal_key = Some(internal_key);
    psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());

    psbt.sign(&xonly_key_map, &secp).expect("valid signature");

    psbt.inputs.iter_mut().for_each(|input| {
        // If a taproot key signature was produced, use it to finalize the witness.
        // Otherwise leave final_script_witness as None (caller may want to handle this).
        if let Some(sig) = input.tap_key_sig.as_ref() {
            let script_witness = Witness::p2tr_key_spend(sig);
            input.final_script_witness = Some(script_witness);
        }

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    psbt.extract_tx().expect("Failed to extract transaction from finalized PSBT")
}
