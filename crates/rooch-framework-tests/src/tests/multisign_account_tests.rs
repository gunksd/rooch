// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

use crate::binding_test;
use anyhow::Result;
use bitcoin::key::rand::rngs::OsRng;
use bitcoin::key::rand::{self, CryptoRng, Rng};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    address::{Address, AddressType},
    hex::DisplayHex,
    secp256k1::Secp256k1,
    PublicKey, XOnlyPublicKey,
};
use move_core_types::account_address::AccountAddress;
use move_core_types::ident_str;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::MoveValue;
use move_core_types::vm_status::{AbortLocation, KeptVMStatus, VMStatus};
use moveos_types::module_binding::MoveFunctionCaller;
use moveos_types::move_std::string::MoveString;
use moveos_types::move_types::FunctionId;
use moveos_types::{module_binding::ModuleBinding, transaction::MoveAction};
use musig2::secp::errors::InvalidPointBytes;
use musig2::secp256k1::SecretKey;
use musig2::{secp::Point, CompactSignature, KeyAggContext};
use musig2::{FirstRound, PartialSignature, SecNonceSpices};
use rooch_key::keystore::account_keystore::AccountKeystore;
use rooch_key::keystore::memory_keystore::InMemKeystore;
use rooch_types::address::BitcoinAddress;
use rooch_types::framework::session_key::SessionKeyModule;
use rooch_types::framework::session_validator::SessionValidatorModule;
use rooch_types::framework::timestamp::TimestampModule;
use rooch_types::{addresses::ROOCH_FRAMEWORK_ADDRESS, framework::empty::Empty};
use rooch_types::{framework::session_key::SessionScope, transaction::rooch::RoochTransactionData};
use std::str::FromStr;
use std::thread::Thread;

#[test]
fn test_session_multisign_account() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut binding_test = binding_test::RustBindingTest::new().unwrap();

    let keystore = InMemKeystore::new_insecure_for_tests(3);

    let u1 = keystore.addresses()[0];
    let u2 = keystore.addresses()[1];
    let u3 = keystore.addresses()[2];

    println!("u1: {:?}", u1);
    println!("u2: {:?}", u2);
    println!("u3: {:?}", u3);

    let sequence_number1 = 0;

    let kp1 = keystore.get_key_pair(&u1, None).unwrap();
    let kp2 = keystore.get_key_pair(&u2, None).unwrap();
    let kp3 = keystore.get_key_pair(&u3, None).unwrap();

    let pubkeys = vec![kp1.public(), kp2.public(), kp3.public()];
    for pubkey in &pubkeys {
        println!("pubkey: {}", hex::encode(pubkey.as_ref()));
    }

    let mut builder = TaprootBuilder::new();
    let threshold = 2;
    builder = builder.add_leaf(0, &bitcoin::Script::new_multisig(threshold, &pubkeys))?;

    let pubkeys = pubkeys
        .iter()
        .map(|pk| Point::from_slice(pk.as_ref()))
        .collect::<Result<Vec<_>, InvalidPointBytes>>()
        .unwrap();
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    let xonly_pubkey_bytes = aggregated_pubkey.serialize_xonly();

    let internal_key = XOnlyPublicKey::from_slice(&xonly_pubkey_bytes).unwrap();
    let pubkey = PublicKey::from_slice(aggregated_pubkey.serialize().as_ref()).unwrap();
    println!("pubkey: {}", pubkey);
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let bitcoin_addr = BitcoinAddress::from(bitcoin::Address::p2tr(
        &secp,
        internal_key,
        None,
        bitcoin::Network::Bitcoin,
    ));

    let rooch_addr = bitcoin_addr.to_rooch_address();
    println!("bitcoin_addr: {}", bitcoin_addr);
    println!("rooch_addr: {:?}", rooch_addr);

    let mut rng = rand::thread_rng();
    let nonce_seed = rng.gen::<[u8; 32]>();
    let message = b"Hello, Taproot Multisig!";

    let seckey1 = SecretKey::from_slice(kp1.private()).unwrap();
    let seckey2 = SecretKey::from_slice(kp2.private()).unwrap();
    let seckey3 = SecretKey::from_slice(kp3.private()).unwrap();

    let mut first_round1 = FirstRound::new(
        key_agg_ctx.clone(),
        nonce_seed,
        0,
        SecNonceSpices::new()
            .with_seckey(seckey1.clone())
            .with_message(&message),
    )
    .unwrap();

    let mut first_round2 = FirstRound::new(
        key_agg_ctx,
        nonce_seed,
        1,
        SecNonceSpices::new()
            .with_seckey(seckey2.clone())
            .with_message(&message),
    )
    .unwrap();

    first_round1
        .receive_nonce(1, first_round2.our_public_nonce())
        .unwrap();
    assert!(first_round1.is_complete(), "First round 1 is not complete");

    first_round2
        .receive_nonce(0, first_round1.our_public_nonce())
        .unwrap();

    let mut secord_round1 = first_round1.finalize(seckey1.clone(), message).unwrap();
    let mut secord_round2 = first_round2.finalize(seckey2.clone(), message).unwrap();

    let aggnonce = secord_round1.aggregated_nonce();
    let sig1: PartialSignature = secord_round1.our_signature();
    let sig2: PartialSignature = secord_round2.our_signature();

    secord_round1.receive_signature(1, sig2).unwrap();
    secord_round2.receive_signature(0, sig1).unwrap();

    let final_sig1: CompactSignature = secord_round1.finalize().unwrap();
    let final_sig2: CompactSignature = secord_round2.finalize().unwrap();

    assert_eq!(final_sig1, final_sig2);

    musig2::verify_single(aggregated_pubkey, final_sig1, message).unwrap();

    // // 第一轮：生成 nonces
    // let secret_nonce1 = SecretNonce::new(&mut rng);
    // let secret_nonce2 = SecretNonce::new(&mut rng);

    // let public_nonce1 = secret_nonce1.public_nonce();
    // let public_nonce2 = secret_nonce2.public_nonce();

    // // 聚合 nonces
    // let agg_nonce = PublicNonce::combine(&[public_nonce1, public_nonce2]).unwrap();

    // // 第二轮：生成部分签名
    // let partial_sig1 = MultiSignature::partial_sign(
    //     &secret_key1,
    //     &secret_nonce1,
    //     &agg_pubkey,
    //     &agg_nonce,
    //     message,
    // ).unwrap();

    // let partial_sig2 = MultiSignature::partial_sign(
    //     &secret_key2,
    //     &secret_nonce2,
    //     &agg_pubkey,
    //     &agg_nonce,
    //     message,
    // ).unwrap();
}
