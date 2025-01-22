use anchor_lang::prelude::*;
use anchor_lang::InstructionData;
use solana_alt_bn128_bls::{G1CompressedPoint, G2CompressedPoint, G1Point, G2Point, PrivKey, Sha256Normalized};
// use solana_program_test::*;
use solana_sdk::{
    transaction::Transaction,
};
use std::convert::TryFrom;
use std::str::FromStr;
use anchor_client::{
    solana_sdk::{
        signature::{read_keypair_file, Keypair},
        signer::Signer,
        system_program,
    },
    Client, Cluster,
};
use std::rc::Rc;
use latest_bls::{accounts, instruction};
use solana_sdk::instruction::Instruction;
use solana_sdk::commitment_config::CommitmentConfig;
use dirs::home_dir;


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_full_verification_on_chain() {
   let keypair_path = home_dir()
    .expect("Unable to get home directory")
    .join(".config/solana/id.json");

let payer = read_keypair_file(keypair_path)
    .expect("Failed to read keypair file");

   let client = Client::new_with_options(
       Cluster::Devnet,
       &payer,
       solana_sdk::commitment_config::CommitmentConfig::processed(),
   );
   let program_id = Pubkey::from_str("E4LXwvzGcZzdJfURbdLDW2BLqz73JLq9ncBd6NteYik").expect("Failed to parse program ID");
   let program = client.program(program_id).expect( "Failed to fetch program");
   

   // Step 2: Generate private keys and derive G2 points
   let private_keys: Vec<PrivKey> = (0..5)
       .map(|_| PrivKey::from_random())
       .collect();

   let g2_points: Vec<G2Point> = private_keys
       .iter()
       .map(|key| G2Point::try_from(key).expect("Failed to derive G2 point from private key"))
       .collect();

   // Step 3: Aggregate G2 points
   let mut aggregated_g2_point = g2_points[0].clone();
   for g2_point in g2_points.iter().skip(1) {
       aggregated_g2_point = aggregated_g2_point + g2_point.clone();
   }
   let aggregated_compressed_pubkey =
       G2CompressedPoint::try_from(&aggregated_g2_point).expect("Failed to compress G2 point");

   // Step 4: Generate aggregated G1 signature
   let message = b"500000.23456".to_vec();
   let g1_signatures: Vec<G1Point> = private_keys
       .iter()
       .map(|key| {
           key.sign::<Sha256Normalized, &[u8]>(&message)
               .expect("Failed to sign message with private key")
       })
       .collect();

   let mut aggregated_g1_signature = g1_signatures[0].clone();
   for g1_signature in g1_signatures.iter().skip(1) {
       aggregated_g1_signature = aggregated_g1_signature + g1_signature.clone();
   }

   let aggregated_compressed_signature =
       G1CompressedPoint::try_from(aggregated_g1_signature).expect("Failed to compress G1 signature");

       let instruction_data = latest_bls::instruction::VerifyAggregatedSignature {
           aggregated_compressed_pubkey: aggregated_compressed_pubkey.0,
           aggregated_compressed_signature: aggregated_compressed_signature.0,
           message: message.clone(),
       }
       .data();
   
       // Step 6: Get blockhash and build transaction
       let blockhash = program.rpc().get_latest_blockhash().expect("Failed to fetch blockhash");
       let verify_instruction = Instruction {
           program_id,
           accounts: vec![], // Add account metas here if required
           data: instruction_data,
       };
       let transaction = Transaction::new_signed_with_payer(
           &[ verify_instruction],
           Some(&payer.pubkey()),
           &[&payer],
           blockhash,
       );
   
       // Step 5: Send and confirm the transaction
    match program.rpc().send_and_confirm_transaction(&transaction) {
        Ok(signature) => println!("✅ Signature verified successfully! Transaction: {}", signature),
        Err(error) => {
            eprintln!("❌ Failed to verify signature: {:?}", error);
            panic!("Transaction failed");
        }
    }

}

//https://explorer.solana.com/tx/2DtkaayJ9d9DmLxhUFpZ761R5XZdzjBNLWaDLLjWBocvoz462CCUaLFdvg6bQ3o8bxqfgfduuFCqCaJjf6EAtHSt?cluster=devnet
//> Program logged: "Instruction: VerifyAggregatedSignature"
// > Program consumption: 199313 units remaining
// > Program consumption: 131281 units remaining
// > Program logged: "✅ Aggregated signature verified successfully!"
// > Program consumed: 68848 of 200000 compute units