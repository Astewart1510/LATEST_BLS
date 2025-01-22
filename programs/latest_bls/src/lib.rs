use anchor_lang::prelude::*;
use solana_alt_bn128_bls::{G1CompressedPoint, G1Point, G2CompressedPoint, Sha256Normalized};
use std::convert::TryFrom;
pub mod utils;


declare_id!("E4LXwvzGcZzdJfURbdLDW2BLqz73JLq9ncBd6NteYik");
#[program]
pub mod latest_bls {
    use solana_program::log::sol_log_compute_units;

    use super::*;


    /// Verify the aggregated signature against the aggregated public key and message.
    pub fn verify_aggregated_signature(
        ctx: Context<VerifySignature>,
        aggregated_compressed_pubkey: [u8; 64], // Aggregated and compressed G2 public key
        aggregated_compressed_signature: [u8; 32], // Aggregated and compressed G1 signature
        message: Vec<u8>, // The message that was signed
    ) -> Result<()> {
        let aggregated_pubkey = G2CompressedPoint(aggregated_compressed_pubkey); // Load the compressed G2 public key
        let aggregated_signature = G1CompressedPoint(aggregated_compressed_signature); // Load the compressed G1 signature
        sol_log_compute_units();
        // Verify the aggregated signature
        aggregated_pubkey
            .verify_signature::<Sha256Normalized, &[u8], G1CompressedPoint>(
                aggregated_signature,
                &message,
            )
            .map_err(|_| {
                msg!("Signature verification failed.");
                error!(ErrorCode::SignatureVerificationFailed)
            })?;
        sol_log_compute_units();

        msg!("✅ Aggregated signature verified successfully!");
        Ok(())
    }
}


/// Accounts structure for verifying a signature.
#[derive(Accounts)]
pub struct VerifySignature {}

/// Custom error codes for the program.
#[error_code]
pub enum ErrorCode {
    #[msg("Signature verification failed.")]
    SignatureVerificationFailed,
}


#[cfg(test)]
mod test {
    use super::*;
    use anchor_lang::prelude::*;
    use solana_program_test::*;
    use solana_sdk::{
        signer::Signer,
        transaction::Transaction,
        pubkey::Pubkey,
        instruction::Instruction,
    };
    use utils::BlsUtils;
    use crate::program;
    use solana_alt_bn128_bls::{G1CompressedPoint, PrivKey, G2CompressedPoint, G2Point};
    use anchor_lang::InstructionData;
    use std::str::FromStr;
    use solana_sdk::compute_budget::ComputeBudgetInstruction;

    #[tokio::test]
    async fn test_aggregated_verification_off_chain() {
         // Step 1: Set up the Solana test environment
         let program_id = Pubkey::from_str("E4LXwvzGcZzdJfURbdLDW2BLqz73JLq9ncBd6NteYik").unwrap();
         let mut program_test = ProgramTest::new(
             "latest_bls", 
             program_id, 
             None,
         );
        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        // Step 1: Generate private keys and derive G2 points
        let private_keys: Vec<PrivKey> = (0..5)
            .map(|_| PrivKey::from_random())
            .collect();
        let g2_points: Vec<G2Point> = private_keys
            .iter()
            .map(|key| G2Point::try_from(key).expect("Failed to derive G2 point from private key"))
            .collect();
    
        // Step 2: Aggregate G2 points
        // let mut aggregated_g2_point = g2_points[0].clone(); // Start with the first valid G2 point
        // for g2_point in g2_points.iter().skip(1) {
        //     aggregated_g2_point = aggregated_g2_point + g2_point.clone();
        // }
        // // Compress aggregated G2 point
        // let aggregated_compressed_pubkey =
        //     G2CompressedPoint::try_from(&aggregated_g2_point).expect("Failed to compress G2 point");
        let aggregated_compressed_pubkey = BlsUtils::aggregate_and_compress_g2_points(&g2_points).expect("Failed to aggregate and compress G2 points");
    
        // Step 3: Generate an aggregated G1 signature (off-chain)
        let message = b"500000.23456".to_vec();
        let g1_signatures: Vec<G1Point> = private_keys
            .iter()
            .map(|key| {
                key.sign::<Sha256Normalized, &[u8]>(&message)
                    .expect("Failed to sign message with private key")
            })
            .collect();
    
        // let mut aggregated_g1_signature = g1_signatures[0].clone(); // Start with the first valid G1 signature
        // for g1_signature in g1_signatures.iter().skip(1) {
        //     aggregated_g1_signature = aggregated_g1_signature + g1_signature.clone();
        // }
    
        // // Compress aggregated G1 signature
        // let aggregated_compressed_signature =
        //     G1CompressedPoint::try_from(aggregated_g1_signature).expect("Failed to compress G1 signature");
        let aggregated_compressed_signature = BlsUtils::aggregate_and_compress_g1_points(&g1_signatures).expect("Failed to aggregate and compress G1 points");
        
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(2_000_000);
        let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: crate::instruction::VerifyAggregatedSignature {
                    aggregated_compressed_pubkey: aggregated_compressed_pubkey,
                    aggregated_compressed_signature: aggregated_compressed_signature,
                    message: message.clone(),
                }
                .data(),
        };
        
        let tx = Transaction::new_signed_with_payer(
            &[compute_budget_ix, instruction],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );

        // Step 7: Send the transaction and verify the result
        let result = banks_client.process_transaction(tx).await;
        match result {
            Ok(_) => println!("✅ Signature verified successfully on-chain!"),
            Err(err) => panic!("❌ Signature verification failed on-chain: {:?}", err),
        }
    }
}