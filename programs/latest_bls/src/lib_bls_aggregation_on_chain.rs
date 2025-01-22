use anchor_lang::prelude::*;
use solana_alt_bn128_bls::*;
use std::convert::TryFrom;


declare_id!("7cpSxJfY5dqRWKAcAjVncK9BFDjq7hooWDY8PrzqxjCQ");

#[program]
pub mod latest_bls{
    use super::*;

    /// Initialize an Oracle account by storing its compressed G2 public key.
    pub fn initialize_oracle(ctx: Context<InitializeOracle>, g2_point_key: [u8; 128]) -> Result<()> {
        let oracle = &mut ctx.accounts.oracle;
        oracle.g2_point_key = g2_point_key; // Store the compressed G2 public key
        msg!("Oracle initialized with G2CompressedPoint: {:?}", g2_point_key);
        Ok(())
    }

   
    /// Verify the aggregated signature using the oracles' G2 compressed public keys.
    pub fn verify_signature(
        ctx: Context<VerifySignature>,
        aggregated_and_compressed_g1_signature: [u8; 32], // Aggregated G1 signature
        message: Vec<u8>,                                 // The message that was signed
    ) -> Result<()> {
        let aggregated_signature = G1CompressedPoint(aggregated_and_compressed_g1_signature); // Load the compressed G1 signature
        
        // Ensure there are remaining accounts to process
        let mut iter = ctx.remaining_accounts.iter();
        let first_account_info = iter.next().ok_or_else(|| error!(ErrorCode::NoOraclesProvided))?;

        // Step 1: Initialize `aggregated_g2_point` from the first account
        let first_oracle_data = &first_account_info.try_borrow_data()?[8..]; // Skip discriminator
        let first_g2_point: [u8; 128] = first_oracle_data
            .try_into()
            .map_err(|_| error!(ErrorCode::InvalidOracleAccount))?;

        let mut aggregated_g2_point = G2Point(first_g2_point); // Start aggregation with the first G2 point

        // Step 2: Iterate through the remaining accounts and aggregate G2 points
        for account_info in iter {
            // Deserialize the OracleAccount from account data
            let oracle_data = &account_info.try_borrow_data()?[8..]; // Skip discriminator
            let g2_point: [u8; 128] = oracle_data
                .try_into()
                .map_err(|_| error!(ErrorCode::InvalidOracleAccount))?;

            // Aggregate G2 points
            aggregated_g2_point = aggregated_g2_point + G2Point(g2_point);
        }
               // Step 4: Verify the aggregated G1 signature against the aggregated G2 point and message.
        aggregated_g2_point
            .verify_signature::<Sha256Normalized, &[u8], G1CompressedPoint>(
                aggregated_signature,
                &message,
            )
            .map_err(|_| {
                msg!("Signature verification failed.");
                error!(ErrorCode::SignatureVerificationFailed)
            })?;

        msg!("✅ Aggregated signature verified successfully!");
        Ok(())
    }
}

/// Accounts structure for initializing an Oracle.
#[derive(Accounts)]
pub struct InitializeOracle<'info> {
    #[account(init, payer = authority, space = 8 + 128)]
    pub oracle: Account<'info, OracleAccount>, // Oracle account to store the G2 compressed key
    #[account(mut)]
    pub authority: Signer<'info>, // The payer creating this account
    pub system_program: Program<'info, System>, // System program
}

/// Accounts structure for verifying a signature.
#[derive(Accounts)]
pub struct VerifySignature {}


/// Data structure for an Oracle account.
#[account]
pub struct OracleAccount {
    pub g2_point_key: [u8; 128], // Compressed G2 public key stored as raw bytes
}

// Custom error codes for the program.
#[error_code]
pub enum ErrorCode {
    #[msg("No oracles were provided in the accounts array.")]
    NoOraclesProvided,
    #[msg("Failed to decompress a G2 compressed public key.")]
    DecompressionFailed,
    #[msg("Failed to aggregate G2 public keys.")]
    AggregationFailed,
    #[msg("Signature verification failed.")]
    SignatureVerificationFailed,
    #[msg("Invalid oracle account provided.")]
    InvalidOracleAccount,
}


#[cfg(test)]
mod test {
    use super::*;
    use anchor_lang::prelude::*;
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
        pubkey::Pubkey,
        instruction::Instruction,
    };
    use crate::program;
    use solana_alt_bn128_bls::{G1CompressedPoint, PrivKey};
    use solana_bn254::prelude::*;
    use anchor_lang::InstructionData;
    use std::str::FromStr;
    use solana_sdk::compute_budget::ComputeBudgetInstruction;


#[tokio::test]
async fn test_initialize_and_verify_signature() {
    // Step 1: Set up the Solana test environment
    let program_id = Pubkey::from_str("7cpSxJfY5dqRWKAcAjVncK9BFDjq7hooWDY8PrzqxjCQ").unwrap();

    let mut program_test = ProgramTest::new(
        "latest_bls",               // Name of your program (crate name)
        program_id,                       // ID of your deployed program
        None, // Register the program's entrypoint
    );

    // Step 2: Add required accounts
    let oracle_account_1 = Keypair::new(); // Oracle 1 account
    let oracle_account_2 = Keypair::new(); // Oracle 2 account
    let authority = Keypair::new(); // Authority account
    let system_program = solana_sdk::system_program::id();
    
    // Step 3: Start the test environment
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    println!("Payer Pubkey: {}", payer.pubkey());
    println!("Authority Pubkey: {}", authority.pubkey());
    println!("Oracle 1 Pubkey: {}", oracle_account_1.pubkey());
    println!("Oracle 2 Pubkey: {}", oracle_account_2.pubkey());

    let private_key_1 = PrivKey::from_random();
    let private_key_2 = PrivKey::from_random();

    let g2_point_key_2 = G2Point::try_from(&private_key_2).expect("Invalid private key");// Example compressed G2 key for Oracle 1
    let g2_point_key_1: G2Point = G2Point::try_from(&private_key_1).expect("Invalid private key");// Example compressed G2 key for Oracle 1
    
    // Step 4: Initialize Oracle 1
    let tx = Transaction::new_signed_with_payer(
        &[Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(oracle_account_1.pubkey(), true), // Mark oracle as writable, not signing
                AccountMeta::new(payer.pubkey(), true),        // Authority is a signer
                AccountMeta::new_readonly(system_program, false),  // System program is read-only
            ],
            data: instruction::InitializeOracle {
                g2_point_key: g2_point_key_1.0,
            }
            .data(),
        }],
        Some(&payer.pubkey()),         // Payer for the transaction
        &[&payer, &oracle_account_1],        // Signers: Payer and authority
        recent_blockhash,
    );
    
    banks_client.process_transaction(tx).await.unwrap();

    // Step 5: Verify the Oracle 1 was initialized correctly
    let account_data = banks_client
        .get_account(oracle_account_1.pubkey())
        .await
        .unwrap()
        .unwrap();
    let oracle_data = OracleAccount::try_deserialize(&mut &account_data.data[..]).unwrap();
    assert_eq!(oracle_data.g2_point_key, g2_point_key_1.0);
    println!("✅ Oracle 1 initialized successfully!");

    // Step 6: Initialize Oracle 2
    let tx = Transaction::new_signed_with_payer(
        &[Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(oracle_account_2.pubkey(), true),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(system_program, false),
            ],
            data: instruction::InitializeOracle {
                g2_point_key: g2_point_key_2.0,
            }
            .data(),
        }],
        Some(&payer.pubkey()),
        &[&payer, &oracle_account_2],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Verify Oracle 2 was initialized
    let account_data = banks_client
        .get_account(oracle_account_2.pubkey())
        .await
        .unwrap()
        .unwrap();
    let oracle_data = OracleAccount::try_deserialize(&mut &account_data.data[..]).unwrap();
    assert_eq!(oracle_data.g2_point_key, g2_point_key_2.0);
    println!("✅ Oracle 2 initialized successfully!");

    // Step 7: Verify the aggregated signature
    let message = b"Test message".to_vec();
    let g1_signature_1 = private_key_1
        .sign::<Sha256Normalized, &[u8]>(&message)
        .expect("Failed to sign message with private key 1");
    let g1_signature_2 = private_key_2
        .sign::<Sha256Normalized, &[u8]>(&message)
        .expect("Failed to sign message with private key 2");
    let aggregated_g1_signature = g1_signature_1 + g1_signature_2;
    let aggregated_compressed_signature: G1CompressedPoint = G1CompressedPoint::try_from(aggregated_g1_signature)
        .expect("Failed to compress aggregated G1 signature");
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(2_000_000); // Increase budget

    let tx = Transaction::new_signed_with_payer(
        &[compute_budget_ix,
         Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(oracle_account_1.pubkey(), false),
                AccountMeta::new_readonly(oracle_account_2.pubkey(), false),
            ],
            data: instruction::VerifySignature {
                aggregated_and_compressed_g1_signature: aggregated_compressed_signature.0,
                message: message.clone(),
            }
            .data(),
        }],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let result = banks_client.process_transaction(tx).await;

    // Check result
    match result {
        Ok(_) => println!("✅ Signature verified successfully!"),
        Err(err) => panic!("❌ Signature verification failed: {:?}", err),
        }
    }

    #[test]
    fn test_initialize_and_verify_signature_locally() {
        // Step 1: Generate private keys and derive G2 points
        let private_key_1 = PrivKey::from_random();
        let private_key_2 = PrivKey::from_random();

        let g2_point_1 = G2Point::try_from(&private_key_1).expect("Failed to derive G2 point from private key 1");
        let g2_point_2 = G2Point::try_from(&private_key_2).expect("Failed to derive G2 point from private key 2");

        // Step 2: Aggregate G2 points
        let aggregated_g2_point = g2_point_1 + g2_point_2;

        // Verify aggregation
        // println!("✅ Aggregated G2 Point: {:?}", aggregated_g2_point);

        // Step 3: Generate an aggregated G1 signature (off-chain)
        let message = b"Test message".to_vec();
        let g1_signature_1 = private_key_1.sign::<Sha256Normalized, &[u8]>(&message).unwrap();
        let g1_signature_2 =private_key_2.sign::<Sha256Normalized, &[u8]>(&message).unwrap();

        // Aggregate G1 signatures (using point addition for simplicity)
        let aggregated_g1_signature = g1_signature_1 + g1_signature_2;
        let compressed_g1_agg_sig = G1CompressedPoint::try_from(aggregated_g1_signature).expect("Failed to compress aggregated G1 signature");
        // Verify G1 signature aggregation
        // println!("✅ Aggregated G1 Signature: {:?}", aggregated_g1_signature);

        // Step 4: Verify the aggregated signature
        let aggregated_g2_compressed = G2CompressedPoint::try_from(&aggregated_g2_point)
            .expect("Failed to compress aggregated G2 point");
    
        match aggregated_g2_compressed.verify_signature::<Sha256Normalized, &[u8], G1CompressedPoint>(
            compressed_g1_agg_sig,
            &message,
        ) {
            Ok(_) => println!("✅ Signature verified successfully!"),
            Err(err) => panic!("❌ Signature verification failed: {:?}", err),
        }
    }

//     #[test]
// fn test_initialize_and_verify_signature_with_five_keys() {
    // Step 1: Generate private keys and derive G2 points
//     let private_keys: Vec<PrivKey> = (0..5)
//         .map(|_| PrivKey::from_random())
//         .collect();

//     let g2_points: Vec<G2Point> = private_keys
//         .iter()
//         .map(|key| G2Point::try_from(key).expect("Failed to derive G2 point from private key"))
//         .collect();

//     // Step 2: Aggregate G2 points
//     // Step 2: Aggregate G2 points
//     let mut aggregated_g2_point = g2_points[0].clone(); // Start with the first valid G2 point
//     for g2_point in g2_points.iter().skip(1) {
//         aggregated_g2_point = aggregated_g2_point + g2_point.clone();
//     }

//     // Verify aggregation
//     // println!("✅ Aggregated G2 Point: {:?}", aggregated_g2_point);

//     // Step 3: Generate an aggregated G1 signature (off-chain)
//     let message = b"Test message".to_vec();
//     let g1_signatures: Vec<G1Point> = private_keys
//         .iter()
//         .map(|key| {
//             key.sign::<Sha256Normalized, &[u8]>(&message)
//                 .expect("Failed to sign message with private key")
//         })
//         .collect();

//     let mut aggregated_g1_signature = G1Point([0u8; 64]); // Start with a zeroed G1 signature
//     for g1_signature in g1_signatures {
//         aggregated_g1_signature = aggregated_g1_signature + g1_signature;
//     }

//     // Step 4: Verify the aggregated signature
//     let aggregated_g2_compressed = G2CompressedPoint::try_from(&aggregated_g2_point)
//         .expect("Failed to compress aggregated G2 point");

//     match aggregated_g2_compressed.verify_signature::<Sha256Normalized, _, _>(
//         aggregated_g1_signature,
//         &message,
//     ) {
//         Ok(_) => println!("✅ Signature verified successfully with 5 keys!"),
//         Err(err) => panic!("❌ Signature verification failed: {:?}", err),
//     }
// }
}