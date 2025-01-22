#TO run against devnet deployed anchor program. 
```cargo test --package tests --lib -- test_initialize --show-output -- --nocapture```

`https://explorer.solana.com/tx/2DtkaayJ9d9DmLxhUFpZ761R5XZdzjBNLWaDLLjWBocvoz462CCUaLFdvg6bQ3o8bxqfgfduuFCqCaJjf6EAtHSt?cluster=devnet`
//> Program logged: "Instruction: VerifyAggregatedSignature"
// > Program consumption: 199313 units remaining
// > Program consumption: 131281 units remaining
// > Program logged: "✅ Aggregated signature verified successfully!"
// > Program consumed: 68848 of 200000 compute units

#To run unit test. 
`cargo test-sbf test_aggregated_verification_off_chain -- --nocapture`

