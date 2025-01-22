use solana_alt_bn128_bls::{G1CompressedPoint, G2CompressedPoint, G1Point, G2Point};
use anyhow::{Result, Context};

/// A struct for BLS utility functions.
pub struct BlsUtils;

impl BlsUtils {
    /// Aggregates a list of G1 points into a single G1 point.
    pub fn aggregate_g1_points(points: &[G1Point]) -> Result<G1Point> {
        if points.is_empty() {
            return Err(anyhow::anyhow!("No G1 points provided for aggregation"));
        }

        let mut aggregated = points[0].clone();
        for point in points.iter().skip(1) {
            aggregated = aggregated + point.clone();
        }
        Ok(aggregated)
    }

    /// Aggregates a list of G2 points into a single G2 point.
    pub fn aggregate_g2_points(points: &[G2Point]) -> Result<G2Point> {
        if points.is_empty() {
            return Err(anyhow::anyhow!("No G2 points provided for aggregation"));
        }

        let mut aggregated = points[0].clone();
        for point in points.iter().skip(1) {
            aggregated = aggregated + point.clone();
        }
        Ok(aggregated)
    }

    /// Aggregates a list of G1 points and compresses the result.
    pub fn aggregate_and_compress_g1_points(points: &[G1Point]) -> Result<[u8; 32]> {
        let aggregated = Self::aggregate_g1_points(points)?;
        G1CompressedPoint::try_from(aggregated) // Pass a reference to `aggregated`
        .map(|compressed| compressed.0)
        .map_err(|e| anyhow::anyhow!("Failed to compress aggregated G1 point: {:?}", e))
    }

    /// Aggregates a list of G2 points and compresses the result.
    pub fn aggregate_and_compress_g2_points(points: &[G2Point]) -> Result<[u8; 64]> {
        let aggregated = Self::aggregate_g2_points(points)?;
        G2CompressedPoint::try_from(&aggregated) // Pass a reference to `aggregated`
        .map(|compressed| compressed.0) // Extract the compressed byte array
        .map_err(|e| anyhow::anyhow!("Failed to compress aggregated G2 point: {:?}", e)) // Convert the error to `anyhow::Error`
}
}