use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Assigned, ConstraintSystem, Error},
};
use halo2_proofs::circuit::Value;
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{Advice, Column, Expression, Selector};
use halo2_proofs::poly::Rotation;

use crate::gadgets::range_check_with_bits::RangeCheckConfig;

/// This gadget range-constrains an element witnessed in the circuit to be N bits.
///
/// Internally, this gadget uses the `range_check` helper, which provides a K-bit
/// lookup table.
///
/// Given an element `value`, we use a running sum to break it into K-bit chunks.
/// Assume for now that N | K, and define C = N / K.
///
///     value = [b_0, b_1, ..., b_{N-1}]   (little-endian)
///           = c_0 + 2^K * c_1  + 2^{2K} * c_2 + ... + 2^{(C-1)K} * c_{C-1}
///
/// Initialise the running sum at
///                                 value = z_0.
///
/// Consequent terms of the running sum are z_{i+1} = (z_i - c_i) * 2^{-K}:
///
///                           z_1 = (z_0 - c_0) * 2^{-K}
///                           z_2 = (z_1 - c_1) * 2^{-K}
///                              ...
///                       z_{C-1} = c_{C-1}
///                           z_C = (z_{C-1} - c_{C-1}) * 2^{-K}
///                               = 0
///
/// One configuration for this gadget could look like:
///
///     | running_sum |  q_decompose  |  table_value  |
///     -----------------------------------------------
///     |     z_0     |       1       |       0       |
///     |     z_1     |       1       |       1       |
///     |     ...     |      ...      |      ...      |
///     |   z_{C-1}   |       1       |      ...      |
///     |     z_C     |       0       |      ...      |
///
/// Stretch task: use the tagged lookup table to constrain arbitrary bitlengths
/// (even non-multiples of K)
#[derive(Debug, Clone)]
struct DecomposeConfig<F: PrimeField> {
    // You'll need an advice column to witness your running sum;
    running_sum: Column<Advice>,
    c_i_bits: Column<Advice>,
    // A selector to constrain the running sum;
    // A selector to lookup the K-bit chunks;
    decompose_selector: Selector,
    // And of course, the K-bit lookup table
    table: RangeCheckConfig<F>,

    lookup_bits: usize,
}

impl<F: PrimeField + PrimeFieldBits> DecomposeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, running_sum: Column<Advice>, c_i_bits: Column<Advice>, lookup_bits: usize) -> Self {
        // Create the needed columns and internal configs.
        let decompose_selector = meta.complex_selector();

        let fixed_column = meta.fixed_column();

        meta.enable_constant(fixed_column);

        meta.enable_equality(running_sum);

        let two_to_k = Expression::Constant(F::from(1 << lookup_bits));

        // Range-constrain each K-bit chunk `c_i = z_i - z_{i+1} * 2^K` derived from the running sum.
        let table = RangeCheckConfig::configure(
            meta,
            |meta| {
                meta.query_advice(running_sum, Rotation::cur()) -
                    meta.query_advice(running_sum, Rotation::next()) * two_to_k
            },
            |meta| {
                meta.query_advice(c_i_bits, Rotation::next())
            },
            |meta| meta.query_selector(decompose_selector),
            1 << lookup_bits,
        );


        Self {
            running_sum,
            c_i_bits,
            decompose_selector,
            table,
            lookup_bits,
        }
    }

    fn bits_to_u64_little_endian(bits: &[bool]) -> u64 {
        assert!(bits.len() <= 64);
        bits.iter()
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedCell<Assigned<F>, F>,
        num_bits: usize,
    ) -> Result<(), Error> {
        // 0. Copy in the witnessed `value`

        layouter.assign_region(|| "decompose", |mut region| {
            let mut offset = 0;

            let mut z = value.copy_advice(
                || "copy first element of running sum",
                &mut region,
                self.running_sum,
                offset,
            )?;

            let value: Value<Vec<_>> = value
                .value()
                .map(|v| v.evaluate().to_le_bits().iter().by_vals().take(num_bits).collect());

            value.and_then(|v| {
                for chunk in v.chunks(self.lookup_bits) {
                    let mut zero_bits = 0;

                    for i in (0..self.lookup_bits).rev() {
                        let bit = chunk[i];
                        if bit {
                            break;
                        }
                        zero_bits += 1
                    }

                    let mut chunk_bits = chunk.len() - zero_bits;

                    if chunk_bits == 0 {
                        chunk_bits = 1;
                    }

                    let chunk_bits = Value::known(Assigned::from(F::from(chunk_bits as u64)));

                    offset += 1;
                    let chunk = Assigned::from(F::from(Self::bits_to_u64_little_endian(chunk)));

                    let z_i = z.value().map(|v| (v - chunk) * Assigned::from(F::from(1u64 << self.lookup_bits)).invert());

                    z = region.assign_advice(|| "z_i", self.running_sum, offset, || z_i).unwrap();
                    region.assign_advice(|| "c_i_bits", self.c_i_bits, offset, || chunk_bits).unwrap();
                }
                Value::<F>::unknown()
            });

            for i in 0..(num_bits / self.lookup_bits) {
                self.decompose_selector.enable(&mut region, i)?;
            }

            region.constrain_constant(z.cell(), F::ZERO)
        })
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;
    use halo2_proofs::plonk::Circuit;

    use super::*;

    #[derive(Default)]
    struct RangeCheckCircuit<F: PrimeField + PrimeFieldBits, const LOOKUP_BITS: usize> {
        value: Value<Assigned<F>>,
        num_bits: usize,
    }

    impl<F: PrimeField + PrimeFieldBits, const LOOKUP_BITS: usize> Circuit<F> for RangeCheckCircuit<F, LOOKUP_BITS> {
        type Config = DecomposeConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let running_sum = meta.advice_column();
            let c_i_bits = meta.advice_column();

            DecomposeConfig::configure(meta, running_sum, c_i_bits, LOOKUP_BITS)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            config.table.lookup_table.load(layouter.namespace(|| "lookup table"))?;

            let value = layouter.assign_region(|| "assign value somewhere", |mut region| {
                region.assign_advice(|| "value", config.running_sum, 0, || self.value)
            })?;

            config.assign(layouter.namespace(|| "assign running sum"), value, self.num_bits)
        }
    }


    #[test]
    fn test_range_check() {
        let circuit = RangeCheckCircuit::<Fp, 4> {
            value: Value::known(Fp::from(152).into()),
            num_bits: 8,
        };

        let prover = MockProver::run(5, &circuit, vec![]).unwrap();

        prover.assert_satisfied();
    }
}
