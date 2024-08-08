use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{Advice, Assigned, Column, Constraints, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

pub use crate::range_check::lookup_with_bits::table::RangeCheckTable;

mod table;

#[derive(Clone, Debug)]
pub struct RangeCheckConfig<F: PrimeField> {
    value: Column<Advice>,
    bits: Column<Advice>,
    selector: Selector,
    lookup_table: RangeCheckTable<F>,
    lookup_selector: Selector,
    range: usize,
    lookup_range: usize,
}

impl<F: PrimeField> RangeCheckConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        value: Column<Advice>,
        bits: Column<Advice>,
        range: usize,
        lookup_range: usize,
    ) -> Self {
        let selector = meta.selector();

        meta.create_gate(
            "Range check",
            |meta| {
                let value = meta.query_advice(value, Rotation::cur());
                let selector = meta.query_selector(selector);

                let value = (0..range).fold(value.clone(), |expr, i| {
                    expr * (Expression::Constant(F::from(i as u64)) - value.clone())
                });

                Constraints::with_selector(selector, [("range check", value)])
            },
        );

        let lookup_selector = meta.complex_selector();

        let lookup_table = RangeCheckTable::configure(meta, lookup_range);

        meta.lookup(|meta| {
            let value = meta.query_advice(value, Rotation::cur());
            let bits = meta.query_advice(bits, Rotation::cur());
            let selector = meta.query_selector(lookup_selector);

            let not_selector = Expression::Constant(F::ONE) - selector.clone();

            let bits_default = Expression::Constant(F::ONE);

            let bits = not_selector.clone() * bits_default + selector.clone() * bits;

            vec![
                (selector * value, lookup_table.value),
                (bits, lookup_table.bits),
            ]
        });

        Self {
            value,
            bits,
            selector,
            lookup_selector,
            lookup_table,
            range,
            lookup_range,
        }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<Assigned<F>>,
        bits: Value<Assigned<F>>,
        range: usize,
    ) -> Result<(), Error> {
        assert!(range <= self.lookup_range);

        if range <= self.range {
            layouter.assign_region(
                || "range check",
                |mut region| {
                    self.selector.enable(&mut region, 0)?;
                    region.assign_advice(|| "value", self.value, 0, || value)?;

                    Ok(())
                },
            )
        } else {
            layouter.assign_region(
                || "range check with lookup table",
                |mut region| {
                    self.lookup_selector.enable(&mut region, 0)?;
                    region.assign_advice(|| "value", self.value, 0, || value)?;
                    region.assign_advice(|| "bits", self.bits, 0, || bits)?;

                    Ok(())
                },
            )
        }
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
    struct MyCircuit<F: PrimeField, const RANGE: usize, const LOOKUP_RANGE: usize> {
        value: Value<Assigned<F>>,
        larger_value: Value<Assigned<F>>,
        larger_value_bits: Value<Assigned<F>>,
    }

    impl<F: PrimeField, const RANGE: usize, const LOOKUP_RANGE: usize> Circuit<F> for MyCircuit<F, RANGE, LOOKUP_RANGE> {
        type Config = RangeCheckConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice = meta.advice_column();
            let bits = meta.advice_column();

            RangeCheckConfig::configure(meta, advice, bits, RANGE, LOOKUP_RANGE)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "Range check"), self.value, Value::known(F::ZERO.into()), RANGE)?;

            config.assign(layouter.namespace(|| "Range check with lookup"), self.larger_value, self.larger_value_bits, LOOKUP_RANGE)?;

            config.lookup_table.load(layouter.namespace(|| "Lookup table"))
        }
    }


    #[test]
    fn test_range_check() {
        let k = 9;

        const RANGE: usize = 8;
        const LOOKUP_RANGE: usize = 256;

        let circuit = MyCircuit::<Fp, RANGE, LOOKUP_RANGE> {
            value: Value::known(Fp::from(5u64).into()),
            larger_value: Value::known(Fp::from(152u64).into()),
            larger_value_bits: Value::known(Fp::from(8u64).into()),
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        prover.assert_satisfied();
    }
}