use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{Advice, Assigned, Column, Constraints, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

use crate::range_check::lookup::table::RangeCheckTable;

mod table;

#[derive(Clone, Debug)]
struct ExpressionConfig<F: PrimeField> {
    value: Column<Advice>,
    selector: Selector,
    lookup_table: RangeCheckTable<F>,
    lookup_selector: Selector,
    range: usize,
    lookup_range: usize,
}

impl<F: PrimeField> ExpressionConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, value: Column<Advice>, range: usize, lookup_range: usize) -> Self {
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
            let selector = meta.query_selector(lookup_selector);

            vec![
                (selector * value, lookup_table.value)
            ]
        });

        Self {
            value,
            selector,
            lookup_selector,
            lookup_table,
            range,
            lookup_range,
        }
    }

    fn assign(&self, mut layouter: impl Layouter<F>, value: Value<Assigned<F>>, range: usize) -> Result<(), Error> {
        assert!(range <= self.lookup_range);

        if range < self.range {
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
    }

    impl<F: PrimeField, const RANGE: usize, const LOOKUP_RANGE: usize> Circuit<F> for MyCircuit<F, RANGE, LOOKUP_RANGE> {
        type Config = ExpressionConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice = meta.advice_column();

            ExpressionConfig::configure(meta, advice, RANGE, LOOKUP_RANGE)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "Range check"), self.value, RANGE)?;

            config.assign(layouter.namespace(|| "Range check with lookup"), self.larger_value, LOOKUP_RANGE)?;

            config.lookup_table.load(layouter.namespace(|| "Lookup table"))
        }
    }


    #[test]
    fn test_range_check() {
        let k = 9;

        const RANGE: usize = 8;
        const LOOKUP_RANGE: usize = 256;

        for i in 0..RANGE {
            let circuit = MyCircuit::<Fp, RANGE, LOOKUP_RANGE> {
                value: Value::known(Fp::from(i as u64).into()),
                larger_value: Value::known(Fp::from(i as u64).into()),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();

            prover.assert_satisfied();
        }

        // let circuit = MyCircuit::<Fp, RANGE> {
        //     value: Value::known(Fp::from(RANGE as u64).into())
        // };
        //
        // let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        //
        // assert_eq!(
        //     prover.verify(),
        //     Err(vec![VerifyFailure::ConstraintNotSatisfied {
        //         constraint: ((0, "Range check").into(), 0, "range check").into(),
        //         location: FailureLocation::InRegion {
        //             region: (0, "range check").into(),
        //             offset: 0,
        //         },
        //         cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0x8".to_string())],
        //     }])
        // )
    }
}