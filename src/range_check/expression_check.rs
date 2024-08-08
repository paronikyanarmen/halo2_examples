use std::marker::PhantomData;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{Advice, Assigned, Column, Constraints, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug)]
struct ExpressionConfig<F: PrimeField> {
    value: Column<Advice>,
    selector: Selector,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> ExpressionConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, value: Column<Advice>, range: usize) -> Self {
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

        Self {
            value,
            selector,
            _marker: PhantomData,
        }
    }

    fn assign(&self, mut layouter: impl Layouter<F>, value: Value<Assigned<F>>) -> Result<(), Error> {
        layouter.assign_region(
            || "range check",
            |mut region| {
                self.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "value", self.value, 0, || value)?;

                Ok(())
            })
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::{FailureLocation, MockProver, VerifyFailure};
    use halo2_proofs::pasta::Fp;
    use halo2_proofs::plonk::{Any, Circuit};

    use super::*;

    #[derive(Default)]
    struct MyCircuit<F: PrimeField, const RANGE: usize> {
        value: Value<Assigned<F>>,
    }

    impl<F: PrimeField, const RANGE: usize> Circuit<F> for MyCircuit<F, RANGE> {
        type Config = ExpressionConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice = meta.advice_column();

            ExpressionConfig::configure(meta, advice, RANGE)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "Range check"), self.value)
        }
    }


    #[test]
    fn test_range_check() {
        let k = 4;

        const RANGE: usize = 8;

        for i in 0..RANGE {
            let circuit = MyCircuit::<Fp, RANGE> {
                value: Value::known(Fp::from(i as u64).into())
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();

            prover.assert_satisfied();
        }

        let circuit = MyCircuit::<Fp, RANGE> {
            value: Value::known(Fp::from(RANGE as u64).into())
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: ((0, "Range check").into(), 0, "range check").into(),
                location: FailureLocation::InRegion {
                    region: (0, "range check").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0x8".to_string())]
            }])
        )
    }
}