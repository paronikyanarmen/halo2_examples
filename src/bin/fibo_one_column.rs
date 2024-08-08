use std::marker::PhantomData;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug)]
struct FiboConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

trait Instructions<F: Field>: Chip<F> {
    type Cell;
    fn assign(&self, layouter: impl Layouter<F>, first: Value<F>, second: Value<F>) -> Result<Self::Cell, Error>;

    fn expose_public(&self, layouter: impl Layouter<F>, c: &ACell<F>) -> Result<(), Error>;
}

struct FiboChip<F: Field> {
    config: FiboConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct ACell<F: Field>(AssignedCell<F, F>);

impl<F: Field> Instructions<F> for FiboChip<F> {
    type Cell = ACell<F>;

    fn assign(&self, mut layouter: impl Layouter<F>, first: Value<F>, second: Value<F>) -> Result<Self::Cell, Error> {
        let config = self.config();

        layouter.assign_region(
            || "table",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let mut a = region.assign_advice(|| "first", config.advice, 0, || first).map(ACell)?;
                let mut b = region.assign_advice(|| "second", config.advice, 1, || second).map(ACell)?;

                for i in 2..10 {
                    if i < 8 {
                        config.selector.enable(&mut region, i)?;
                    }

                    let c_cell = region.assign_advice(
                        || "next",
                        config.advice,
                        i,
                        || a.0.value().cloned() + b.0.value()
                    ).map(ACell)?;

                    a = b;
                    b = c_cell;
                }

                Ok(b)
            },
        )
    }

    fn expose_public(&self, mut layouter: impl Layouter<F>, c: &ACell<F>) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(c.0.cell(), config.instance, 0)
    }
}

impl<F: Field> Chip<F> for FiboChip<F> {
    type Config = FiboConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> FiboChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }


    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: Column<Advice>,
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        let selector = meta.selector();

        meta.enable_equality(advice);

        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());
            let c = meta.query_advice(advice, Rotation(2));

            let s = meta.query_selector(selector);

            vec![s * (a + b - c)]
        });

        FiboConfig {
            advice,
            instance,
            selector,
        }
    }
}

#[derive(Default)]
struct FiboCircuit<F: Field> {
    first: Value<F>,
    second: Value<F>,
}

impl<F: Field> Circuit<F> for FiboCircuit<F> {
    type Config = FiboConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();

        let instance = meta.instance_column();

        FiboChip::configure(meta, advice, instance)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = FiboChip::construct(config);

        let last_cell = chip.assign(layouter.namespace(|| "first row"), self.first, self.second)?;

        chip.expose_public(layouter.namespace(|| ""), &last_cell)
    }
}

fn main() {
    let first = Fp::from(1);
    let second = Fp::from(1);

    let last = Fp::from(55);

    let circuit = FiboCircuit {
        first: Value::known(first),
        second: Value::known(second),
    };

    let public_inputs = vec![last];

    let prover = MockProver::run(4, &circuit, vec![public_inputs]).unwrap();

    prover.assert_satisfied();
}