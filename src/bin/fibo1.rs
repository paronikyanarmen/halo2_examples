use std::marker::PhantomData;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug)]
struct FiboConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    selector: Selector,
}

trait Instructions<F: Field>: Chip<F> {
    type Cell;
    fn assign_first_row(&self, layouter: impl Layouter<F>, first: Value<F>, second: Value<F>) -> Result<(Self::Cell, Self::Cell), Error>;

    fn assign_next_row(&self, layouter: impl Layouter<F>, b_prev: &ACell<F>, c_prev: &ACell<F>) -> Result<Self::Cell, Error>;

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

    fn assign_first_row(&self, mut layouter: impl Layouter<F>, first: Value<F>, second: Value<F>) -> Result<(Self::Cell, Self::Cell), Error> {
        let config = self.config();

        layouter.assign_region(
            || "fisrt row",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                region.assign_advice(|| "a", config.advice[0], 0, || first).map(ACell)?;

                let b_cell = region.assign_advice(
                    || "b",
                    config.advice[1],
                    0,
                    || second,
                ).map(ACell)?;

                let c_cell = region.assign_advice(
                    || "c",
                    config.advice[2],
                    0,
                    || first + second,
                ).map(ACell)?;


                Ok((b_cell, c_cell))
            },
        )
    }

    fn assign_next_row(&self, mut layouter: impl Layouter<F>, prev_b: &ACell<F>, prev_c: &ACell<F>) -> Result<Self::Cell, Error> {
        let config = self.config();

        layouter.assign_region(
            || "next row",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                prev_b.0.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                prev_c.0.copy_advice(|| "b", &mut region, config.advice[1], 0)?;

                let c_cell = region.assign_advice(
                    || "c",
                    config.advice[2],
                    0,
                    || prev_b.0.value().cloned() + prev_c.0.value(),
                ).map(ACell)?;

                Ok(c_cell)
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
        advice: (Column<Advice>, Column<Advice>, Column<Advice>),
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        let selector = meta.selector();
        let (a_col, b_col, c_col) = advice;

        meta.enable_equality(a_col);
        meta.enable_equality(b_col);
        meta.enable_equality(c_col);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let a = meta.query_advice(a_col, Rotation::cur());
            let b = meta.query_advice(b_col, Rotation::cur());
            let c = meta.query_advice(c_col, Rotation::cur());
            let s = meta.query_selector(selector);

            vec![s * (a + b - c)]
        });

        FiboConfig {
            advice: [a_col, b_col, c_col],
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
        let advice = (meta.advice_column(), meta.advice_column(), meta.advice_column());

        let instance = meta.instance_column();

        FiboChip::configure(meta, advice, instance)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = FiboChip::construct(config);

        let (mut b_cell, mut c_cell) = chip.assign_first_row(layouter.namespace(|| "first row"), self.first, self.second)?;

        for _ in 3..10 {
            let c_cell_new = chip.assign_next_row(
                layouter.namespace(|| "next row"),
                &b_cell, &c_cell,
            )?;

            b_cell = c_cell;
            c_cell = c_cell_new;
        }

        chip.expose_public(layouter.namespace(|| ""), &c_cell)
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