use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

use halo2_examples::gadgets::is_zero::{Instructions, IsZeroChip, IsZeroConfig};

#[derive(Clone, Debug)]
struct FnConfig<F: Field> {
    advice: (Column<Advice>, Column<Advice>, Column<Advice>),
    output: Column<Advice>,
    selector: Selector,
    a_equals_b: IsZeroConfig<F>,
}

struct FnChip<F: Field> {
    config: FnConfig<F>,
}

impl<F: Field> Chip<F> for FnChip<F> {
    type Config = FnConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> FnChip<F> {
    fn construct(config: FnConfig<F>) -> Self {
        Self {
            config,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: (Column<Advice>, Column<Advice>, Column<Advice>),
        output: Column<Advice>,
    ) -> <Self as Chip<F>>::Config
    {
        let (a_col, b_col, c_col) = advice;

        meta.enable_equality(a_col);
        meta.enable_equality(b_col);
        meta.enable_equality(c_col);
        let selector = meta.selector();

        let is_zero_advice_column = meta.advice_column();

        let a_equals_b = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(selector),
            |meta| meta.query_advice(a_col, Rotation::cur()) - meta.query_advice(b_col, Rotation::cur()),
            is_zero_advice_column,
        );

        meta.create_gate("if a == b {c} else {a - b}", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(a_col, Rotation::cur());
            let b = meta.query_advice(b_col, Rotation::cur());
            let c = meta.query_advice(c_col, Rotation::cur());
            let output = meta.query_advice(output, Rotation::cur());

            vec![
                s.clone() * a_equals_b.expr() * (output.clone() - c),
                s * ((Expression::Constant(F::ONE) - a_equals_b.expr()) * (output - (a - b))),
            ]
        });

        FnConfig {
            advice,
            selector,
            a_equals_b,
            output,
        }
    }

    fn assign(&self, mut layouter: impl Layouter<F>, a: Value<F>, b: Value<F>, c: Value<F>)
              -> Result<AssignedCell<F, F>, Error>
    {
        let config = self.config();
        let is_zero_chip = IsZeroChip::construct(config.a_equals_b.clone());

        layouter.assign_region(
            || "function region",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.advice.0, 0, || a)?;
                region.assign_advice(|| "b", config.advice.1, 0, || b)?;
                region.assign_advice(|| "c", config.advice.2, 0, || c)?;

                is_zero_chip.assign(&mut region, a - b, 0)?;

                let output = a.and_then(|a| b.and_then(|b| if a == b { c } else { Value::known(a - b) }));

                region.assign_advice(|| "output", config.output, 0, || output)
            },
        )
    }
}

#[derive(Default)]
struct FnCircuit<F: Field> {
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
}

impl<F: Field> Circuit<F> for FnCircuit<F> {
    type Config = FnConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = (meta.advice_column(), meta.advice_column(), meta.advice_column());

        let output = meta.advice_column();

        FnChip::configure(meta, advice, output)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = FnChip::construct(config);

        chip.assign(layouter.namespace(|| "first row"), self.a, self.b, self.c)?;

        Ok(())
    }
}

fn main() {
    let circuit = FnCircuit {
        a: Value::known(Fp::from(15)),
        b: Value::known(Fp::from(12)),
        c: Value::known(Fp::from(15)),
    };

    let prover = MockProver::run(4, &circuit, vec![]).unwrap();

    prover.assert_satisfied();
}