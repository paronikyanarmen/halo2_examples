use std::marker::PhantomData;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector};
use halo2_proofs::poly::Rotation;

trait NumericInstructions<F: Field>: Chip<F> {
    type Num;

    fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;

    fn load_constant(&self, layouter: impl Layouter<F>, a: F) -> Result<Self::Num, Error>;

    fn mul(&self, layouter: impl Layouter<F>, a: Self::Num, b: Self::Num) -> Result<Self::Num, Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
struct FieldConfig {
    advice: [Column<Advice>; 2],

    instance: Column<Instance>,

    s_mul: Selector,
}

struct FieldChip<F: Field> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for FieldChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> FieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_constant(constant);
        meta.enable_equality(instance);
        for column in advice {
            meta.enable_equality(column);
        }
        let s_mul = meta.selector();

        meta.create_gate("mul", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);


            vec![s_mul * (lhs * rhs - out)]
        });

        FieldConfig {
            advice,
            instance,
            s_mul,
        }
    }
}

#[derive(Clone)]
struct Number<F: Field>(AssignedCell<F, F>);

impl<F: Field> NumericInstructions<F> for FieldChip<F> {
    type Num = Number<F>;

    fn load_private(&self, mut layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || a)
                    .map(Number)
            },
        )
    }

    fn load_constant(&self, mut layouter: impl Layouter<F>, a: F) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                region
                    .assign_advice_from_constant(|| "constant value", config.advice[0], 0, a)
                    .map(Number)
            },
        )
    }

    fn mul(&self, mut layouter: impl Layouter<F>, a: Self::Num, b: Self::Num) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mut",
            |mut region| {
                config.s_mul.enable(&mut region, 0)?;

                a.0.copy_advice(|| "lhs", &mut region, self.config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, self.config.advice[1], 0)?;

                let value = a.0.value().copied() * b.0.value();

                region
                    .assign_advice(|| "lhs * rhs", self.config.advice[0], 1, || value)
                    .map(Number)
            }
        )
    }

    fn expose_public(&self, mut layouter: impl Layouter<F>, num: Self::Num, row: usize) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

#[derive(Default)]
struct MyCircuit<F: Field> {
    a: Value<F>,
    b: Value<F>,
    constant: F
}

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];

        let instance = meta.instance_column();

        let constant = meta.fixed_column();

        FieldChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = FieldChip::construct(config);

        let a = chip.load_private(layouter.namespace(|| "a"), self.a)?;
        let b = chip.load_private(layouter.namespace(|| "b"), self.b)?;

        let constant = chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

        let ab = chip.mul(layouter.namespace(|| "a * b"), a, b)?;
        let abab = chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab)?;

        chip.expose_public(layouter.namespace(|| "expose absq"), abab, 0)
    }
}

fn main() {
    let k = 4;

    let a = Fp::from(2);
    let b = Fp::from(3);

    let c = a.square() * b.square();

    let circuit = MyCircuit {
        constant: Fp::from(7),
        a: Value::known(a),
        b: Value::known(b),
    };

    let mut public_inputs = vec![c];

    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    prover.assert_satisfied();

    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    prover.assert_satisfied();

}
