use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Chip, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug)]
pub struct IsZeroConfig<F: Field> {
    value_inv: Column<Advice>,
    is_zero_expression: Expression<F>,
}

impl<F: Field> IsZeroConfig<F> {
    pub fn expr(&self) -> Expression<F> {
        self.is_zero_expression.clone()
    }
}

pub trait Instructions<F: Field> {
    fn assign(&self, region: &mut Region<'_, F>, value: Value<F>, offset: usize) -> Result<(), Error>;
}

pub struct IsZeroChip<F: Field> {
    config: IsZeroConfig<F>,
}

impl<F: Field> Chip<F> for IsZeroChip<F> {
    type Config = IsZeroConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> IsZeroChip<F> {
    pub fn construct(config: IsZeroConfig<F>) -> Self {
        IsZeroChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value_inv: Column<Advice>,
    ) -> IsZeroConfig<F> {
        let mut is_zero_expression = Expression::Constant(F::ZERO);

        meta.create_gate(
            "is zero",
            |meta| {
                let q_enable = q_enable(meta);
                let value = value(meta);

                let value_inv = meta.query_advice(value_inv, Rotation::cur());

                is_zero_expression = Expression::Constant(F::ONE) - value.clone() * value_inv;

                vec![q_enable * value * is_zero_expression.clone()]
            },
        );

        IsZeroConfig {
            value_inv,
            is_zero_expression,
        }
    }
}

impl<F: Field> Instructions<F> for IsZeroChip<F> {
     fn assign(&self, region: &mut Region<'_, F>, value: Value<F>, offset: usize) -> Result<(), Error> {
        let config = self.config();

        let value_inv = value.and_then(|value| Value::known(value.invert().unwrap_or_else(|| F::ZERO)));

        region.assign_advice(
            || "value inv",
            config.value_inv,
            offset,
            || value_inv,
        )?;

        Ok(())
    }
}
