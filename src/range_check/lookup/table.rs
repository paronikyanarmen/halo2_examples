use std::marker::PhantomData;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{ConstraintSystem, Error, TableColumn};

#[derive(Clone, Debug)]
pub struct RangeCheckTable<F: PrimeField> {
    pub value: TableColumn,
    lookup_range: usize,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RangeCheckTable<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, lookup_range: usize) -> Self {
        let value = meta.lookup_table_column();

        Self {
            value,
            lookup_range,
            _marker: PhantomData
        }
    }

    pub fn load(&self, mut layouter: impl Layouter<F>)-> Result<(), Error> {
        layouter.assign_table(|| "Assign lookup table", |mut table| {
            for i in 0..self.lookup_range {
                table.assign_cell(|| "Assign lookup cell", self.value, i, || Value::known(F::from(i as u64)))?;
            }

            Ok(())
        })
    }
}