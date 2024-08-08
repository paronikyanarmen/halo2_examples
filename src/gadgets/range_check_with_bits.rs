use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{ConstraintSystem, Expression, VirtualCells};

use crate::range_check::lookup_with_bits::RangeCheckTable;

#[derive(Clone, Debug)]
pub struct RangeCheckConfig<F: PrimeField> {
    pub lookup_table: RangeCheckTable<F>,
}

impl<F: PrimeField> RangeCheckConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        value: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        bits: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        lookup_selector: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        lookup_range: usize,
    ) -> Self {
        let lookup_table = RangeCheckTable::configure(meta, lookup_range);

        meta.lookup(|meta| {
            let value = value(meta);
            let bits = bits(meta);
            let lookup_selector = lookup_selector(meta);

            let not_selector = Expression::Constant(F::ONE) - lookup_selector.clone();

            let bits_default = Expression::Constant(F::ONE);

            let bits = not_selector.clone() * bits_default + lookup_selector.clone() * bits;

            vec![
                (lookup_selector * value, lookup_table.value),
                (bits, lookup_table.bits),
            ]
        });

        Self {
            lookup_table,
        }
    }
}