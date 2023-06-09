#[macro_export]
macro_rules! impl_from_variant_wrap {
    ($(<$($generic: ident$(: $trait: ident$(+ $traits: ident)*)*,)+>)*, $from_type: ty, $to_type: ty, $variant: path) => {
        impl$(<$($generic $(: $trait $(+ $traits)*)*,)+>)* From<$from_type> for $to_type {
            fn from(t: $from_type) -> Self {
                $variant(t)
            }
        }
    };
}
