use dioxus::{logger::tracing::trace, prelude::*};
use std::{fmt::Debug, hash::Hash};

pub fn store<K, V>(key: K, value: V)
where
    K: Hash + Debug,
    V: Sized + Debug,
{
    trace!("Storing with key: {:?}, value: {:?}", key, value)
}

pub fn get<K, V>(key: K) -> Option<V>
where
    K: Hash + Debug,
    V: Sized,
{
    trace!("Getting with key: {:?}", key);
    None
}
