//! Deserializers that reject collections, byte strings, and strings over a fixed limit.

use serde::{Deserialize, Deserializer, de};
use std::marker::PhantomData;

pub(crate) fn vec<'de, D: Deserializer<'de>, T: Deserialize<'de>, const MAX: usize>(
    decoder: D,
) -> Result<Vec<T>, D::Error> {
    struct Bounded<T, const MAX: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> de::Visitor<'de> for Bounded<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX} elements")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > MAX) {
                return Err(de::Error::custom(format!("exceeds {MAX}-element limit")));
            }
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(de::Error::custom(format!("exceeds {MAX}-element limit")));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    decoder.deserialize_seq(Bounded::<T, MAX>(PhantomData))
}

pub(crate) fn bytes<'de, D: Deserializer<'de>, const MAX: usize>(
    decoder: D,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytes<const MAX: usize>;
    impl<'de, const MAX: usize> de::Visitor<'de> for BoundedBytes<MAX> {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX} bytes")
        }
        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
            if bytes.len() > MAX {
                return Err(E::custom(format!("exceeds {MAX}-byte limit")));
            }
            Ok(bytes.to_vec())
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, sequence: A) -> Result<Vec<u8>, A::Error> {
            vec::<_, u8, MAX>(de::value::SeqAccessDeserializer::new(sequence))
        }
    }
    decoder.deserialize_bytes(BoundedBytes::<MAX>)
}

pub(crate) fn string<'de, D: Deserializer<'de>, const MAX: usize>(
    decoder: D,
) -> Result<String, D::Error> {
    struct BoundedString<const MAX: usize>;
    impl<const MAX: usize> de::Visitor<'_> for BoundedString<MAX> {
        type Value = String;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string of at most {MAX} bytes")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > MAX {
                return Err(E::custom(format!("exceeds {MAX}-byte limit")));
            }
            Ok(value.into())
        }
    }
    decoder.deserialize_str(BoundedString::<MAX>)
}
