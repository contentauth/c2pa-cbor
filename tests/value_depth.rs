// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

use std::collections::BTreeMap;

use c2pa_cbor::{
    DEFAULT_MAX_DEPTH, Error, Value, from_value, from_value_with_max_depth, to_value,
    to_value_with_max_depth,
};
use serde::{
    Serialize, Serializer,
    ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
};

#[derive(Clone, Copy, Debug)]
enum Shape {
    Array,
    Tuple,
    TupleStruct,
    MapValue,
    MapKey,
    Struct,
    Some,
    Newtype,
    NewtypeVariant,
    TupleVariant,
    StructVariant,
}

struct Nested {
    levels: usize,
    shape: Shape,
}

impl Serialize for Nested {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.levels == 0 {
            return serializer.serialize_bool(true);
        }
        let next = Nested {
            levels: self.levels - 1,
            shape: self.shape,
        };
        match self.shape {
            Shape::Array => {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(&next)?;
                seq.end()
            }
            Shape::Tuple => {
                let mut seq = serializer.serialize_tuple(1)?;
                seq.serialize_element(&next)?;
                seq.end()
            }
            Shape::TupleStruct => {
                let mut seq = serializer.serialize_tuple_struct("Nested", 1)?;
                seq.serialize_field(&next)?;
                seq.end()
            }
            Shape::MapValue | Shape::MapKey => {
                let mut map = serializer.serialize_map(Some(1))?;
                if matches!(self.shape, Shape::MapKey) {
                    map.serialize_entry(&next, &true)?;
                } else {
                    map.serialize_entry("next", &next)?;
                }
                map.end()
            }
            Shape::Struct => {
                let mut map = serializer.serialize_struct("Nested", 1)?;
                map.serialize_field("next", &next)?;
                map.end()
            }
            Shape::Some => serializer.serialize_some(&next),
            Shape::Newtype => serializer.serialize_newtype_struct("Nested", &next),
            Shape::NewtypeVariant => {
                serializer.serialize_newtype_variant("Nested", 0, "Next", &next)
            }
            Shape::TupleVariant => {
                let mut seq = serializer.serialize_tuple_variant("Nested", 0, "Next", 1)?;
                seq.serialize_field(&next)?;
                seq.end()
            }
            Shape::StructVariant => {
                let mut map = serializer.serialize_struct_variant("Nested", 0, "Next", 1)?;
                map.serialize_field("next", &next)?;
                map.end()
            }
        }
    }
}

fn assert_depth_error<T>(result: c2pa_cbor::Result<T>) {
    assert!(matches!(result, Err(Error::Encoding(message)) if message.contains("maximum depth")));
}

#[test]
fn serialization_boundaries_include_wrappers_and_enum_payloads() {
    for shape in [
        Shape::Array,
        Shape::Tuple,
        Shape::TupleStruct,
        Shape::MapValue,
        Shape::MapKey,
        Shape::Struct,
        Shape::Some,
        Shape::Newtype,
        Shape::NewtypeVariant,
        Shape::TupleVariant,
        Shape::StructVariant,
    ] {
        let levels = if matches!(shape, Shape::TupleVariant | Shape::StructVariant) {
            DEFAULT_MAX_DEPTH / 2
        } else {
            DEFAULT_MAX_DEPTH
        };
        for nesting in [levels - 1, levels] {
            assert!(
                to_value(Nested {
                    levels: nesting,
                    shape
                })
                .is_ok(),
                "{shape:?}: {nesting}"
            );
        }
        assert_depth_error(to_value(Nested {
            levels: levels + 1,
            shape,
        }));
        assert_depth_error(to_value_with_max_depth(Nested { levels: 10, shape }, 3));
    }
}

fn tree(levels: usize, shape: Shape) -> Value {
    let mut value = Value::Bool(true);
    for _ in 0..levels {
        value = match shape {
            Shape::Array => Value::Array(vec![value]),
            Shape::MapKey => Value::Map(BTreeMap::from([(value, Value::Null)])),
            Shape::MapValue => Value::Map(BTreeMap::from([(Value::Text("next".into()), value)])),
            _ => Value::Tag(42, Box::new(value)),
        };
    }
    value
}

#[test]
fn owned_conversion_checks_keys_values_and_tags_at_exact_limit() {
    for shape in [Shape::Array, Shape::MapKey, Shape::MapValue, Shape::Newtype] {
        for levels in [DEFAULT_MAX_DEPTH - 1, DEFAULT_MAX_DEPTH] {
            let input = tree(levels, shape);
            assert!(to_value(&input).is_ok());
            assert!(from_value::<Value>(input).is_ok());
        }
        assert_depth_error(from_value::<Value>(tree(DEFAULT_MAX_DEPTH + 1, shape)));
        assert_depth_error(to_value(tree(DEFAULT_MAX_DEPTH + 1, shape)));
        assert!(from_value_with_max_depth::<Value>(tree(4, shape), 4).is_ok());
        assert_depth_error(from_value_with_max_depth::<Value>(tree(5, shape), 4));
        assert!(to_value_with_max_depth(tree(4, shape), 4).is_ok());
        assert_depth_error(to_value_with_max_depth(tree(5, shape), 4));
    }
}

#[test]
fn zero_budget_allows_leaves_but_not_empty_containers_or_wrappers() {
    for value in [
        Value::Null,
        Value::Bool(true),
        Value::Integer(3),
        Value::Float(1.5),
        Value::Text("text".into()),
        Value::Bytes(vec![1, 2]),
    ] {
        assert_eq!(to_value_with_max_depth(&value, 0).unwrap(), value);
        assert_eq!(
            from_value_with_max_depth::<Value>(value.clone(), 0).unwrap(),
            value
        );
    }
    for value in [
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
        Value::Tag(42, Box::new(Value::Null)),
    ] {
        assert_depth_error(to_value_with_max_depth(&value, 0));
        assert_depth_error(from_value_with_max_depth::<Value>(value, 0));
    }
    assert_depth_error(to_value_with_max_depth(Some(true), 0));
    assert!(to_value_with_max_depth(None::<bool>, 0).is_ok());
}

#[test]
fn siblings_do_not_exhaust_the_budget_and_output_is_unchanged() {
    let value = Value::Array(vec![Value::Array(vec![Value::Integer(42)]); 1000]);
    assert_eq!(to_value_with_max_depth(&value, 2).unwrap(), value);
    assert_eq!(
        from_value_with_max_depth::<Value>(value.clone(), 2).unwrap(),
        value
    );
    assert_eq!(
        c2pa_cbor::to_vec(&to_value(&value).unwrap()).unwrap(),
        c2pa_cbor::to_vec(&value).unwrap()
    );
}

#[test]
fn excessively_deep_owned_trees_are_rejected_and_disposed_of_iteratively() {
    for shape in [Shape::Array, Shape::MapKey, Shape::MapValue, Shape::Newtype] {
        let input = tree(20_000, shape);
        assert_depth_error(to_value(&input));
        input.drop_iterative();
        assert_depth_error(from_value::<Value>(tree(20_000, shape)));
    }
}

#[test]
fn raised_limits_apply_to_both_conversion_and_decoder() {
    let limit = DEFAULT_MAX_DEPTH + 1;
    let value = tree(limit, Shape::Array);
    assert!(to_value_with_max_depth(&value, limit).is_ok());
    assert!(from_value_with_max_depth::<Value>(value, limit).is_ok());
}

#[test]
fn tag_state_is_restored_after_depth_errors() {
    assert_depth_error(to_value_with_max_depth(
        Value::Tag(42, Box::new(Value::Null)),
        0,
    ));
    assert_eq!(to_value(true).unwrap(), Value::Bool(true));
    let tagged = Value::Tag(7, Box::new(Value::Bool(true)));
    assert_eq!(to_value(&tagged).unwrap(), tagged);
}

#[test]
fn serialization_and_deserialization_errors_are_not_hidden() {
    struct Fail;
    impl Serialize for Fail {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("expected failure"))
        }
    }
    assert!(matches!(
        to_value(vec![Fail]),
        Err(Error::Serde(message)) if message == "expected failure"
    ));
    assert!(from_value::<u64>(Value::Text("not an integer".into())).is_err());
}

#[test]
fn partially_built_containers_are_cleaned_up_after_errors() {
    let value = Value::Array(vec![
        tree(DEFAULT_MAX_DEPTH - 1, Shape::Array),
        tree(DEFAULT_MAX_DEPTH, Shape::Array),
    ]);
    assert_depth_error(to_value(&value));
    value.drop_iterative();
    assert_eq!(to_value(42).unwrap(), Value::Integer(42));
}
