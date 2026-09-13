#![allow(clippy::expect_used)]

use wasmtime::component::{Component, Linker, Resource, ResourceTable, ResourceType};
use wasmtime::{Engine, Store};

const FORGE: &str = r#"(component
    (import "test:grant/token@0.1.0" (instance $api
        (export "token" (type $token (sub resource)))
        (export "get" (func $get (result (own $token))))
        (export "[method]token.value" (func $value (param "self" (borrow $token)) (result u32)))))
    (alias export $api "token" (type $token))
    (alias export $api "get" (func $get))
    (alias export $api "[method]token.value" (func $value))
    (core func $get-lowered (canon lower (func $get)))
    (core func $value-lowered (canon lower (func $value)))
    (core module $module
        (import "api" "get" (func $get (result i32)))
        (import "api" "value" (func $value (param i32) (result i32)))
        (func (export "token") (result i32) call $get)
        (func (export "probe") (param i32) (result i32) local.get 0 call $value))
    (core instance $instance (instantiate $module
        (with "api" (instance
            (export "get" (func $get-lowered))
            (export "value" (func $value-lowered))))))
    (alias core export $instance "token" (core func $token))
    (alias core export $instance "probe" (core func $probe))
    (func (export "token") (result u32) (canon lift (core func $token)))
    (func (export "probe") (param "raw" u32) (result u32)
        (canon lift (core func $probe))))"#;

struct Token(u32);

struct State {
    table: ResourceTable,
    native_handles: Vec<u32>,
}

fn linker(engine: &Engine, grant: u32) -> Linker<State> {
    let mut linker = Linker::<State>::new(engine);
    let mut api = linker
        .instance("test:grant/token@0.1.0")
        .expect("grant instance");
    api.resource("token", ResourceType::host::<Token>(), |mut store, raw| {
        store
            .data_mut()
            .table
            .delete(Resource::<Token>::new_own(raw))?;
        Ok(())
    })
    .expect("token resource");
    api.func_wrap("get", move |mut store, (): ()| {
        let token = store.data_mut().table.push(Token(grant))?;
        store.data_mut().native_handles.push(token.rep());
        Ok((token,))
    })
    .expect("get grant");
    api.func_wrap(
        "[method]token.value",
        |store, (token,): (Resource<Token>,)| Ok((store.data().table.get(&token)?.0,)),
    )
    .expect("read grant");
    linker
}

#[test]
fn imported_host_resources_stay_component_local_in_a_shared_resource_table() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let component = Component::new(&engine, FORGE).expect("forging component");
    let mut store = Store::new(
        &engine,
        State {
            table: ResourceTable::new(),
            native_handles: Vec::new(),
        },
    );
    store.set_epoch_deadline(100);
    let first = linker(&engine, 10)
        .instantiate(&mut store, &component)
        .expect("first instance");
    let second = linker(&engine, 20)
        .instantiate(&mut store, &component)
        .expect("second instance");
    let first_token = first
        .get_typed_func::<(), (u32,)>(&mut store, "token")
        .expect("first token")
        .call(&mut store, ())
        .expect("first grant")
        .0;
    let second_token = second
        .get_typed_func::<(), (u32,)>(&mut store, "token")
        .expect("second token")
        .call(&mut store, ())
        .expect("second grant")
        .0;
    let probe = first
        .get_typed_func::<(u32,), (u32,)>(&mut store, "probe")
        .expect("first probe");
    assert_eq!(first_token, second_token, "canonical indices can collide");
    assert_eq!(
        probe.call(&mut store, (second_token,)).expect("own grant"),
        (10,)
    );
    let second_probe = second
        .get_typed_func::<(u32,), (u32,)>(&mut store, "probe")
        .expect("second probe");
    assert_eq!(
        second_probe
            .call(&mut store, (first_token,))
            .expect("second grant"),
        (20,)
    );
    let foreign_native_handle = store.data().native_handles[1];
    match probe.call(&mut store, (foreign_native_handle,)) {
        Ok(value) => assert_eq!(
            value,
            (10,),
            "a colliding handle resolves only the caller's grant"
        ),
        Err(error) => assert!(
            format!("{error:#}").contains("unknown handle index"),
            "{error:#}"
        ),
    }
    let error = probe
        .call(&mut store, (u32::MAX,))
        .expect_err("ungranted handle");
    assert!(
        format!("{error:#}").contains("unknown handle index"),
        "{error:#}"
    );
}
