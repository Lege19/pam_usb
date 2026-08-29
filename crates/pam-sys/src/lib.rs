#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// This is the way to represent opaque C types recommended by the Rustonomicon
/// I couldn't get bindgen to generate anything like this for some reason,
/// so I'm doing it myself
#[repr(C)]
pub struct pam_handle_t {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}
