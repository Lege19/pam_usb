pub use bitflags;

/// Generates type safe bitflags types using the bitflags crate from C-style constants.
///
/// Example usage:
/// ```
/// decl_bitflags! {
///     repr = c_int;
///
///     FlagsA {
///         PAM_FLAG_1,
///         PAM_FLAG_2,
///     }
///
///     FlagsB {
///         PAM_FLAG_2,
///         PAM_FLAG_3,
///     }
/// }
/// ```
#[macro_export]
macro_rules! decl_bitflags {
    {
        repr = $repr:ty;

        $(
            $typename:ident {
                $($flagname:ident),*$(,)?
            }
        )*
    } => {
        $crate::bitflags::bitflags! {
            $(
                pub struct $typename: $repr {
                    $(
                        const $flagname = $flagname;
                    )*
                }
            )*
        }
    }
}

/// Generates type safe enums from C-style constants.
/// Expected to be used for errors
///
/// ```
/// decl_enums! {
///     // This must be a type that is allowed to be in `#[repr(...)]` on a Rust enum
///     repr = i32;
///
///     EnumA {
///         PAM_ERRNO_1,
///         PAM_ERRNO_2,
///     }
///
///     EnumB {
///         PAM_ERRNO_2,
///         PAM_ERRNO_3,
///     }
/// }
/// ```
///
/// This will generate a `From` impl to convert back to the underlying integer type,
/// and a `TryFrom` impl to convert from the underlying integer type
#[macro_export]
macro_rules! decl_enums {
    {
        repr = $repr:ty;

        $(
            $typename:ident {
                $($flagname:ident),*$(,)?
            }
        )*
    } => {
        $(
            #[allow(non_camel_case_types)]
            #[repr($repr)]
            pub enum $typename {
                $(
                    $flagname = $flagname,
                )*
            }
            impl ::std::convert::TryFrom<$repr> for $typename {
                type Error = ();
                fn try_from(value: $repr) -> ::std::result::Result<Self, Self::Error> {
                    match value {
                        $(
                            $flagname => Ok(Self::$flagname),
                        )*
                        _ => Err(()),
                    }
                }
            }
            impl ::std::convert::From<$typename> for $repr {
                fn from(value: $typename) -> $repr {
                    value as $repr
                }
            }
        )*
    }
}
