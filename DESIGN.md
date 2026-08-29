## Crates
I expect adding GPG pinentry to this will add another crate.

### `pam-sys`
This crate provides raw bindings to relevant libpam APIs,
generated using `bindgen`.

NOTE this includes _both_ `extern` declarations for functions provided by libpam,
and `extern` declarations for functions that must (or may) be provided by pam modules,
such as `pamusb-pam-module`.
The latter kind should not be used,
but are still useful to have as a reference for what the correct Rust function signature should be.

### `pamusb-lib`
This crate is a library containing pamusb logic which is not specific to
`pamusb-check`, `pamusb-cli`, or `pamusb-pam-module`

### `pamusb-check`
This is to `pamusb-pam-module` as `unix_chkpwd` is to `pam_unix.so`.

This is a binary with capabilities (TBD) to perform various actions that may require elevated privileges,
such as mounting the USB drive, interacting with udev, and reading the system keys.

NOTE: I think it would be hard to reliably stop this binary from being used other than through `pamusb-cli` and `pamusb-pam-module`,
therefore the interface exposed must not trust the calling code.
The nice side effect of this is that `pamusb-cli` doesn't need to be written as carefully as `pamusb-check` and `pamusb-pam-module`.

### `pamusb-cli`
A cli interface to `pamusb-check`.
I'm hoping this can be the only cli needed.

### `pamusb-pam-module`
The actual pam module

### `run-pamusb-check`
It would be nice if this could be part of `pamusb-check` or `pamusb-lib`,
but unfortunately it has to be a separate crate to avoid future circular dependencies.

To prevent tampering, I'm considering making `pamusb-pam-module`
(and other users of `pamusb-check`, but they're obviously less critical)
check the hash of the `pamusb-check` binary against a hash computed at compile time.

The most robust way to make this work is to make `pamusb-check` a Cargo build-dependency of it's consumers and compute the hash of the binary in a build script.
Obviously making `pamusb-check` or `pamusb-lib` (which `pamusb-check` depends on) require `pamusb-check` as a build dependency would be a circular dependency.
I had hoped I'd be able to get round this with Cargo features: making the build-dependency on `pamusb-check` optional,
but Cargo's circular dependency checking wasn't ok with that,
even if it might work in theory.
