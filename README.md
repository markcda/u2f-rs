# Rust FIDO U2F Library

## u2f-rs

Rust [FIDO U2F](https://fidoalliance.org/specifications/download/) library is a simple server side implementation to register and check signatures provided by U2F clients/devices. See [U2F Technical Overview](https://developers.yubico.com/U2F/Protocol_details/Overview.html)

## Usage

> [!IMPORTANT]
> DO NOT USE THIS LIBRARY IN PRODUCTION WITHOUT PROPER SECURITY MEASURES IN PLACE.

Add this to your Cargo.toml

```toml
[dependencies]
u2f = "0.2"
```

Make sure that you have read [Using a U2F library](https://developers.yubico.com/U2F/Libraries/Using_a_library.html) before continuing.

See provided [example](https://github.com/wisespace-io/u2f-rs/tree/master/example)
