# jargon

A modern Argon2 password hashing library for Erlang.

## Argon2

Argon2 is a password hashing function that was designed to be fast, memory-hard, and resistant to side-channel attacks.

Read more about Argon2 on [the official Argon2 website](https://github.com/P-H-C/phc-winner-argon2).

## Usage

### Hashing

```erlang
{ok, RawHash, EncodedHash} = jargon:hash(<<"password">>, <<"saltsalt">>, argon2d, 32, 12, 1, 32).
```

### Verifying

```erlang
{ok, true} = jargon:verify(EncodedHash, <<"password">>).
```

## Building

```bash
git submodule update --init --recursive
make compile
```

## Contributing

Contributions are welcome!
