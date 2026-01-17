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

## Using in Docker

If you want to deploy an application using Jargon in a Docker container, you'll
need to make sure your image includes a C compiler to build the Jargon NIF.

### Alpine

```dockerfile
RUN apk add --no-cache build-base
```

### Debian

```dockerfile
RUN apt-get update && apt-get install -y build-essential
```

## Using on Windows

Jargon is not currently set up to compile on Windows, and I don't currently have
a Windows machine available on which to test this. PRs resolving adding support
are more than welcome!

## Contributing

Contributions are welcome!
