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

Jargon currently needs to compile on MSYS2. It has been tested on the MINGW64 environment and, as such, this guide is written for it.

First, install dependencies with `pacman`
```bash
pacman -S git make mingw-w64-x86_64-gcc
```

Then, you must put `erl` and `rebar3` in your path. As an example, if their paths in Windows are, respectively, `C:\path\to\erlang\here\erl` and `C:\path\to\rebar\here\rebar3`, you would run
```bash
PATH = /c/path/to/erlang/here:/c/path/to/rebar/here:$PATH
```

Finally, you can compile the package with `make`. After compiling, you can use it through Windows as normal.

## Contributing

Contributions are welcome!
