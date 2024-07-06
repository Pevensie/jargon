#include "erl_nif.h"

#include "argon2.h"
#include <stdlib.h>

#define ARGON2_VERSION 13
#define JARGON_IS_VALID_TYPE(v) (v <= Argon2_id)

static ERL_NIF_TERM argon2_hash_nif(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[]) {
  if (argc != 7) {
    return enif_make_badarg(env);
  }

  uint32_t t_cost, m_cost, parallelism, hash_len, algorithm;
  ErlNifBinary password, salt;
  char *raw_hash = NULL;
  char *encoded_hash = NULL;
  size_t encoded_hash_len = 0;

  if (!enif_get_uint(env, argv[0], &t_cost) ||
      !enif_get_uint(env, argv[1], &m_cost) ||
      !enif_get_uint(env, argv[2], &parallelism) ||
      !enif_inspect_binary(env, argv[3], &password) ||
      !enif_inspect_binary(env, argv[4], &salt) ||
      !enif_get_uint(env, argv[5], &hash_len) ||
      !enif_get_uint(env, argv[6], &algorithm) ||
      !JARGON_IS_VALID_TYPE(algorithm)) {
    return enif_make_badarg(env);
  }

  raw_hash = malloc(hash_len);
  if (raw_hash == NULL) {
    // TODO: return better error
    return enif_make_badarg(env);
  }

  encoded_hash_len =
      argon2_encodedlen(t_cost, m_cost, parallelism, (uint32_t)salt.size,
                        hash_len, (argon2_type)algorithm);
  encoded_hash_len++;
  encoded_hash = malloc(encoded_hash_len);
  if (encoded_hash == NULL) {
    // TODO: return better error
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result_nif;

  uint32_t result;

  result = argon2_hash((uint32_t)t_cost, m_cost, parallelism, password.data,
                       password.size, salt.data, salt.size, raw_hash,
                       (size_t)hash_len, encoded_hash, encoded_hash_len,
                       (argon2_type)algorithm, ARGON2_VERSION);

  if (result != ARGON2_OK) {
    // TODO: return better error
    return enif_make_badarg(env);
  }

  result_nif =
      enif_make_tuple3(env, enif_make_atom(env, "ok"),
                       enif_make_string(env, raw_hash, ERL_NIF_LATIN1),
                       enif_make_string(env, encoded_hash, ERL_NIF_LATIN1));

  if (raw_hash) {
    clear_internal_memory(raw_hash, hash_len);
    free(raw_hash);
  }
  if (encoded_hash) {
    clear_internal_memory(encoded_hash, encoded_hash_len);
    free(encoded_hash);
  }

  return result_nif;
}

static ErlNifFunc nif_funcs[] = {{"hash", 7, argon2_hash_nif}};

ERL_NIF_INIT(argon2, nif_funcs, NULL, NULL, NULL, NULL)
