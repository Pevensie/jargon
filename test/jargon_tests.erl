-module(jargon_tests).

-include_lib("eunit/include/eunit.hrl").

argon2d_hash_verify_test() ->
  Password = gen_random_valid_password(),
  Salt = gen_random_valid_salt(),
  {ok, RawHash, EncodedHash} = jargon:hash(Password, Salt, argon2d, 32, 12, 1, 32),
  ?assertEqual(32, byte_size(RawHash)),
  ?assertEqual({ok, true}, jargon:verify(EncodedHash, Password)).

argon2i_hash_verify_test() ->
  Password = gen_random_valid_password(),
  Salt = gen_random_valid_salt(),
  {ok, RawHash, EncodedHash} = jargon:hash(Password, Salt, argon2i, 32, 12, 1, 32),
  ?assertEqual(32, byte_size(RawHash)),
  ?assertEqual({ok, true}, jargon:verify(EncodedHash, Password)).

argon2id_hash_verify_test() ->
  Password = gen_random_valid_password(),
  Salt = gen_random_valid_salt(),
  {ok, RawHash, EncodedHash} = jargon:hash(Password, Salt, argon2id, 32, 12, 1, 32),
  ?assertEqual(32, byte_size(RawHash)),
  ?assertEqual({ok, true}, jargon:verify(EncodedHash, Password)).

invalid_algorithm_test() ->
  {error, invalid_algorithm} =
    jargon:hash(<<"password">>, <<"salt">>, argon2, 32, 12, 1, 32).

salt_too_short_test() ->
  {error, salt_too_short} = jargon:hash(<<"password">>, <<"salt">>, argon2d, 32, 12, 1, gen_random_valid_hashlen()).

verify_invalid_algorithm_test() ->
  {error, invalid_algorithm} = jargon:verify(<<"$argon2$">>, <<"password">>).

%% Generation functions

gen_random_int(Min, Max) ->
  crypto:strong_rand_bytes(4),
  <<Int:32/unsigned-integer>> = crypto:strong_rand_bytes(4),
  Int rem (Max - Min) + Min.

gen_random_valid_password() ->
  Bytes = gen_random_int(8, 64),
  base64:encode(
    crypto:strong_rand_bytes(Bytes)).

gen_random_valid_salt() ->
  Bytes = gen_random_int(32, 1024),
  base64:encode(
    crypto:strong_rand_bytes(Bytes)).

gen_random_valid_hashlen() ->
  gen_random_int(32, 1024).
