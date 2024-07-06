-module(jargon).
-author("Isaac Harris-Holt").

-export([]).

-on_load(init/0).

init() ->
    ok = erlang:load_nif("./priv/jargon", 0).

hash(TimeCost, MemoryCost, Parallelism, Password, Salt, HashLen, Algorithm) ->
    erlang:nif_error(nif_library_not_loaded).
