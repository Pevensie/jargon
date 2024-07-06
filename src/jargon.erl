-module(jargon).

-author("Isaac Harris-Holt").

-export([hash/7]).

-on_load init/0.

-define(APPNAME, jargon).
-define(LIBNAME, jargon).

init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
            {error, bad_name} ->
                case filelib:is_dir(
                         filename:join(["..", priv]))
                of
                    true ->
                        filename:join(["..", priv, ?LIBNAME]);
                    _ ->
                        filename:join([priv, ?LIBNAME])
                end;
            Dir ->
                filename:join(Dir, ?LIBNAME)
        end,
    erlang:load_nif(SoName, 0).

hash(TimeCost, MemoryCost, Parallelism, Password, Salt, HashLen, Algorithm) ->
    erlang:nif_error(nif_library_not_loaded).
