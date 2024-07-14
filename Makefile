PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

REBAR=rebar3

.PHONY: compile clean test release-prod release-dev

compile:
	mkdir -p priv
	(cd argon2;make all;cd ..;cp argon2/libargon2.so.1 argon2/libargon2.a priv)
	@$(REBAR) compile

clean:
	(cd argon2;make clean;cd ..;rm -f priv/libargon2.so.1 priv/libargon2.a priv/kat-argon2*)
	@$(REBAR) clean

test:
	@$(REBAR) eunit

build: compile
	@$(REBAR) hex build

publish: build
	@$(REBAR) hex cut --repo hexpm:pevensie
