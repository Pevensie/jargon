PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

REBAR=rebar3

.PHONY: compile clean test release-prod release-dev

compile:
	mkdir -p priv
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test:
	@$(REBAR) eunit

build: compile
	@$(REBAR) hex build

publish: build
	@$(REBAR) hex cut --repo hexpm:pevensie
