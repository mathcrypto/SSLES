CLI = .build/ssles_cli
KEY_PREFIX = .keys/ssles
PROVING_KEY = $(KEY_PREFIX).pk.raw
VERIFYING_KEY = $(KEY_PREFIX).vk.json
CMAKE ?= cmake
GIT ?= git

all: $(CLI) test

$(CLI): .build
	$(MAKE) -C $(dir $@)

.build:
	mkdir -p $@
	cd $@ && $(CMAKE) ../src/ || rm -rf ../$@

debug:
	mkdir -p .build && cd .build && $(CMAKE) -DCMAKE_BUILD_TYPE=Debug ../src/

release:
	mkdir -p .build && cd .build && $(CMAKE) -DCMAKE_BUILD_TYPE=Release ../src/

performance:
	mkdir -p .build && cd .build && $(CMAKE) -DCMAKE_BUILD_TYPE=Release -DPERFORMANCE=1 ../src/

git-submodules:
	$(GIT) submodule update --init --recursive

git-pull:
	$(GIT) pull --recurse-submodules
	$(GIT) submodule update --recursive --remote

clean:
	rm -rf .build 



test: .keys/ssles.pk.raw  solidity-test python-test

.keys/ssles.pk.raw: $(CLI)
	mkdir -p $(dir $@)
	$(CLI) genkeys $(PROVING_KEY) $(VERIFYING_KEY)