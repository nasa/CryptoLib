#
# CryptoLib Makefile
#

# The "LOCALTGTS" defines the top-level targets that are implemented in this makefile
# Any other target may also be given, in that case it will simply be passed through.
LOCALTGTS := all clean debug internal kmc wolf
OTHERTGTS := $(filter-out $(LOCALTGTS),$(MAKECMDGOALS))

# As this makefile does not build any real files, treat everything as a PHONY target
# This ensures that the rule gets executed even if a file by that name does exist
.PHONY: $(LOCALTGTS) $(OTHERTGTS)

#
# Commands
#
all:
	$(MAKE) internal
	$(MAKE) kmc
	$(MAKE) wolf

clean:
	rm -rf ./build
	rm -rf ./build-asan
	rm -rf ./build-cmplog
	rm -rf ./build-compcov
	rm -rf ./docs/wiki/_build

debug:
	./support/scripts/docker_debug.sh

docs:
	./support/scripts/documentation_build.sh

internal: 
	./support/scripts/internal_docker_build.sh

kmc:
	./support/scripts/kmc_docker_build.sh

wolf:
	./support/scripts/wolf_docker_build.sh

env:
	./support/scripts/update_env.sh
