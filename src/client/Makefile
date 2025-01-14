# This program only communicates over HTTP for the time being, more work on that later.
# Set the your vars in the config.env

# The hosted dylib will be reached via the following variables:
#	http://$(HOST):$(PORT)$(DYLIB_PATH)
# 	NOTE: You must include any '/' in the variables, otherwise it is not written.

include config.env
export

all: release

release: main.c
	gcc main.c -o $(BINARY_NAME) \
		-I/opt/homebrew/opt/openssl@3/include \
		-L/opt/homebrew/opt/openssl@3/lib \
		-lssl \
		-lcrypto \
		-DHOST=\"$(HOST)\" \
		-DPORT=$(PORT) \
		-DDYLIB_PATH=\"$(DYLIB_PATH)\" \
		-DENTRY_POINT=\"$(ENTRY_POINT)\" \
		-DENTRY_POINT_FUNC=$(ENTRY_POINT) \
		-DTMP_FILENAME=\"$(TMP_FILENAME)\"

release-dl: main.c
	gcc main.c -o $(BINARY_NAME).dylib \
		-I/opt/homebrew/opt/openssl@3/include \
		-L/opt/homebrew/opt/openssl@3/lib \
		-lssl \
		-lcrypto \
		-dynamiclib \
		-DHOST=\"$(HOST)\" \
		-DPORT=$(PORT) \
		-DDYLIB_PATH=\"$(DYLIB_PATH)\" \
		-DENTRY_POINT=\"$(ENTRY_POINT)\" \
		-DENTRY_POINT_FUNC=$(ENTRY_POINT) \
		-DTMP_FILENAME=\"$(TMP_FILENAME)\"

debug: main.c
	gcc main.c -o $(BINARY_NAME)_debug \
		-I/opt/homebrew/opt/openssl@3/include \
		-L/opt/homebrew/opt/openssl@3/lib \
		-lssl \
		-lcrypto \
		-DHOST=\"$(HOST)\" \
		-DPORT=$(PORT) \
		-DDYLIB_PATH=\"$(DYLIB_PATH)\" \
		-DENTRY_POINT=\"$(ENTRY_POINT)\" \
		-DENTRY_POINT_FUNC=$(ENTRY_POINT) \
		-DTMP_FILENAME=\"$(TMP_FILENAME)\" \
		-DVERBOSE

test_dylib: testdylib.c
	gcc testdylib.c -dynamiclib -o libtest.dylib

clean: rm -f $(BINARY_NAME)