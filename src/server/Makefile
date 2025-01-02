include config.env
export

all: release

release: main.c
	gcc main.c -o $(BINARY_NAME) \
		-lssl \
		-lcrypto

debug: main.c
	gcc main.c -o $(BINARY_NAME) \
		-lssl \
		-lcrypto \
		-DVERBOSE

test-certs: 
			# Default parameters have been given (e.g. -subj "/CN=Test/O=Client/C=US") to each certificate
			# in an attempt to prevent time-consuming user input. Change this in production.
			# All certificates are generated with default 365 day expiration.

	mkdir -p ./certs
	openssl genpkey -algorithm RSA -out ./certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048					# CA private key
	openssl req -x509 -new -nodes -key ./certs/ca-key.pem -sha256 -days 3650 -out ./certs/ca-cert.pem \
		-subj "/CN=Test/O=Client/C=US"																		# CA certificate

	openssl genpkey -algorithm RSA -out ./certs/server-key.pem -pkeyopt rsa_keygen_bits:2048				# Server private key
	openssl req -new -key ./certs/server-key.pem -out ./certs/server-csr.pem \
		-subj "/CN=Server/O=Client/C=US"																	# Server certificate signing request
	openssl x509 -req -in ./certs/server-csr.pem -CA ./certs/ca-cert.pem -CAkey ./certs/ca-key.pem \
		-CAcreateserial -out ./certs/server-cert.pem -days 365 -sha256										# Server certificate

	openssl genpkey -algorithm RSA -out ./certs/client-key.pem -pkeyopt rsa_keygen_bits:2048				# Client private key
	openssl req -new -key ./certs/client-key.pem -out ./certs/client-csr.pem \
		-subj "/CN=Beacon/O=Client/C=US"																	# Client certificate signing request
	openssl x509 -req -in ./certs/client-csr.pem -CA ./certs/ca-cert.pem -CAkey ./certs/ca-key.pem \
		-CAcreateserial -out ./certs/client-cert.pem -days 365 -sha256										# Client certificate

clean-certs:
	find ./certs/ | grep -E 'pem|srl' | xargs rm
