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
	mkdir -p ./certs
	openssl genpkey -algorithm RSA -out ./certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048 				# CA private key
	openssl req -x509 -new -nodes -key ./certs/ca-key.pem -sha256 -days 3650 -out ./certs/ca-cert.pem 	# CA certificate
	openssl genpkey -algorithm RSA -out ./certs/server-key.pem -pkeyopt rsa_keygen_bits:2048 			# Server private key
	openssl req -new -key ./certs/server-key.pem -out ./certs/server-csr.pem							# Server certificate signing request
	openssl x509 -req -in ./certs/server-csr.pem -CA ./certs/ca-cert.pem -CAkey ./certs/ca-key.pem \
		-CAcreateserial -out ./certs/server-cert.pem -days 365 -sha256 									# Server certificate
	openssl genpkey -algorithm RSA -out ./certs/client-key.pem -pkeyopt rsa_keygen_bits:2048			# Client private key
	openssl req -new -key ./certs/client-key.pem -out ./certs/client-csr.pem							# Client certificate signing request
	openssl x509 -req -in ./certs/client-csr.pem -CA ./certs/ca-cert.pem -CAkey ./certs/ca-key.pem \
		-CAcreateserial -out ./certs/client-cert.pem -days 365 -sha256									# Client certificate

