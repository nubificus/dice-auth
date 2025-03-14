# Dice Authentication

The project is comprised of 2 sub-projects: `submit` and `dice-auth-service`.

## Submit

`submit` is a program that can be used to submit device entries to a `Redis` Database. The source code can be found in `src/redis_submit.c`. First of all, install `redis` and `redis-lib`:
```bash
sudo apt-get install redis-server

# Now redis should run. You can verify it:
redis-cli ping
PONG

sudo apt install libhiredis-dev
```

Now you can clone and prepare the repository by running:
```bash
git clone git@github.com:nubificus/dice-auth.git
cd dice-auth
git submodule update --init
cd  mbedtls && git submodule update --init && make -j$(nproc) && cd -
```

Afterwards, `submit` can be built using the following command:
```bash
make submit
```

And now you can submit a new device entry to the database by running:

```bash
./submit <uuid/key> <Unique-Device-Secret (MAC)> <device-type> <firmware-version> <firmware-type> <redis-db-IP>
```
Internally, `submit` will generate the Root certificate of the device using the unique device secret (the MAC address) and will submit a new entry to the Redis database. That entry will contain the certificate that will be used later to verify incoming attestation certificates.

## Dice Auth Service

This is a simple `http` server that authorizes incoming Attestation certificates. Actually, the server expects `POST` request that contain the attestation certificate, e.g:
```bash
curl -X POST <IP> -H "Content-Type: text/plain" --data-binary @/path/to/attestation.pem
```

### Build and Run
Before building the server, make sure that `OpenSSL` library is installed. Otherwise, install it by running:
```bash
sudo apt install libssl-dev
```

```bash
make dice_auth
make run
```
## Cleanup
```bash
make clean
```
