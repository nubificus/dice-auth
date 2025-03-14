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

Afterwards, `submit` can be built using the following command:
```bash
make submit
```
And now you can submit a new device entry to the database by running:

```bash
./submit <uuid/key> <path-to-root.pem> <device-type> <firmware-version> <firmware-type> <redis-db-IP>
```
Now the entry contains a root certificate that will be used later to verify attestation incoming certificates.

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
