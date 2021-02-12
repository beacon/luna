# luna

Extended vulnerability scanner based on clair.

Luna can scan a local image without uploading it to another remote server. This makes it possible to place luna in the middle of CI builds and stop it if the image built is way too vulnerable.

Running online updates is fairly slow. Luna can export it's updates into a compressed file, so another luna instance can import those updates. These updates can be specified with date.

![luna-arch](./doc/luna-arch.png)

# Quickstart

1. Database setup

Create a postgres database called clair:
```bash
docker run --name pg -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DATABASE=clair -v $PWD/pgdata:/var/lib/data -e PGDATA=/var/lib/data/pgdata -p 5432:5432  -d docker.io/library/postgres:latest
# Connect to database and create database clair
# Now your DSN looks like postgres://postgres:postgres@localhost/clair?sslmode=disable
```

2. Build luna

```bash
go mod vendor && make luna
```

3. Run online updates

```bash
./bin/luna update --dsn <DSN>
```

4. Scan a local image

The image is supposed to be present on local machine, so a manual pull may be needed.
TODO: Support cri-o and automatical pull.

```bash
docker pull nginx:1.7
./bin/luna scan nginx:1.7 --dsn <DSN>
```

5. Export our vulnerability updates

This exports updates fetched since 2021-02-12 into a file named updates.gz

```bash
./bin/luna export --dsn <DSN> -o updates.gz --from 2021-02-12
```

6. Import dumped updates

```bash
./bin/luna import --dsn <DSN> -i updates.gz
```
