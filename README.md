# ldoups

Oups, we made another Rest API for LDAP.


## Configuration


## Development

1. Launch LDAP container :

```sh
docker run --detach --rm --name openldap \
  -p 1389:1389 \
  --env LDAP_ADMIN_USERNAME=admin \
  --env LDAP_ADMIN_PASSWORD=admin \
  bitnami/openldap:latest
```

2. Adapt `config.yaml` to adapt ldap url.

3. Launch API

```
go get .
go run .
````

4. Import some data

Run `test.sh` to create users/groups in ldap from API.

5. Run ToolJet as Front

```
docker run --name tooljet --user root --restart unless-stopped -p 3000:3000 -v tooljet_data:/var/lib/postgresql/13/main tooljet/try:latest
```

6. Import front in ToolJet

`front.json`

## Build

```sh
GOOS=linux GOARCH=amd64 go build -o ldoups-linux-amd64
GOOS=darwin GOARCH=amd64 go build -o ldoups-darwin-amd64
```
