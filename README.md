# LDOups

Oups, we made another Rest API for LDAP.

We use [ToolJet](https://github.com/ToolJet/ToolJet) as Front.

## Configuration

Parameter | Description
--- | ---
`server` | Define host & port for LDOups API
`ldap.ro` | Read-only user used for Easy Login. When a user CN is given, a ldap search is done to find DN and allow LDAP authentication.
`ldap.url` | Url of ldap
`ldap.baseDN` | BaseDN of ldap
`ldap.usersObjectClassSearch` | User object used in your ldap schema
`ldap.userAttributes` | Attributes needed in your schema. If an attribute is required, it will trigger an API error if this attribute is missing during user updates (often used with user id).
`ldap.groupsObjectClassSearch` | user object used in your ldap schema
`ldap.groupAttributes` | Attributes needed in your schema. If an attribute is required, it will trigger an API error if this attribute is missing during group updates.

## Features

- [x] CRUD User/Group
- [x] Easy Login (use CN instead of DN)
- [x] OpenAPI Static (`/openapi.yaml`)
- [x] Front example with [ToolJet](https://github.com/ToolJet/ToolJet) (`front.json`)
- [ ] Dynamic OpenAPI Generation (depending on `ldap.userAttributes` and `ldap.groupAttributes`)
- [ ] Use ZeroLog
- [ ] Generate GoDoc
- [ ] Unit Testing

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

7. Adapt OpenAPI datasource in ToolJet

In ToolJet datasources, adapt OpenAPI to use the correct LDOups API host:port

## Build

```sh
GOOS=linux GOARCH=amd64 go build -o ldoups-linux-amd64
GOOS=darwin GOARCH=amd64 go build -o ldoups-darwin-amd64
```
