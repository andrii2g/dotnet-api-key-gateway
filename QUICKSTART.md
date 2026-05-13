# Quick Start

This guide shows the full local flow for the sample Minimal API app with Docker-backed MySQL.

## Prerequisites

- Docker with `docker compose`
- .NET 10 SDK

All commands below should be run from the repository root.

## 1. Start MySQL

```bash
docker compose up -d
```

Check container status:

```bash
docker compose ps
```

The default setup starts:

- MySQL on `localhost:3306`
- database: `apikeys`
- user: `app`
- password: `appsecret`

The `api_keys` table is initialized automatically from:

- `src/ApiKeyGateway/Scripts/mysql/001_create_api_keys.sql`

Optional PostgreSQL too:

```bash
docker compose --profile postgres up -d
```

## 2. Run the sample Minimal API app

Use the MySQL-backed sample:

```bash
dotnet run --project samples/ApiKeyGateway.SampleWeb -- \
  --urls http://localhost:5000 \
  --ApiKeys:Store=MySql \
  --ApiKeys:Dialect=MySql \
  --ApiKeys:CurrentEnvironment=local \
  --ApiKeys:ConnectionString="Server=localhost;Port=3306;Database=apikeys;User=app;Password=appsecret;"
```

Useful health checks:

```bash
curl http://localhost:5000/
curl http://localhost:5000/health
```

## 3. Create a test API key

```bash
curl -X POST http://localhost:5000/api-keys \
  -H "Content-Type: application/json" \
  -d '{"app":"crm","env":"local","scopes":["personas:execute"],"name":"local test","createdBy":"quickstart"}'
```

Example response shape:

```json
{
  "id": 1,
  "app": "crm",
  "env": "local",
  "publicKey": "ABCDEFGHJKLMNP23",
  "fullApiKey": "ak_crm_ABCDEFGHJKLMNP23_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "scopes": ["personas:execute"],
  "expiresAt": null,
  "name": "local test",
  "createdBy": "quickstart"
}
```

Save these values from the response:

- `fullApiKey`
- `publicKey`

## 4. Test the API key

Replace `<fullApiKey>` with the returned key:

```bash
curl http://localhost:5000/secure/personas \
  -H "Authorization: Bearer <fullApiKey>"
```

Expected result:

```json
{
  "message": "Authenticated with API key.",
  "tip": "Call this endpoint with Authorization: Bearer <fullApiKey>."
}
```

## 5. Revoke the API key

Use the returned `publicKey`:

```bash
curl -X POST http://localhost:5000/api-keys/<publicKey>/revoke
```

The sample also accepts:

- the full API key
- a pasted `publicKey_secretPrefix` fragment

## 6. Confirm the revoked key no longer works

```bash
curl http://localhost:5000/secure/personas \
  -H "Authorization: Bearer <fullApiKey>"
```

Expected result:

- HTTP `401`
- body: `{"error":"invalid_api_key"}`

## 7. Stop containers

Keep data:

```bash
docker compose down
```

## 8. Remove containers and all database data

This removes:

- containers
- networks
- named volumes

```bash
docker compose down -v
```

If you also started PostgreSQL with the optional profile and want to clean that data too:

```bash
docker compose --profile postgres down -v
```
