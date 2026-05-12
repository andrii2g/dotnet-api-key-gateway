# dotnet-api-key-gateway

Small .NET API key gateway library with:

- core API key generation, hashing, validation, and revocation
- explicit SQL-backed persistence for MySQL and PostgreSQL
- ASP.NET Core authentication/authorization integration
- a runnable Minimal API sample app

## Projects

- `src/ApiKeyGateway`: single reusable library
- `samples/ApiKeyGateway.SampleWeb`: sample Minimal API app
- `tests/ApiKeyGateway.Tests`: merged test suite

## Local databases

Use Docker Compose to start MySQL by default, with PostgreSQL available as an optional profile.

```bash
docker compose up -d
```

This starts:

- `mysql` on `localhost:3306`

To also start PostgreSQL:

```bash
docker compose --profile postgres up -d
```

This additionally starts:

- `postgres` on `localhost:5432`

Both databases initialize the `api_keys` table automatically from the SQL scripts in `src/ApiKeyGateway/Scripts`.

## Run the sample app

In-memory mode:

```bash
dotnet run --project samples/ApiKeyGateway.SampleWeb -- --urls http://localhost:5000
```

MySQL-backed mode:

```bash
dotnet run --project samples/ApiKeyGateway.SampleWeb -- \
  --urls http://localhost:5000 \
  --ApiKeys:Store=MySql \
  --ApiKeys:Dialect=MySql \
  --ApiKeys:ConnectionString="Server=localhost;Port=3306;Database=apikeys;User=app;Password=appsecret;"
```

PostgreSQL-backed mode:

```bash
dotnet run --project samples/ApiKeyGateway.SampleWeb -- \
  --urls http://localhost:5000 \
  --ApiKeys:Store=PostgreSql \
  --ApiKeys:Dialect=PostgreSql \
  --ApiKeys:ConnectionString="Host=localhost;Port=5432;Database=apikeys;Username=app;Password=appsecret"
```

Sample endpoints:

- `POST /api-keys`
- `POST /api-keys/{publicKey}/revoke`
- `GET /secure/personas`
- `GET /health`

## Quick test flow

Create a key:

```bash
curl -X POST http://localhost:5000/api-keys \
  -H "Content-Type: application/json" \
  -d "{\"app\":\"crm\",\"env\":\"local\",\"scopes\":[\"personas:execute\"],\"name\":\"local test\",\"createdBy\":\"readme\"}"
```

Use the returned `fullApiKey`:

```bash
curl http://localhost:5000/secure/personas \
  -H "Authorization: Bearer <fullApiKey>"
```

## Verify

```bash
dotnet build ApiKeyGateway.slnx
dotnet test ApiKeyGateway.slnx --no-build
```
