# RallyNation-MLB

## Authentication

The API uses stateless bearer access tokens. Register and log in at
`POST /api/auth/register` and `POST /api/auth/login`; send the returned token on
protected requests as `Authorization: Bearer <accessToken>`. `GET /api/auth/me`
is a small protected endpoint for verifying the authenticated identity.

### PostgreSQL with pgAdmin

pgAdmin is the GUI used to manage PostgreSQL; the application connects directly
to the PostgreSQL server using JDBC. You do not need a pgAdmin dependency in the
Java project. The default JDBC URL expects PostgreSQL at `localhost:5432` with
a database named `rallynation`.

In pgAdmin, connect to your PostgreSQL server, open **Tools > Query Tool** on
the default `postgres` database, and create an application login and database.
Replace the example password with a strong password:

```sql
CREATE ROLE rallynation LOGIN PASSWORD 'replace-with-a-strong-password';
CREATE DATABASE rallynation OWNER rallynation;
```

The app's default database username is `rallynation`. Set `DB_PASSWORD` to the
password used above before starting the application. You can instead create the
database and login through pgAdmin's **Login/Group Roles** and **Databases**
menus, then provide the matching values through `DB_URL`, `DB_USERNAME`, and
`DB_PASSWORD`. Flyway creates and updates the tables automatically when the app
starts; in pgAdmin, browse **Databases > rallynation > Schemas > public > Tables**
to inspect them. Do not manually create the migrated tables.

Provide `JWT_SECRET` as a Base64-encoded random secret with at least 32 bytes;
do not commit it. For example, PowerShell can generate one with:

```powershell
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[Convert]::ToBase64String($bytes)
$rng.Dispose()
```

`JWT_ISSUER` and `JWT_ACCESS_TOKEN_TTL` are optional; the defaults are
`rallynation-mlb` and `15m`. Flyway applies schema migrations at startup, and
Hibernate validates the mapped schema rather than changing it automatically.

Run the authentication and application tests with `.\mvnw.cmd test`.