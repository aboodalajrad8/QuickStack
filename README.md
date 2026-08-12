# QuickStack

**Rapid .NET Backend Environment Generator** — an interactive CLI that scaffolds a production-ready ASP.NET Core backend with Clean Architecture, JWT authentication, a full permission system, and more. One command, zero configuration.

## Features

- **Clean Architecture** — 4 projects: `Domain`, `Application`, `Infrastructure`, `Api` (classic Vertical Layers + Clean Architecture folder layout)
- **Authentication** (choose one):
  - ASP.NET Core Identity + JWT
  - Lightweight Custom JWT (BCrypt, no Identity dependency)
  - None
- **Auth sub-features**: refresh token rotation with family-wide revocation, email verification, 2FA, login via email / phone / username / both
- **Permission system** — `RequirePermission` / `RequireAnyPermission` attributes, role & user permission management, audit logs, append-only audit tables, permission seeding
- **Databases**: SQL Server, PostgreSQL, MySQL, SQLite, or none
- **Features**: Swagger with JWT bearer input, Serilog, global exception handling middleware, rate limiting, multi-stage Dockerfile + docker-compose
- **CLI subcommand**: `quickstack permissions scan|sync|diff|export|prune|changelog`

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download) (required to scaffold and run generated projects)
- A database of your choice (optional — "None" is supported)

## Usage

### Option A — Download the standalone exe (no .NET install needed to run the tool)

Grab `quickstack.exe` from the [latest release](https://github.com/aboodalajrad8/QuickStack/releases), open a terminal, and run it:

```bash
./quickstack.exe
```

### Option B — Build from source

```bash
git clone https://github.com/aboodalajrad8/QuickStack.git
cd QuickStack/QuickStack
dotnet run
```

### Option C — Install as a .NET tool

```bash
dotnet tool install --global QuickStack.cli
quickstack
```

### Option D — Publish a self-contained exe (for sharing)

```bash
dotnet publish QuickStack/QuickStack.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish
```

## Interactive prompts

The CLI walks you through:

1. **Project name** (validated against C# keywords and invalid filename characters)
2. **Output directory**
3. **Database** — SQL Server, PostgreSQL, MySQL, SQLite, None
4. **Authentication type** — ASP.NET Identity + JWT, Custom JWT, None
5. **Login identifier** — Email, Phone Number, Both, Username
6. **Auth features** — Refresh Tokens, Account Verification (email confirmation), 2FA
7. **Email provider** (if verification enabled) — Resend or Google Gmail SMTP
8. **Features** — Serilog, Global Exception Handling, Docker, Rate Limiting (JWT + Swagger is included when auth is on)

A summary table is shown before anything is generated — confirm and go.

## Generated project layout

```
YourProject/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── src/
    ├── Domain/          # Entities, Enums, Exceptions, Common
    ├── Application/     # DTOs, Interfaces, Authorization abstractions
    ├── Infrastructure/  # Persistence (EF Core), Services, DependencyInjection
    └── Api/             # Controllers, Middlewares, Filters, Program.cs
```

## Permissions CLI

Generated projects expose a permission management CLI. Run it from the QuickStack tool:

```bash
quickstack permissions scan    # discover permissions from code (no DB writes)
quickstack permissions sync    # apply discovered permissions to database
quickstack permissions diff    # dry-run of sync (exits non-zero on drift)
quickstack permissions export --format:json   # json | csv | markdown
quickstack permissions prune --yes           # delete orphaned permissions
quickstack permissions changelog             # print change log history
```

`--project-path <path>` points at a scaffolded project (defaults to the current directory).

## Tech

- .NET 10, Spectre.Console, top-level programs
- EF Core (provider chosen at prompt time), JWT bearer auth, BCrypt.Net-Next, FluentValidation, MailKit (optional)

## License

[MIT](LICENSE)
