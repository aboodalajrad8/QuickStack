# QuickStack

Rapid .NET backend project generator — scaffolds a production-ready Clean Architecture API with authentication, authorization, and infrastructure in seconds.

```bash
dotnet tool install --global QuickStack.cli --version 1.0.0
quickstack
```

## Features

- **Clean Architecture** — Domain, Application, Infrastructure, Api layers with dependency inversion
- **Authentication** — ASP.NET Core Identity + JWT or Custom JWT (password hashing, refresh tokens, email verification, 2FA)
- **Authorization** — Declarative permission system with role/user-level permissions, resource-based ownership checks, audit logging, discovery & sync CLI
- **Databases** — SQL Server, PostgreSQL, MySQL, SQLite — connection strings match your selection
- **Infrastructure** — Rate limiting, global exception handling, Serilog logging, CORS, security headers
- **Docker** — Multi-stage Dockerfile + docker-compose.yml
- **Swagger** — Bearer token support via `BearerSecuritySchemeTransformer`

## Quick Start

```bash
# Install
dotnet tool install --global QuickStack.cli

# Scaffold
quickstack

# Run the generated project
cd ./MyApi/src/Api
dotnet run
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `quickstack` | Interactive scaffolding wizard |
| `quickstack permissions scan` | Discover permissions from code |
| `quickstack permissions sync` | Apply permissions to database |
| `quickstack permissions diff` | Dry-run, exits non-zero on drift |
| `quickstack permissions export` | Export permissions (json/csv/markdown) |
| `quickstack permissions prune` | Remove orphaned permissions |
| `quickstack permissions changelog` | View permission change history |

## Generated Structure

```
Project/
├── src/
│   ├── Api/               Controllers, Middlewares, Filters, Program.cs
│   ├── Application/       DTOs, Interfaces, Validators
│   ├── Domain/            Entities, Enums, Exceptions
│   └── Infrastructure/    Persistence, Services, Authorization, DependencyInjection
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Project Name Rules

- Spaces converted to underscores
- C# reserved keywords rejected
- Must not start with a digit
- Invalid filename characters rejected

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
