# Agent instructions

Rules for AI coding agents working on Sovite. `CLAUDE.md` is a symlink to this file.

## Git

- Never run `git commit` or `git push`, in any form (including `--amend` and `--force`). The maintainer commits and pushes. Leave changes in the working tree.

## Database

Sovite's own data lives in its database through Ecto (`Sovite.Core.Repo`). SQLite is the default; PostgreSQL and MySQL are chosen with `[database] adapter`.

- Every database table is defined explicitly. Each one gets:
  - its own migration module, one file in `lib/core/repo/migrations/` (`Sovite.Core.Repo.Migrations.*`), registered in `Sovite.Core.Repo` `@migrations` with a new, increasing version;
  - its own typed Ecto schema (model), one file in `lib/core/repo/schemas/` (`Sovite.Core.Repo.Schemas.*`).
- Schemas live only in `lib/core/repo/schemas/`.
- The modules that read and write a table (`Sovite.Core.Repo.Tables.Aliases`, `...Domains`, ...) go in `lib/core/repo/tables/`, one file each. Helpers they share are in `Sovite.Core.Repo.Data` (`lib/core/repo/data.ex`).
- Everything else, including `sovitectl` (`lib/core/cli*`), uses the database only through `lib/core/repo/tables/` modules: no Ecto queries, schemas, or repo calls outside `lib/core/repo/`. If a command needs something a table module doesn't offer, add it to the table module.
- No generic or catch-all tables: no key/value stores, and no "type + untyped value" columns holding different kinds of data. A schema that isn't defined can't be migrated later.
- Never edit a migration that has shipped. Change the schema with a new migration.
- Migrations run automatically at startup. Every migration must work on all three adapters, so never use adapter-specific SQL.

## Code

- `lib/<component>/` folders are reusable libraries (see `STRUCTURE.md`):
  - They never reference `Sovite.Core`; `scripts/check_boundaries.sh` enforces this.
  - They report through telemetry instead of logging.
- Never create atoms from untrusted input.
- Match the surrounding code: naming, comment density, documentation style.

## Checks

The pre-commit hook runs these, but run them yourself before saying work is done:

```sh
mix lint            # format, warnings as errors, credo --strict, xref cycles
mix dialyzer
mix test            # coverage must stay at or above 85%
scripts/check_boundaries.sh
```
