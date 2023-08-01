# Dependabot Dashboard

A simple Python script to dump Dependabot alerts from all GitHub orgs and repos to PostgresDB.

Requires the following env variables to execute:
- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `GH_HOST`
- `GH_TOKEN` (needs full repo access to query internal repos)
- `GH_ORG`

The script needs to be run everyday to visualize metrics over time.

**Note:** This fork has been adapted to work on GitHub.com and GitHub Enterprise Cloud. 

### Fork changes
- Support Github cloud instead of GitHub Enterprise Server
- Added CVE details including CVSS score
- Added `GH_ORG` env variable to query a specific organization