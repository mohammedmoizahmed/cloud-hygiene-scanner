# Cloud hygiene and compliance scanner

[![ci](https://github.com/mohammedmoizahmed/cloud-hygiene-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mohammedmoizahmed/cloud-hygiene-scanner/actions/workflows/ci.yml)

A small web app that reads an AWS account, read-only, and lists what needs attention: security gaps, wasted spend, missing governance tags and weak resilience. Every finding has a severity, a category, the affected resource and a recommendation.

The app is deliberately small. The real project is the **delivery pipeline** around it: a change pushed to GitHub is linted, tested, scanned, packaged and deployed to a server automatically, with no manual steps on the server.

## What it checks

| Check | Category | What it reports |
|---|---|---|
| Security groups open to the internet | Security | All traffic or all TCP ports open (critical); SSH, RDP, database and other sensitive ports open to `0.0.0.0/0` or `::/0` (high) |
| S3 Block Public Access | Security | Buckets with no Block Public Access settings (high) or only some of them (medium). Skipped when the whole account is blocked |
| Unencrypted EBS volumes | Security | Volumes stored without encryption |
| RDS posture | Security, Resilience | Public databases, unencrypted storage, automated backups off, single-AZ |
| Unattached EBS volumes | Cost | Volumes not attached to anything but still billed |
| Required tags | Governance | Running or stopped instances missing the required tags (default `Name`, `Project`) |

Each finding also carries a general control area (for example "Network security" or "Backup and recovery") as a study reference. **These are guidance, not a formal audit or a compliance certificate.**

## How it behaves

- **Read-only.** It only calls `Describe*` and `List*` APIs. It never changes the account.
- **Partial results are honest.** If a check lacks permission or fails, the dashboard lists it under "Checks that could not run" and the other checks still report.
- **Never public.** Every page except `/health` and `/version` needs a username and password, and the app refuses to start without them.
- **Versioned.** `/version` shows the exact commit and build time of the running container, so every release is visible.

## Run it locally

1. Create a read-only IAM user and attach `docs/iam-read-only-policy.json`. Configure a profile for it with `aws configure --profile scanner`.
2. Build and run (Windows CMD):

```
docker build -t cloud-hygiene-scanner .
docker run --rm -p 5000:5000 ^
  -e SECRET_KEY=change-this-to-something-long ^
  -e SCANNER_PASSWORD=choose-a-password ^
  -e AWS_PROFILE=scanner ^
  -v "%USERPROFILE%\.aws:/home/app/.aws:ro" ^
  cloud-hygiene-scanner
```

3. Open http://localhost:5000, sign in as `admin` with that password, and press **Run scan now**.

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | required | Signs the session cookie |
| `SCANNER_PASSWORD` | required | Password for the dashboard (`SCANNER_USER`, default `admin`) |
| `SCAN_REGIONS` | `us-east-1` | Comma-separated regions to scan |
| `REQUIRED_TAGS` | `Name,Project` | Tags every instance must have |
| `DISPLAY_UTC_OFFSET` | `3` | Hours added to UTC when showing times |
| `COOKIE_SECURE` | off | Set to `1` once the site is served over HTTPS |

## Tests

The tests run against a mocked AWS (moto), so they need no account and cost nothing.

```
pip install -r requirements-dev.txt
pytest --cov=app
ruff check .
```

## The pipeline (roadmap)

```
git push -> lint, tests, security scans -> build image -> push to ECR
         -> deploy to staging -> smoke test -> approval -> production
         -> health check fails? roll back automatically -> alarms email you
```

| Phase | What | Status |
|---|---|---|
| 1 | The app, its tests, and CI (lint, tests, image build and health check) | Done |
| 2 | Continuous delivery: push the image to Amazon ECR and update the server | Planned |
| 3 | Infrastructure as code with Terraform, and GitHub OIDC instead of stored keys | Planned |
| 4 | Staging and production, manual approval, automatic rollback | Planned |
| 5 | Security scanning in the pipeline, CloudWatch alarms and notifications | Planned |
| 6 | Move from EC2 with Docker to ECS Fargate | Planned |

## Limitations

- The latest scan is kept in memory, so it is lost when the container restarts. Scan history in DynamoDB is planned.
- Access control is one shared username and password. Until the site is behind HTTPS, use it only locally or from a restricted address.
- Checks cover a handful of services. Adding one is a single function with its own tests: see `app/checks/`.
