# Baseline Command Reference

## Build and Test
```bash
go build -o baseline ./cmd/baseline
go test ./...
```

## Core CLI
```bash
baseline version
baseline check
baseline enforce
baseline scan
baseline report --json
baseline report --sarif
baseline explain A1
```

## AI Commands
```bash
baseline generate
baseline pr
```

## API and Dashboard
```bash
baseline api keygen
baseline api verify-prod
baseline api verify-prod --strict
baseline api serve --addr :8080
baseline dashboard --addr 127.0.0.1:8091 --api http://127.0.0.1:8080
```

## API Key Rotation (Managed Keys)
```powershell
# create a new operator key
.\scripts\api-key-rotate.ps1 `
  -ApiBaseUrl http://127.0.0.1:8080 `
  -AdminApiKey "<current_admin_key>" `
  -Role operator `
  -Name "ops-rotation-01"

# create new key and revoke previous key id
.\scripts\api-key-rotate.ps1 `
  -ApiBaseUrl http://127.0.0.1:8080 `
  -AdminApiKey "<current_admin_key>" `
  -Role operator `
  -Name "ops-rotation-02" `
  -RevokeKeyId "<old_key_id>"
```

## Git and Release
```bash
git status
git add -A
git commit -m "your message"
git push origin main

git tag v1.0.1
git push origin v1.0.1
```

## Final Release Gate
```bash
go test ./...
baseline check
baseline report --json
baseline report --sarif
```
