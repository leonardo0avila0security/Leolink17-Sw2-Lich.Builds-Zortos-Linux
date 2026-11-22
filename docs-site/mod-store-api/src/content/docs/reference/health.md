---
title: Health check
description: Check whether the public Mod Store can query its database and find its asset directory.
---

`GET /healthz`

The health check needs no authentication and has no parameters. An empty catalog is healthy. The check does not read individual previews or ZIP files.

## Example

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	https://lichii-api.zortos.me/healthz
```

`200 OK` with `Content-Type: application/json`:

```json
{"status":"ok"}
```

`status` is a string and is always `"ok"` on success.

## Errors

`503 Service Unavailable` with code `unavailable` means the database query failed or the asset directory is unavailable:

```json
{"error":{"code":"unavailable","message":"catalog unavailable"}}
```

See [response schemas](/reference/schemas/) for other public API errors.
