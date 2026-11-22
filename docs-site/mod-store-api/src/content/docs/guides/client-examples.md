---
title: Client examples
description: Page through the Mod Store catalog and verify a file from its original GitHub source.
---

Each example lists mods for 13 Sentinels Aegis Rim, one mod per page, then fetches the detail for the 16.10 Ultrawide listing. Keep the filters, sort order, and `X-Lichii-Catalog-Features: github-v1` header the same on each page. Pass the returned `next_offset` as `offset` and stop at `null`. Send the same header on the detail request.

For the byte check, the examples use the first build with a `download` object. They fetch `path` from `raw.githubusercontent.com` at the catalog's exact `repository` and `commit`, with each path segment URL-encoded. They don't send the catalog header to GitHub or follow redirects.

If `download` is absent for a build, offer the listing's `source_url` instead. For a ZIP, `size_bytes` and `sha256` describe the whole ZIP, not the `member` inside it. These examples verify and discard the bytes. They don't check game compatibility, extract a patch, or grant permission to redistribute it.

See [List mods](/reference/mods/) and [Get a mod](/reference/detail/) for the request and response fields. Before installing a verified download, follow the [integrity and safety guide](/guides/integrity/).

## Python

Save as `verify-mod.py`. Run `python3 verify-mod.py` using Python 3. No packages are required.

```python
import hashlib
import json
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

API = "https://lichii-api.zortos.me/api/v1"
MOD_ID = "gh-fl4sh9174-16-10-ultrawide-d1a9cf61a887cb32"


class NoRedirects(HTTPRedirectHandler):
	def redirect_request(self, req, fp, code, msg, headers, newurl):
		return None


http = build_opener(NoRedirects())


def get(url, *, catalog=False, limit=2 << 20):
	headers = {"User-Agent": "Lichii-Mod-Store-Python-Example/1.0"}
	if catalog:
		headers["X-Lichii-Catalog-Features"] = "github-v1"
	with http.open(Request(url, headers=headers), timeout=20) as response:
		if response.status != 200:
			raise ValueError(f"HTTP {response.status}: {url}")
		body = response.read(limit + 1)
	if len(body) > limit:
		raise ValueError(f"Response exceeds {limit} bytes: {url}")
	return body


offset = 0
while offset is not None:
	url = f"{API}/mods?title_id=01003FC01670C000&sort=name&limit=1&offset={offset}"
	page = json.loads(get(url, catalog=True))
	for mod in page["mods"]:
		print(mod["id"], mod["name"])
	offset = page["next_offset"]

detail = json.loads(get(f"{API}/mods/{MOD_ID}", catalog=True))
github = detail["github"]
download = next((b["download"] for b in github["builds"] if "download" in b), None)
if download is None:
	raise SystemExit(f"No download metadata. Open {detail['source_url']}")

size = download["size_bytes"]
if not 0 < size <= (64 << 20):
	raise ValueError("Invalid download size")

path = f"{github['repository']}/{github['commit']}/{download['path']}"
raw_url = "https://raw.githubusercontent.com/" + quote(path, safe="/")
body = get(raw_url, limit=size)
digest = hashlib.sha256(body).hexdigest()
if len(body) != size or digest != download["sha256"]:
	raise ValueError("Download size or SHA-256 mismatch")
print(f"Verified {len(body)} bytes: {digest}")
```

## TypeScript

Use Node.js 24. Save as `verify-mod.mts`, then install Zod and run the example:

```sh
npm install zod@4
node verify-mod.mts
```

```ts
import { createHash } from "node:crypto";
import { z } from "zod";

const api = "https://lichii-api.zortos.me/api/v1";
const modId = "gh-fl4sh9174-16-10-ultrawide-d1a9cf61a887cb32";
const catalogHeaders = { "X-Lichii-Catalog-Features": "github-v1" };

const pageSchema = z.object({
	mods: z.array(z.object({ id: z.string(), name: z.string() })),
	next_offset: z.number().int().nonnegative().nullable(),
});
const detailSchema = z.object({
	source_url: z.string(),
	github: z.object({
		repository: z.string().regex(/^[\w-]+\/[\w.-]+$/),
		commit: z.string().regex(/^[0-9a-f]{40}$/),
		builds: z.array(z.object({
			download: z.object({
				path: z.string(),
				size_bytes: z.number().int().positive().max(64 * 1024 * 1024),
				sha256: z.string().regex(/^[0-9a-f]{64}$/),
			}).optional(),
		})),
	}),
});

async function get(url: string, headers?: HeadersInit) {
	const requestHeaders = new Headers(headers);
	requestHeaders.set("User-Agent", "Lichii-Mod-Store-TypeScript-Example/1.0");
	const response = await fetch(url, {
		headers: requestHeaders,
		redirect: "error",
		signal: AbortSignal.timeout(20_000),
	});
	if (response.status !== 200) {
		throw new Error(`HTTP ${response.status}: ${url}`);
	}
	return response;
}

let offset: number | null = 0;
while (offset !== null) {
	const url = `${api}/mods?title_id=01003FC01670C000&sort=name&limit=1&offset=${offset}`;
	const response = await get(url, catalogHeaders);
	const page = pageSchema.parse(await response.json());
	for (const mod of page.mods) {
		process.stdout.write(`${mod.id} ${mod.name}\n`);
	}
	offset = page.next_offset;
}

const metadata = await get(`${api}/mods/${modId}`, catalogHeaders);
const detail = detailSchema.parse(await metadata.json());
const { repository, commit, builds } = detail.github;
const download = builds.find((build) => build.download !== undefined)?.download;
if (!download) {
	throw new Error(`No download metadata. Open ${detail.source_url}`);
}

const path = `${repository}/${commit}/${download.path}`.split("/").map(encodeURIComponent).join("/");
const response = await get(`https://raw.githubusercontent.com/${path}`);
if (!response.body) {
	throw new Error("Missing download body");
}

const hash = createHash("sha256");
let size = 0;
for await (const chunk of response.body) {
	size += chunk.byteLength;
	if (size > download.size_bytes) {
		throw new Error("Download exceeds the catalog size");
	}
	hash.update(chunk);
}
const digest = hash.digest("hex");
if (size !== download.size_bytes || digest !== download.sha256) {
	throw new Error("Download size or SHA-256 mismatch");
}
process.stdout.write(`Verified ${size} bytes: ${digest}\n`);
```

## C++

Save as `verify-mod.cpp`. On Ubuntu, install a C++17 compiler and the development packages for libcurl, OpenSSL, and nlohmann/json:

```sh
sudo apt install g++ libcurl4-openssl-dev libssl-dev nlohmann-json3-dev
g++ -std=c++17 verify-mod.cpp -o verify-mod -lcurl -lcrypto
./verify-mod
```

```cpp
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

using nlohmann::json;
const std::string api = "https://lichii-api.zortos.me/api/v1";
const std::string mod_id = "gh-fl4sh9174-16-10-ultrawide-d1a9cf61a887cb32";

std::string get(const std::string& url, bool catalog = false, std::size_t limit = 2 << 20) {
	struct Buffer {
		std::string bytes;
		std::size_t limit;
	} buffer{{}, limit};
	std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
	if (!curl) {
		throw std::runtime_error("Could not initialize libcurl");
	}
	std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
		catalog ? curl_slist_append(nullptr, "X-Lichii-Catalog-Features: github-v1") : nullptr,
		curl_slist_free_all);
	if (catalog && !headers) {
		throw std::runtime_error("Could not set catalog header");
	}

	curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, "Lichii-Mod-Store-Cpp-Example/1.0");
	curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 20L);
	curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
	curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &buffer);
	curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION,
		+[](char* data, std::size_t size, std::size_t count, void* user) -> std::size_t {
			auto& out = *static_cast<Buffer*>(user);
			const auto length = size * count;
			if (length > out.limit - out.bytes.size()) {
				return 0;
			}
			try {
				out.bytes.append(data, length);
			} catch (...) {
				return 0;
			}
			return length;
		});
	const auto result = curl_easy_perform(curl.get());
	if (result != CURLE_OK) {
		throw std::runtime_error(url + ": " + curl_easy_strerror(result));
	}
	long status = 0;
	curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
	if (status != 200) {
		throw std::runtime_error("HTTP " + std::to_string(status) + ": " + url);
	}
	return std::move(buffer.bytes);
}

std::string raw_url(const std::string& path) {
	std::istringstream input(path);
	std::string url = "https://raw.githubusercontent.com";
	for (std::string segment; std::getline(input, segment, '/');) {
		std::unique_ptr<char, decltype(&curl_free)> escaped(
			curl_easy_escape(nullptr, segment.c_str(), 0), curl_free);
		if (!escaped) {
			throw std::runtime_error("Could not encode GitHub path");
		}
		url += '/';
		url += escaped.get();
	}
	return url;
}

int main() try {
	int offset = 0;
	for (;;) {
		const auto page = json::parse(get(api + "/mods?title_id=01003FC01670C000&sort=name"
			"&limit=1&offset=" + std::to_string(offset), true));
		for (const auto& mod : page.at("mods")) {
			std::cout << mod.at("id").get<std::string>() << ' '
				<< mod.at("name").get<std::string>() << '\n';
		}
		const auto& next = page.at("next_offset");
		if (next.is_null()) {
			break;
		}
		offset = next.get<int>();
	}

	const auto detail = json::parse(get(api + "/mods/" + mod_id, true));
	const auto& github = detail.at("github");
	for (const auto& build : github.at("builds")) {
		if (!build.contains("download")) {
			continue;
		}
		const auto& download = build.at("download");
		const auto size = download.at("size_bytes").get<long long>();
		if (size <= 0 || size > (64 << 20)) {
			throw std::runtime_error("Invalid download size");
		}

		const auto path = github.at("repository").get<std::string>() + '/' +
			github.at("commit").get<std::string>() + '/' + download.at("path").get<std::string>();
		const auto bytes = get(raw_url(path), false, static_cast<std::size_t>(size));
		unsigned char hash[SHA256_DIGEST_LENGTH];
		if (!SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), hash)) {
			throw std::runtime_error("Could not calculate SHA-256");
		}
		std::ostringstream digest;
		for (const auto byte : hash) {
			digest << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		}
		if (bytes.size() != static_cast<std::size_t>(size) || digest.str() != download.at("sha256")) {
			throw std::runtime_error("Download size or SHA-256 mismatch");
		}
		std::cout << "Verified " << bytes.size() << " bytes: " << digest.str() << '\n';
		return 0;
	}
	throw std::runtime_error("No download metadata. Open " + detail.at("source_url").get<std::string>());
} catch (const std::exception& error) {
	std::cerr << error.what() << '\n';
	return 1;
}
```
