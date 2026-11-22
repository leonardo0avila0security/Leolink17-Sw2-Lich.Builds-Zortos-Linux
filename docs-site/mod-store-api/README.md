# Lichii Mod Store API docs

Use Node.js 24 and npm, then run these commands from this directory:

```sh
npm ci
npm run build
```

The build validates internal Markdown links and writes the static site to
`dist/`. Run `npm run dev` to edit locally or `npm run preview` to serve the build.
Add pages under `src/content/docs/` and list them in `astro.config.mjs` if
they belong in the sidebar.

The Cloudflare Pages project is `lichii-mod-api`. Publish the contents of
`dist/` as a static site; no server adapter or runtime variables are needed.
