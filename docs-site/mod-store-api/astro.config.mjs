import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

export default defineConfig({
  site: 'https://lichii-mod-api.pages.dev',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'Lichii Mod Store API',
      description: 'Integrate the Lichii Mod Store catalog into your emulator.',
      disable404Route: true,
      social: [{ icon: 'github', label: 'Lichii on GitHub', href: 'https://github.com/zortos293/Lichii' }],
      plugins: [starlightLinksValidator()],
      sidebar: [
        { label: 'Overview', link: '/' },
        { label: 'Quickstart', link: '/quickstart/' },
        { label: 'Catalog concepts', link: '/concepts/' },
        {
          label: 'API reference',
          items: [
            { label: 'Health', link: '/reference/health/' },
            { label: 'List games', link: '/reference/games/' },
            { label: 'List mods', link: '/reference/mods/' },
            { label: 'Get a mod', link: '/reference/detail/' },
            { label: 'Get a preview', link: '/reference/preview/' },
            { label: 'Download a managed ZIP', link: '/reference/download/' },
            { label: 'Response schemas', link: '/reference/schemas/' },
          ],
        },
        {
          label: 'Integration guides',
          items: [
            { label: 'Install mods', link: '/guides/installation/' },
            { label: 'Integrity and safety', link: '/guides/integrity/' },
            { label: 'Caching and fair use', link: '/guides/caching/' },
            { label: 'Client examples', link: '/guides/client-examples/' },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Attribution and licensing', link: '/attribution/' },
            { label: 'Support and takedowns', link: '/contact/' },
            { label: 'Versioning and changelog', link: '/changelog/' },
          ],
        },
      ],
    }),
  ],
});
