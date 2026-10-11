<script lang="ts">
  import { page } from '$app/state';

  let { title, description }: { title: string; description: string } = $props();
  let url = $derived(page.url.origin + page.url.pathname);
</script>

<svelte:head>
  <title>{title}</title>
  <meta name="description" content={description} />
  <link rel="canonical" href={url} />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="Terrarium" />
  <meta property="og:title" content={title} />
  <meta property="og:description" content={description} />
  <meta property="og:url" content={url} />
  <meta name="twitter:card" content="summary" />
</svelte:head>
