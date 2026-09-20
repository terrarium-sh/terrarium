<script lang="ts">
	import { base } from '$app/paths';
	import { releaseTag } from '$lib/generated/version.json';

	let { data } = $props();
</script>

<svelte:head>
	<title>{data.guide.title} · Terra</title>
	<meta name="description" content={data.guide.description} />
</svelte:head>

<div class="page-intro">
	<p class="eyebrow">Guides</p>
	<nav aria-label="Guides">
		{#each data.guides as guide}
			<a href={`${base}/docs/${guide.slug}/`} aria-current={guide.slug === data.guide.slug ? 'page' : undefined}>{guide.title}</a>{' '}
		{/each}
	</nav>
</div>

<p class="docs-notice">Development guide, built from the current repository. Features may differ from {releaseTag ?? 'the published release'}; consult the <a href={`${base}/commands/`}>command reference</a> for the binary documented on this site.</p>

<article class="prose">{@html data.guide.html}</article>
