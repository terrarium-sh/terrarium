<script lang="ts">
	import { resolve } from '$app/paths';
	import { onMount } from 'svelte';
	import { Select, type SelectItem } from '@alis-is/starlight';
	import { releaseTag } from '#lib/generated/version.json';
	import { copyGuideCode } from '#lib/copy-guide-code.ts';
	import { detectClientPlatform, type ClientPlatform } from '#lib/client-platform.ts';
	import PageMeta from '#lib/PageMeta.svelte';

	let { data } = $props();

	let platform = $state<ClientPlatform>('');
	let isClient = $state(false);
	const platformChoices = $derived<SelectItem<ClientPlatform>[]>([
		{ label: 'All platforms', value: '' },
		...data.guide.platforms.map(({ platform, label }) => ({ label, value: platform }))
	]);

	/** A link to `#linux` or one of its headings selects that platform's section. */
	const selectLinkedPlatform = () => {
		const hash = location.hash.slice(1);
		const linked = data.guide.platforms.find(
			(section) => hash === section.platform || hash.startsWith(`${section.platform}-`)
		);
		if (linked) platform = linked.platform;
	};

	onMount(() => {
		platform = detectClientPlatform(navigator);
		selectLinkedPlatform();
		isClient = true;
	});
</script>

<svelte:window onhashchange={selectLinkedPlatform} />

<PageMeta title={`${data.guide.title} — Terrarium`} description={data.guide.description} />

<div class="page-intro">
	<p class="eyebrow">Guides</p>
	<nav aria-label="Guides">
		{#each data.guides as guide}
			<a href={resolve(`docs/${guide.slug}/`)} aria-current={guide.slug === data.guide.slug ? 'page' : undefined}>{guide.title}</a>{' '}
		{/each}
	</nav>
</div>

<p class="docs-notice">Development guide, built from the current repository. Features may differ from {releaseTag ?? 'the published release'}; consult the <a href={resolve('commands/')}>command reference</a> for the binary documented on this site.</p>

{#key data.guide.slug}
	<article class="prose" use:copyGuideCode>{@html data.guide.html}</article>
	{#if data.guide.platforms.length}
		<section class="platform-sections" aria-label="Platforms">
			{#if isClient}
				<div class="platform-choice">
					<Select
						label="Show platform"
						options={platformChoices}
						value={platformChoices.find((choice) => choice.value === platform)}
						onselected={(choice: SelectItem<ClientPlatform>) => (platform = choice.value)}
					/>
				</div>
			{/if}
			{#each data.guide.platforms as section (section.platform)}
				<article
					id={section.platform}
					class="prose"
					hidden={isClient && platform !== '' && platform !== section.platform}
					use:copyGuideCode
				>
					{@html section.html}
				</article>
			{/each}
		</section>
	{/if}
{/key}
