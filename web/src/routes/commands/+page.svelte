<script lang="ts">
  import { Input, Button } from '@alis-is/starlight';
  import commands from '$lib/generated/commands.json';
  import { version } from '$lib/generated/version.json';

  let query = $state('');
  const terms = $derived(query.toLowerCase().trim().split(/\s+/).filter(Boolean));
  const matches = $derived(commands.filter(command => terms.every(term =>
    `${command.title} ${command.description} ${command.help}`.toLowerCase().includes(term)
  )));
</script>

<svelte:head>
  <title>Command reference — Terrarium</title>
  <meta name="description" content="Search Terra commands, options, and examples. A command reference generated from the Terra CLI." />
</svelte:head>

<div class="page-intro">
  <p class="eyebrow">Keep the reference close</p>
  <h1>Every command.<br />A little less guesswork.</h1>
  <p>The box comes first: <code>terra [BOX] command</code>. Omit <code>BOX</code> to use this directory’s only box.</p>
  <p class="small">Generated from <code>{version}</code>. Search commands, flags, and examples below.</p>
</div>
<div class="search-row" role="search" aria-label="Command reference">
  <Input id="command-search" label="Search commands, flags, examples" bind:value={query} aria-controls="command-results" />
  {#if query}<Button onclick={() => query = ''}>Clear</Button>{/if}
</div>
<p class="small muted" role="status">{matches.length} of {commands.length} commands</p>
<noscript><p>All commands are listed below. Use your browser’s Find command to search this page.</p></noscript>
<div class="reference-layout" id="command-results">
  <aside class="reference-nav" aria-label="Jump to a command">
    {#each matches as command}<a href="#{command.slug}">{command.title}</a>{/each}
  </aside>
  <div>
    {#each matches as command}
      <section class="command" id={command.slug}>
        <h2><a href="#{command.slug}"><code>{command.title}</code></a></h2>
        <p>{command.description}</p>
        <pre><code>{command.help}</code></pre>
      </section>
    {:else}
      <h2>No matching commands.</h2><p>Try a command such as <code>setup</code>, or a flag such as <code>--project</code>.</p>
    {/each}
  </div>
</div>
