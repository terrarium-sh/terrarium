<script lang="ts">
  import { resolve } from '$app/paths';
  import { Rotation } from '#lib/rotation.svelte.ts';
  import type { Snippet } from 'svelte';
  import { fade } from 'svelte/transition';

  let { children }: { children: Snippet } = $props();

  type Line = { text: string; kind?: 'command' | 'key' | 'output' | 'denied'; prompt?: string; note?: string };
  type Benefit = { title: string; text: string; icon: string; screen: string; lines: Line[]; link: { label: string; href: string; arrow: string } };

  const CYCLE_MS = 7000;
  const TAPPED_DWELL_MS = 14000;
  const DESCRIPTION_FADE_MS = 180;

  const benefits: Benefit[] = [
    {
      title: 'Your harness, confined',
      text: 'Run Claude Code, Codex or your own tools inside a VM. Your recipe grants the project folders and network destinations the harness can reach.',
      icon: 'M3 4h18v16H3ZM7 9l3 3-3 3M12 15h5',
      screen: '~/app',
      lines: [
        { kind: 'command', text: 'cat dev.yaml' },
        { kind: 'key', text: 'mounts:' },
        { text: '  - host: .' },
        { text: '    guest: /work' },
        { text: '    readonly: false' },
        { kind: 'key', text: 'network:' },
        { text: '  allow:' },
        { text: '    - api.anthropic.com:443' },
        { kind: 'command', text: 'terra ./dev.yaml setup && terra' }
      ],
      link: { label: 'Start with the quickstart', href: '#start', arrow: '→' }
    },
    {
      title: 'A home for agents',
      text: 'Give a long-lived agent a box of its own. Its tools and files survive restarts, and systemd can keep it running. Optionally, reset changes to the root filesystem on every boot.',
      icon: 'M3 11 12 4l9 7M5 9.5V20h14V9.5M10 20v-6h4v6',
      screen: 'agent',
      lines: [
        { kind: 'command', text: 'terra ./agent.yaml setup' },
        { kind: 'output', text: 'terra: agent (~/agents) is ready - `terra agent` boots it' },
        { kind: 'command', text: 'terra agent', note: '# the agent is the workload' },
        { text: '', note: '# Ctrl-\\ detaches; the box keeps running' },
        { kind: 'command', text: 'terra agent stop', note: '# its files stay' },
        { kind: 'command', text: 'terra agent', note: '# back where it left off' }
      ],
      link: { label: 'Set one up', href: resolve('docs/usage/#a-terrarium-for-agents'), arrow: '→' }
    },
    {
      title: 'Nothing until you allow it',
      text: 'A new box sees no host files and reaches no network. You name the folders, hosts and ports it gets. Network denials appear in the log.',
      icon: 'M5 11h14v10H5ZM8 11V7a4 4 0 0 1 8 0v4M12 15v2',
      screen: 'network',
      lines: [
        { kind: 'key', text: 'network:' },
        { text: '  allow:' },
        { text: '    - registry.npmjs.org:443' },
        { kind: 'command', text: 'terra exec -- wget -q --spider https://example.com' },
        { kind: 'output', text: "wget: bad address 'example.com'" },
        { kind: 'command', text: 'terra logs | grep egress' },
        { kind: 'denied', text: '… egress: blocked example.com - policy denied name lookup' }
      ],
      link: { label: 'Write network rules', href: resolve('docs/recipe/#network'), arrow: '→' }
    },
    {
      title: 'A real VM, devices in Wasm',
      text: 'Each box runs its own Linux kernel under hardware virtualization. Every device runs in its own WebAssembly sandbox, inside an OS-sandboxed process.',
      icon: 'M12 3 2 8l10 5 10-5ZM2 12.5l10 5 10-5M2 17l10 5 10-5',
      screen: 'isolation',
      lines: [
        { text: 'your workload' },
        { text: '└─ guest Linux kernel', note: '   hardware VM' },
        { text: '   └─ virtio devices', note: '   one Wasm store each' },
        { text: '      └─ thin host API', note: '  scoped imports' },
        { text: '         └─ VM worker', note: '   OS sandbox' },
        { text: 'network → broker', note: '           its own sandbox' }
      ],
      link: { label: 'See every layer', href: '#isolation-heading', arrow: '↓' }
    },
    {
      title: 'One binary, every platform',
      text: 'The kernel, Alpine base and VM parts ship inside terra. No daemon or OCI images to manage. Use the same recipe on Linux, macOS on Apple Silicon and Windows.',
      icon: 'M12 2 3 7v10l9 5 9-5V7ZM3 7l9 5 9-5M12 12v10',
      screen: 'install',
      lines: [
        { kind: 'command', text: 'curl -fsSL …/install.sh | sh' },
        { kind: 'command', text: 'terra ./dev.yaml setup' },
        { text: '' },
        { kind: 'key', text: 'Linux  ', note: ' KVM                    x86_64 · ARM64' },
        { kind: 'key', text: 'macOS  ', note: ' Hypervisor.framework   Apple Silicon' },
        { kind: 'key', text: 'Windows', note: ' WHP                    x86_64 · ARM64' }
      ],
      link: { label: 'Install Terra', href: '#start', arrow: '→' }
    },
    {
      title: 'Built online, run offline',
      text: 'Set up a box where there is network and export it to one file. Import it on an air-gapped machine: it boots with its tools installed and downloads nothing.',
      icon: 'M12 3v11M7 9.5l5 5 5-5M4 15v5h16v-5',
      screen: 'air gap',
      lines: [
        { kind: 'command', prompt: 'online $', text: 'terra dev storage export dev.terra' },
        { kind: 'output', text: 'terra: wrote dev.terra' },
        { text: '', note: '# carry dev.terra and terra across' },
        { kind: 'command', prompt: 'offline $', text: 'terra dev storage import dev.terra' },
        { kind: 'output', text: 'terra: imported into dev (~/app) - `terra dev` boots it' },
        { kind: 'command', prompt: 'offline $', text: 'terra dev' }
      ],
      link: { label: 'Carry one over', href: resolve('docs/usage/#air-gapped-machines'), arrow: '→' }
    }
  ];

  const rotation = new Rotation(benefits.length, CYCLE_MS, TAPPED_DWELL_MS);
  const benefit = $derived(benefits[rotation.active]);
  const descriptionFadeMs = $derived(rotation.isAnimated ? DESCRIPTION_FADE_MS : 0);
</script>

<section {@attach rotation.observeVisibility} {...rotation.holdWhileEngaged} class="benefits-section" class:is-animated={rotation.isAnimated} aria-label="Why Terrarium">
  <div class="benefits-intro">{@render children()}</div>
  <div class="benefit-showcase">
    <ol class="benefit-list">
      {#each benefits as item, index (item.title)}
        <li>
          <button
            type="button"
            class:active={rotation.active === index}
            aria-pressed={rotation.active === index}
            onclick={() => rotation.select(index)}
            onfocus={() => (rotation.active = index)}
            onpointerenter={(event) => event.pointerType === 'mouse' && (rotation.active = index)}
          >
            <svg class="benefit-icon" viewBox="0 0 24 24" aria-hidden="true"><path d={item.icon} /></svg>
            <span>{item.title}<span class="sr-only">: {item.text}</span></span>
            {#if rotation.isCycling && rotation.active === index}{#key rotation.selectionCount}<span class="layer-progress" style:animation-duration="{rotation.dwellMs}ms"></span>{/key}{/if}
          </button>
        </li>
      {/each}
    </ol>
    <div class="benefit-detail">
      <div class="benefit-screen" aria-hidden="true">
        <div class="screen-bar"><span class="screen-dots"><i></i><i></i><i></i></span><span>{benefit.screen}</span></div>
        <pre><code>{#key rotation.active}{#each benefit.lines as line, index}<span class="screen-line" data-kind={line.kind} style:--i={index}>{#if line.kind === 'command'}<span class="screen-prompt">{line.prompt ?? '$'} </span>{/if}{line.text}{#if line.note}<span class="screen-note">{line.kind === 'command' ? '  ' : ''}{line.note}</span>{/if}</span>{/each}{/key}</code></pre>
      </div>
      <div class="benefit-description">
        {#key rotation.active}
          <p class="benefit-text" in:fade={{ delay: descriptionFadeMs, duration: descriptionFadeMs }} out:fade={{ duration: descriptionFadeMs }}>{benefit.text} <a href={benefit.link.href}>{benefit.link.label} <span aria-hidden="true">{benefit.link.arrow}</span></a></p>
        {/key}
      </div>
    </div>
  </div>
  <div class="showcase-caption">
    <span>Illustrative recipes & CLI sessions</span>
    {#if rotation.canAnimate}
      <button class="iso-motion-toggle" type="button" onclick={() => (rotation.isPaused = !rotation.isPaused)}>{rotation.isPaused ? 'Resume examples' : 'Pause examples'}</button>
    {/if}
  </div>
  <noscript>
    <div class="benefits-static">
      {#each benefits.slice(1) as item}
        <div><h3>{item.title}</h3><p>{item.text} <a href={item.link.href}>{item.link.label} →</a></p></div>
      {/each}
    </div>
  </noscript>
</section>
