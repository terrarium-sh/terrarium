<script lang="ts">
  import { base } from '$app/paths';
  import { onMount } from 'svelte';

  type Point = [number, number, number];
  type Box = { x: number; y: number; z: number; w: number; d: number; h: number };
  type WasmComponent = { name: string; icon: string; box: Box };
  type Anchor = 'above' | 'below' | 'left' | 'right';
  type Label = { text: string; at: Point; align: Anchor; layer: number };

  const CYCLE_MS = 4500;
  const TAPPED_DWELL_MS = 10000;
  const ISO_X = Math.cos(Math.PI / 6);

  const layers = [
    { title: 'Hardware VM', text: 'Your agent and tools run on a guest Linux kernel inside a hardware VM: KVM, Hypervisor.framework, or WHP.' },
    { title: 'Wasm components', text: 'Each blue case is a separate Wasm store, with isolated memory and scoped host imports for that component.' },
    { title: 'Thin host API', text: 'Each Wasm store gets only its scoped host imports: VM handles, guest memory, disks, shares, or broker operations.' },
    { title: 'OS sandbox', text: 'By default, the VM worker runs in an OS sandbox without host networking: Bubblewrap and seccomp, App Sandbox, or AppContainer.' },
    { title: 'Network broker', text: 'A separate process owns host sockets and enforces egress policy. Sandboxed on Linux and macOS.' }
  ];

  const icons = {
    folder: 'M3 7V5h6l2 2h10v12H3ZM3 10h18',
    disk: 'M3 4h18v7H3ZM3 13h18v7H3ZM6 7.5h2M6 16.5h2',
    memory: 'M2 6h20v10H2ZM6 16v3M10 16v3M14 16v3M18 16v3M6 10h4M14 10h4',
    vsock: 'M9 3h6v5H9ZM12 8v5M5 16v-3h14v3M2 16h6v5H2ZM16 16h6v5h-6Z',
    chip: 'M6 6h12v12H6ZM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4',
    bolt: 'M13 2 4 14h7l-1 8 9-12h-7Z',
    terminal: 'M3 4h18v16H3ZM7 9l3 3-3 3M12 15h5',
    code: 'M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16',
    funnel: 'M3 5h18l-7 8v6l-4 2v-8Z'
  };

  const ground: Box = { x: 0, y: 0, z: -14, w: 508, d: 376, h: 14 };
  const workerCage: Box = { x: 16, y: 16, z: 0, w: 352, d: 344, h: 120 };
  const hostApi: Box = { x: 28, y: 28, z: 0, w: 328, d: 320, h: 10 };
  const vm: Box = { x: 42, y: 42, z: 10, w: 190, d: 222, h: 92 };
  const guestKernel: Box = { x: 54, y: 54, z: 10, w: 166, d: 198, h: 8 };
  const workload: Box = { x: 82, y: 104, z: 18, w: 110, d: 76, h: 40 };
  const brokerCage: Box = { x: 398, y: 201, z: 0, w: 90, d: 90, h: 58 };
  const broker: Box = { x: 412, y: 215, z: 0, w: 62, d: 62, h: 32 };
  const WIRE_Z = 20;
  const globe: Point = [552, 246, WIRE_Z];
  const GLOBE_RADIUS = 15;
  const wasmBlock = (x: number, y: number, w: number): Box => ({ x, y, z: 10, w, d: 40, h: 20 });
  const devices: WasmComponent[] = [
    { name: 'Filesystem', icon: icons.folder, box: wasmBlock(272, 40, 72) },
    { name: 'Block', icon: icons.disk, box: wasmBlock(272, 102, 72) },
    { name: 'Memory', icon: icons.memory, box: wasmBlock(272, 164, 72) },
    { name: 'Vsock', icon: icons.vsock, box: wasmBlock(272, 226, 72) }
  ];
  const vmmBlock: WasmComponent = { name: 'VMM', icon: icons.chip, box: wasmBlock(56, 296, 76) };
  const interruptBlock: WasmComponent = { name: 'Interrupts', icon: icons.bolt, box: wasmBlock(146, 296, 76) };
  const agentBlock: WasmComponent = { name: 'Host agent', icon: icons.terminal, box: wasmBlock(272, 296, 72) };
  const machineBlocks = [vmmBlock, interruptBlock, agentBlock];

  const centerX = ({ x, w }: Box) => x + w / 2;
  const centerY = ({ y, d }: Box) => y + d / 2;
  const vsockBox = devices[3].box;
  const virtioWires: Point[][] = devices.map(({ box }) => [
    [vm.x + vm.w, centerY(box), WIRE_Z],
    [box.x, centerY(box), WIRE_Z]
  ]);
  const machineWires: Point[][] = [
    [[centerX(vmmBlock.box), vm.y + vm.d, WIRE_Z], [centerX(vmmBlock.box), vmmBlock.box.y, WIRE_Z]],
    [[centerX(interruptBlock.box), interruptBlock.box.y, WIRE_Z], [centerX(interruptBlock.box), vm.y + vm.d, WIRE_Z]],
    [[centerX(vsockBox), vsockBox.y + vsockBox.d, WIRE_Z], [centerX(vsockBox), agentBlock.box.y, WIRE_Z]]
  ];
  const brokerWires: Point[][] = [
    [[vsockBox.x + vsockBox.w, centerY(vsockBox), WIRE_Z], [broker.x, centerY(vsockBox), WIRE_Z]],
    [[broker.x + broker.w, centerY(broker), WIRE_Z], globe]
  ];

  const tags: Label[] = [
    { layer: 4, text: 'OS sandbox · VM worker', at: [16, 250, 120], align: 'above' },
    { layer: 1, text: 'Hardware VM', at: [42, 42, 102], align: 'above' },
    { layer: 2, text: 'Wasm components', at: [356, 28, 62], align: 'right' },
    { layer: 3, text: 'Thin host API', at: [356, 28, 0], align: 'right' },
    { layer: 5, text: 'Network broker', at: [488, 201, 58], align: 'right' }
  ];
  const wireLabels: Label[] = [
    { layer: 2, text: 'virtio', at: [252, 52, WIRE_Z], align: 'above' },
    { layer: 5, text: 'IPC', at: [378, centerY(vsockBox), WIRE_Z], align: 'below' },
    { layer: 5, text: 'TCP · UDP · DNS', at: [505, centerY(broker), WIRE_Z], align: 'above' },
    { layer: 5, text: 'Internet', at: [globe[0], globe[1], globe[2] - GLOBE_RADIUS * 1.6], align: 'below' }
  ];

  function project([x, y, z]: Point): [number, number] {
    return [(x - y) * ISO_X, (x + y) / 2 - z];
  }

  function toPoints(points: Point[]): string {
    return points.map((point) => project(point).map((value) => value.toFixed(1)).join(',')).join(' ');
  }

  const topFace = ({ x, y, z, w, d, h }: Box) => toPoints([[x, y, z + h], [x + w, y, z + h], [x + w, y + d, z + h], [x, y + d, z + h]]);
  const leftFace = ({ x, y, z, w, d, h }: Box) => toPoints([[x, y + d, z], [x + w, y + d, z], [x + w, y + d, z + h], [x, y + d, z + h]]);
  const rightFace = ({ x, y, z, w, d, h }: Box) => toPoints([[x + w, y, z], [x + w, y + d, z], [x + w, y + d, z + h], [x + w, y, z + h]]);
  const backWall = ({ x, y, z, w, h }: Box) => toPoints([[x, y, z], [x + w, y, z], [x + w, y, z + h], [x, y, z + h]]);
  const sideWall = ({ x, y, z, d, h }: Box) => toPoints([[x, y, z], [x, y + d, z], [x, y + d, z + h], [x, y, z + h]]);

  function matrixAt(point: Point, xAxis: [number, number], yAxis: [number, number]): string {
    const [originX, originY] = project(point);
    return `matrix(${xAxis[0]} ${xAxis[1]} ${yAxis[0]} ${yAxis[1]} ${originX.toFixed(1)} ${originY.toFixed(1)})`;
  }

  function iconOnTop({ x, y, z, w, d, h }: Box, size: number): string {
    const face = matrixAt([x, y, z + h], [ISO_X, 0.5], [-ISO_X, 0.5]);
    return `${face} translate(${w / 2 - size / 2} ${d / 2 - size / 2}) scale(${size / 24})`;
  }

  const textOnLeftFace = ({ x, y, z, d, h }: Box) => matrixAt([x, y + d, z + h], [ISO_X, 0.5], [0, 1]);

  function cagePaths({ x, y, z, w, d, h }: Box) {
    const corner = (i: number, j: number, k: number): Point => [x + i * w, y + j * d, z + k * h];
    const toPath = (edges: [Point, Point][]) =>
      edges.map(([from, to]) => `M${project(from).join(' ')}L${project(to).join(' ')}`).join('');
    return {
      back: toPath([
        [corner(0, 0, 0), corner(1, 0, 0)],
        [corner(0, 0, 0), corner(0, 1, 0)],
        [corner(0, 0, 0), corner(0, 0, 1)]
      ]),
      front: toPath([
        [corner(1, 0, 0), corner(1, 1, 0)],
        [corner(0, 1, 0), corner(1, 1, 0)],
        [corner(1, 0, 0), corner(1, 0, 1)],
        [corner(1, 1, 0), corner(1, 1, 1)],
        [corner(0, 1, 0), corner(0, 1, 1)],
        [corner(0, 0, 1), corner(1, 0, 1)],
        [corner(1, 0, 1), corner(1, 1, 1)],
        [corner(1, 1, 1), corner(0, 1, 1)],
        [corner(0, 1, 1), corner(0, 0, 1)]
      ])
    };
  }

  const workerCagePaths = cagePaths(workerCage);
  const brokerCagePaths = cagePaths(brokerCage);
  const [globeX, globeY] = project(globe);

  const VIEW_PADDING = { top: 40, right: 16, bottom: 12, left: 16 };
  const viewBox = (() => {
    const { x, y, z, w, d } = ground;
    const extremes: Point[] = [
      [x, y + d, z],
      [x + w, y, z],
      [x + w, y + d, z],
      [workerCage.x, workerCage.y, workerCage.z + workerCage.h],
      [globe[0], globe[1], globe[2] + GLOBE_RADIUS],
      [globe[0] + GLOBE_RADIUS * 2, globe[1] - GLOBE_RADIUS * 2, globe[2]]
    ];
    const projected = extremes.map(project);
    const left = Math.min(...projected.map(([px]) => px)) - VIEW_PADDING.left;
    const right = Math.max(...projected.map(([px]) => px)) + VIEW_PADDING.right;
    const top = Math.min(...projected.map(([, py]) => py)) - VIEW_PADDING.top;
    const bottom = Math.max(...projected.map(([, py]) => py)) + VIEW_PADDING.bottom;
    return { x: left, y: top, w: right - left, h: bottom - top };
  })();

  function placeLabel(point: Point): string {
    const [px, py] = project(point);
    return `left: ${(((px - viewBox.x) / viewBox.w) * 100).toFixed(2)}%; top: ${(((py - viewBox.y) / viewBox.h) * 100).toFixed(2)}%`;
  }

  let active = $state(1);
  let isHovered = $state(false);
  let isFocused = $state(false);
  let isVisible = $state(false);
  let canAnimate = $state(false);
  let isPaused = $state(false);
  let dwellMs = $state(CYCLE_MS);
  let selectionCount = $state(0);
  const isCycling = $derived(canAnimate && !isPaused && isVisible && !isHovered && !isFocused);

  onMount(() => {
    const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
    const updateMotionPreference = () => (canAnimate = !motionPreference.matches);
    updateMotionPreference();
    motionPreference.addEventListener('change', updateMotionPreference);
    return () => motionPreference.removeEventListener('change', updateMotionPreference);
  });

  function observeVisibility(node: HTMLElement) {
    const observer = new IntersectionObserver(([entry]) => (isVisible = entry.isIntersecting), { threshold: 0.3 });
    observer.observe(node);
    return () => observer.disconnect();
  }

  $effect(() => {
    if (!isCycling) return;
    void selectionCount;
    const timer = setTimeout(() => {
      active = (active % layers.length) + 1;
      dwellMs = CYCLE_MS;
    }, dwellMs);
    return () => clearTimeout(timer);
  });

  function selectLayer(layer: number) {
    active = layer;
    dwellMs = TAPPED_DWELL_MS;
    selectionCount += 1;
  }

  function findLayer(event: Event): number | undefined {
    const layer = (event.target as Element).closest<HTMLElement | SVGElement>('[data-layer]')?.dataset.layer;
    return layer ? Number(layer) : undefined;
  }

  function previewLayerUnderMouse(event: PointerEvent) {
    const layer = findLayer(event);
    if (event.pointerType === 'mouse' && layer) active = layer;
  }

  function selectTappedLayer(event: MouseEvent) {
    const layer = findLayer(event);
    if (layer) selectLayer(layer);
  }

  function setHovered(event: PointerEvent, hovered: boolean) {
    if (event.pointerType === 'mouse') isHovered = hovered;
  }
</script>

{#snippet solid(box: Box)}
  <polygon class="iso-face-left" points={leftFace(box)} />
  <polygon class="iso-face-right" points={rightFace(box)} />
  <polygon class="iso-face-top" points={topFace(box)} />
{/snippet}

{#snippet wasmComponent(component: WasmComponent, index: number)}
  {@const box = component.box}
  {@const enclosure: Box = { x: box.x - 5, y: box.y - 5, z: box.z, w: box.w + 10, d: box.d + 10, h: box.h + 16 }}
  <g class="iso-wasm-cell">
    <polygon class="iso-glass iso-glass-back" points={backWall(enclosure)} />
    <polygon class="iso-glass iso-glass-back" points={sideWall(enclosure)} />
    <g class="iso-block iso-lift" style:--i={index}>
      {@render solid(box)}
      <path class="iso-icon" transform={iconOnTop(box, 18)} d={component.icon} />
      <text class="iso-face-label" transform={textOnLeftFace(box)} x={box.w / 2} y={box.h / 2}>{component.name}</text>
    </g>
    <polygon class="iso-glass" points={leftFace(enclosure)} />
    <polygon class="iso-glass" points={rightFace(enclosure)} />
    <polygon class="iso-glass iso-glass-top" points={topFace(enclosure)} />
    <polygon class="iso-sheen" points={leftFace(enclosure)} />
  </g>
{/snippet}

{#snippet wires(paths: Point[][])}
  {#each paths as path, index (index)}
    <g class="iso-link" style:--i={index}>
      <polyline class="iso-wire" points={toPoints(path)} />
      <polyline class="iso-packet" points={toPoints(path)} pathLength="100" />
      {#each [path[0], path[path.length - 1]] as endpoint}
        {@const [cx, cy] = project(endpoint)}
        <circle class="iso-port" {cx} {cy} r="2" />
      {/each}
    </g>
  {/each}
{/snippet}

<section
  {@attach observeVisibility}
  class="isolation-section"
  class:is-animated={canAnimate && !isPaused && isVisible}
  aria-labelledby="isolation-heading"
  onfocusin={() => (isFocused = true)}
  onfocusout={(event) => (isFocused = event.currentTarget.contains(event.relatedTarget as Node | null))}
  onpointerenter={(event) => setHovered(event, true)}
  onpointerleave={(event) => setHovered(event, false)}
>
  <div class="isolation-heading">
    <p class="eyebrow">Isolation at every layer</p>
    <h2 id="isolation-heading">Your workload in a VM.<br />Its machinery in Wasm.</h2>
  </div>
  <div class="isolation-steps">
    <ol class="layer-key">
      {#each layers as layer, index (layer.title)}
        <li>
          <button
            type="button"
            class:active={active === index + 1}
            aria-pressed={active === index + 1}
            onclick={() => selectLayer(index + 1)}
            onfocus={() => (active = index + 1)}
            onpointerenter={(event) => event.pointerType === 'mouse' && (active = index + 1)}
          >
            <span class="layer-number">{index + 1}</span>
            <span>{layer.title}<span class="sr-only">: {layer.text}</span></span>
            {#if isCycling && active === index + 1}{#key selectionCount}<span class="layer-progress" style:animation-duration="{dwellMs}ms"></span>{/key}{/if}
          </button>
        </li>
      {/each}
    </ol>
    <p class="layer-description" aria-hidden="true">{#key active}<span>{layers[active - 1].text}</span>{/key}</p>
    <a href="{base}/docs/security/">Explore the security model <span aria-hidden="true">→</span></a>
  </div>
  <!-- The layer list buttons give keyboard users the same selection the figure gives pointers. -->
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
  <figure class="iso-figure" onpointerover={previewLayerUnderMouse} onclick={selectTappedLayer}>
    <div class="iso-scene">
      <svg
        class="iso"
        viewBox="{viewBox.x.toFixed(1)} {viewBox.y.toFixed(1)} {viewBox.w.toFixed(1)} {viewBox.h.toFixed(1)}"
        role="img"
        aria-label="Your workload runs in a hardware VM. Its devices, VMM, host agent, and x86 interrupt controller each run inside an individual Wasm enclosure on a thin host API inside an OS-sandboxed VM worker; network traffic leaves through a separate broker process."
      >
        <defs>
          <pattern id="iso-api-grid" width="24" height="24" patternUnits="userSpaceOnUse" patternTransform="matrix({ISO_X} 0.5 {-ISO_X} 0.5 0 0)">
            <path d="M24 0H0V24" fill="none" stroke="#568d88" stroke-width="0.6" />
          </pattern>
          <clipPath id="iso-vm-glass">
            <polygon points={leftFace(vm)} />
            <polygon points={rightFace(vm)} />
            <polygon points={topFace(vm)} />
          </clipPath>
          <linearGradient id="iso-reflection">
            <stop stop-color="#fff" stop-opacity="0" />
            <stop offset="0.5" stop-color="#fff" stop-opacity="0.45" />
            <stop offset="1" stop-color="#fff" stop-opacity="0" />
          </linearGradient>
          <linearGradient id="iso-workload-top" x1="0" y1="0" x2="1" y2="1">
            <stop stop-color="#51877a" />
            <stop offset="1" stop-color="#28594f" />
          </linearGradient>
          <linearGradient id="iso-component-top" x1="0" y1="0" x2="0.8" y2="1">
            <stop stop-color="#fffefb" />
            <stop offset="1" stop-color="#e6eee4" />
          </linearGradient>
          <linearGradient id="iso-api-top" x1="0" y1="0" x2="1" y2="1">
            <stop stop-color="#edf5f4" />
            <stop offset="1" stop-color="#c2dce0" />
          </linearGradient>
          <linearGradient id="iso-glass-sheen" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#fff" stop-opacity="0.55" />
            <stop offset="0.45" stop-color="#fff" stop-opacity="0" />
          </linearGradient>
        </defs>

        <g class="iso-ground">
          {@render solid(ground)}
          <text class="iso-ground-label" transform={textOnLeftFace(ground)} x={ground.w / 2} y={ground.h / 2}>HOST OS &amp; HYPERVISOR</text>
        </g>

        <g class="iso-layer" data-layer="4" class:is-active={active === 4} class:is-dimmed={active !== 4}>
          <polygon class="iso-process-glass" points={backWall(workerCage)} />
          <polygon class="iso-process-glass" points={sideWall(workerCage)} />
          <path class="iso-cage iso-cage-back" d={workerCagePaths.back} />
        </g>
        <g class="iso-layer" data-layer="5" class:is-active={active === 5} class:is-dimmed={active !== 5}>
          <path class="iso-cage iso-cage-back" d={brokerCagePaths.back} />
        </g>

        <g class="iso-layer iso-slab" data-layer="3" class:is-active={active === 3} class:is-dimmed={active !== 3}>
          {@render solid(hostApi)}
          <polygon class="iso-grid" points={topFace(hostApi)} />
        </g>

        <g class="iso-layer iso-vm" data-layer="1" class:is-active={active === 1} class:is-dimmed={active !== 1}>
          <polygon class="iso-glass iso-glass-back" points={backWall(vm)} />
          <polygon class="iso-glass iso-glass-back" points={sideWall(vm)} />
          <g class="iso-kernel">
            {@render solid(guestKernel)}
            <text class="iso-kernel-label" transform={matrixAt([guestKernel.x, guestKernel.y, guestKernel.z + guestKernel.h], [ISO_X, 0.5], [-ISO_X, 0.5])} x={guestKernel.w / 2} y={guestKernel.d - 16}>Guest Linux</text>
          </g>
          <g class="iso-workload iso-lift">
            {@render solid(workload)}
            <path class="iso-icon" transform={iconOnTop(workload, 22)} d={icons.code} />
            <text class="iso-face-label iso-workload-label" transform={textOnLeftFace(workload)} x={workload.w / 2} y={workload.h / 2}>Your workload</text>
          </g>
          <polygon class="iso-glass" points={leftFace(vm)} />
          <polygon class="iso-sheen" points={leftFace(vm)} />
          <polygon class="iso-glass" points={rightFace(vm)} />
          <polygon class="iso-glass iso-glass-top" points={topFace(vm)} />
          <g clip-path="url(#iso-vm-glass)" pointer-events="none">
            <path class="iso-reflection" d="M-90-100H-30L90 350H30Z" />
          </g>
        </g>

        <g class="iso-layer" data-layer="2" class:is-active={active === 2} class:is-dimmed={active !== 2}>
          {@render wires(virtioWires)}
          {@render wires(machineWires)}
          {#each devices as device, index (device.name)}
            {@render wasmComponent(device, index)}
          {/each}
          {#each machineBlocks as block, index (block.name)}
            {@render wasmComponent(block, devices.length + index)}
          {/each}
        </g>

        <g class="iso-layer" data-layer="5" class:is-active={active === 5} class:is-dimmed={active !== 5}>
          {@render wires(brokerWires)}
          <g class="iso-broker iso-lift">
            {@render solid(broker)}
            <path class="iso-icon" transform={iconOnTop(broker, 20)} d={icons.funnel} />
          </g>
          <g class="iso-globe" transform="translate({globeX.toFixed(1)} {globeY.toFixed(1)})">
            <circle class="iso-pulse" r={GLOBE_RADIUS + 4} />
            <circle r={GLOBE_RADIUS} />
            <ellipse rx={GLOBE_RADIUS * 0.42} ry={GLOBE_RADIUS} />
            <path d="M{-GLOBE_RADIUS} 0H{GLOBE_RADIUS}" />
          </g>
          <path class="iso-cage" d={brokerCagePaths.front} />
        </g>

        <g class="iso-layer" data-layer="4" class:is-active={active === 4} class:is-dimmed={active !== 4}>
          <polygon class="iso-process-glass" points={leftFace(workerCage)} />
          <polygon class="iso-process-glass" points={rightFace(workerCage)} />
          <polygon class="iso-process-glass" points={topFace(workerCage)} />
          <path class="iso-cage" d={workerCagePaths.front} />
        </g>
      </svg>

      {#each tags as tag (tag.text)}
        <span
          class="iso-tag"
          class:is-active={tag.layer === active}
          class:is-dimmed={tag.layer !== active}
          data-layer={tag.layer}
          data-align={tag.align}
          style={placeLabel(tag.at)}
        >
          <span class="layer-number">{tag.layer}</span><span class="iso-tag-text">{tag.text}</span>
        </span>
      {/each}
      {#each wireLabels as label (label.text)}
        <span class="iso-wire-label" class:is-active={label.layer === active} data-layer={label.layer} data-align={label.align} style={placeLabel(label.at)}>{label.text}</span>
      {/each}
    </div>
    <figcaption class="iso-caption">
      <span class="iso-boundary-key" aria-label="Isolation boundaries">
        <span class="iso-boundary-vm">Hardware VM</span>
        <span class="iso-boundary-wasm">One Wasm store per component</span>
        <span class="iso-boundary-process">OS sandbox</span>
      </span>
      <span>Interrupts: Wasm controller on x86 · native IRQ lines on ARM.</span>
      {#if canAnimate}
        <button class="iso-motion-toggle" type="button" onclick={() => (isPaused = !isPaused)}>{isPaused ? 'Resume motion' : 'Pause motion'}</button>
      {/if}
    </figcaption>
  </figure>
</section>
