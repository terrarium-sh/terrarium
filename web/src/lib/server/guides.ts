import { base } from '$app/paths';
import { marked, Renderer } from 'marked';

const repository = 'https://github.com/terrarium-sh/terrarium/blob/main/';
const guideFiles = ['usage', 'recipe', 'manifest', 'security', 'sandboxing', 'sandbox-policy'] as const;
/** The sandboxing guide's per-platform documents, shown as switchable sections of its page. */
const sandboxPlatforms = [
	{ platform: 'linux', label: 'Linux' },
	{ platform: 'macos', label: 'macOS' },
	{ platform: 'windows', label: 'Windows' }
] as const;
const sources = import.meta.glob<string>(
	'../../../../docs/{usage,recipe,manifest,security,sandboxing,sandbox-policy,sandboxing-linux,sandboxing-macos,sandboxing-windows}.md',
	{ eager: true, import: 'default', query: '?raw' }
);

type GuideSlug = (typeof guideFiles)[number];
export type SandboxPlatform = (typeof sandboxPlatforms)[number]['platform'];

export type PlatformSection = {
	platform: SandboxPlatform;
	label: string;
	html: string;
};

export type Guide = {
	slug: GuideSlug;
	title: string;
	description: string;
	html: string;
	platforms: PlatformSection[];
};

const readSource = (name: string) => sources[`../../../../docs/${name}.md`];

const extractTitle = (markdown: string) => markdown.match(/^# (.+)$/m)?.[1] ?? 'Terra guide';

const MAX_DESCRIPTION_LENGTH = 160;

const extractDescription = (markdown: string) => {
	const paragraph = (markdown.split(/\n\s*\n/).find((block) => block && !block.startsWith('#')) ?? '')
		.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/`/g, '')
		.replace(/\s+/g, ' ')
		.trim();
	if (paragraph.length <= MAX_DESCRIPTION_LENGTH) return paragraph;
	const clipped = paragraph.slice(0, MAX_DESCRIPTION_LENGTH);
	const sentenceEnd = clipped.lastIndexOf('. ');
	return sentenceEnd > 0 ? clipped.slice(0, sentenceEnd + 1) : `${clipped.slice(0, clipped.lastIndexOf(' '))}…`;
};

const rewriteLink = (href: string) => {
	if (href.startsWith('#') || /^(?:[a-z]+:|\/)/i.test(href)) return href;

	const [path, anchor = ''] = href.split('#', 2);
	const name = path.replace(/\.md$/, '');
	const platform = sandboxPlatforms.find((item) => name === `sandboxing-${item.platform}`)?.platform;
	if (platform) return `${base}/docs/sandboxing/#${platform}${anchor && `-${anchor}`}`;
	const slug = name as GuideSlug;
	if (guideFiles.includes(slug)) return `${base}/docs/${slug}/${anchor && `#${anchor}`}`;

	return `${new URL(path, `${repository}docs/`)}${anchor && `#${anchor}`}`;
};

const stripTags = (html: string) => {
	let text = html;
	let previous = '';
	while (previous !== text) {
		previous = text;
		text = text.replace(/<[^>]+>/g, '');
	}
	return text;
};

/** `prefix` keeps ids unique when several documents share one page. */
const addHeadingIds = (html: string, prefix = '') => {
	const ids = new Map<string, number>();
	return html.replace(/<h([1-6])>(.*?)<\/h\1>/g, (_, level, content) => {
		const stem = stripTags(content)
			.toLowerCase()
			.replace(/[^\w -]/g, '')
			.trim()
			.replace(/\s+/g, '-') || 'section';
		const count = ids.get(stem) ?? 0;
		ids.set(stem, count + 1);
		return `<h${level} id="${prefix}${stem}${count ? `-${count}` : ''}">${content}</h${level}>`;
	});
};

const renderer = new Renderer();
const renderLink = renderer.link;
renderer.link = function (token) {
	const html = renderLink.call(this, token);
	return /^(?:https?:)?\/\//i.test(token.href)
		? html.replace('<a ', '<a target="_blank" rel="noopener noreferrer" ')
		: html;
};

const renderGuide = (markdown: string, idPrefix = '') =>
	addHeadingIds(
		marked.parse(markdown, {
			async: false,
			renderer,
			walkTokens(token) {
				if (token.type === 'link') token.href = rewriteLink(token.href);
			}
		}),
		idPrefix
	);

/** Moves every heading one level down, so a section's title sits under the page's own. */
const demoteHeadings = (html: string) =>
	html.replace(/<(\/?)h([1-5])(?=[\s>])/g, (_, slash, level) => `<${slash}h${Number(level) + 1}`);

const readPlatformSections = (slug: GuideSlug): PlatformSection[] =>
	slug === 'sandboxing'
		? sandboxPlatforms.map(({ platform, label }) => ({
				platform,
				label,
				html: demoteHeadings(renderGuide(readSource(`sandboxing-${platform}`), `${platform}-`))
			}))
		: [];

const readGuide = (slug: GuideSlug): Guide => {
	const markdown = readSource(slug);
	return {
		slug,
		title: extractTitle(markdown),
		description: extractDescription(markdown),
		html: renderGuide(markdown),
		platforms: readPlatformSections(slug)
	};
};

export const guides = guideFiles.map(readGuide);

export const guideEntries = guideFiles.map((slug) => ({ slug }));

export const findGuide = (slug: string) => guides.find((item) => item.slug === slug);

export const guideList = guides.map(({ slug, title }) => ({ slug, title }));
