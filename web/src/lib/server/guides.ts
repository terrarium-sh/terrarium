import { base } from '$app/paths';
import { marked, Renderer } from 'marked';

const repository = 'https://github.com/terrarium-sh/terrarium/blob/main/';
const guideFiles = ['usage', 'recipe', 'manifest', 'security'] as const;
const sources = import.meta.glob<string>('../../../../docs/{usage,recipe,manifest,security}.md', {
	eager: true,
	import: 'default',
	query: '?raw'
});

type GuideSlug = (typeof guideFiles)[number];

export type Guide = {
	slug: GuideSlug;
	title: string;
	description: string;
	html: string;
};

const readGuideSource = (slug: GuideSlug) => sources[`../../../../docs/${slug}.md`];

const extractTitle = (markdown: string) => markdown.match(/^# (.+)$/m)?.[1] ?? 'Terra guide';

const extractDescription = (markdown: string) =>
	markdown
		.split('\n')
		.find((line) => line && !line.startsWith('#'))
		?.replace(/`/g, '') ?? '';

const rewriteLink = (href: string) => {
	if (href.startsWith('#') || /^(?:[a-z]+:|\/)/i.test(href)) return href;

	const [path, anchor = ''] = href.split('#', 2);
	const slug = path.replace(/\.md$/, '') as GuideSlug;
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

const addHeadingIds = (html: string) => {
	const ids = new Map<string, number>();
	return html.replace(/<h([1-6])>(.*?)<\/h\1>/g, (_, level, content) => {
		const stem = stripTags(content)
			.toLowerCase()
			.replace(/[^\w -]/g, '')
			.trim()
			.replace(/\s+/g, '-') || 'section';
		const count = ids.get(stem) ?? 0;
		ids.set(stem, count + 1);
		return `<h${level} id="${stem}${count ? `-${count}` : ''}">${content}</h${level}>`;
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

const renderGuide = (markdown: string) =>
	addHeadingIds(
		marked.parse(markdown, {
			async: false,
			renderer,
			walkTokens(token) {
				if (token.type === 'link') token.href = rewriteLink(token.href);
			}
		})
	);

const readGuide = (slug: GuideSlug): Guide => {
	const markdown = readGuideSource(slug);
	return { slug, title: extractTitle(markdown), description: extractDescription(markdown), html: renderGuide(markdown) };
};

export const guides = guideFiles.map(readGuide);

export const guideEntries = guideFiles.map((slug) => ({ slug }));

export const findGuide = (slug: string) => guides.find((item) => item.slug === slug);

export const guideList = guides.map(({ slug, title }) => ({ slug, title }));
