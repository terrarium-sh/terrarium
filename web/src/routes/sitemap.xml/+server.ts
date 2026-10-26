import { resolve } from '$app/paths';
import { guideEntries } from '#lib/server/guides.ts';

export const prerender = true;

const paths = ['', 'commands/', 'skill.md', ...guideEntries.map(({ slug }) => `docs/${slug}/`)];

export const GET = ({ url }) => {
	const root = new URL(resolve('/'), url);
	return new Response(
		`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${paths
			.map((path) => `  <url><loc>${new URL(path, root)}</loc></url>`)
			.join('\n')}\n</urlset>\n`,
		{ headers: { 'Content-Type': 'application/xml' } }
	);
};
