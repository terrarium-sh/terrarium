import skill from '../../../../skills/terra-box/SKILL.md?raw';

export const prerender = true;

export const GET = () =>
	new Response(skill, { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
