import { error } from '@sveltejs/kit';
import { findGuide, guideEntries, guideList } from '$lib/server/guides';

export const entries = () => guideEntries;

export const load = ({ params }) => {
	const currentGuide = findGuide(params.slug);
	if (!currentGuide) error(404, 'Guide not found');

	return { guide: currentGuide, guides: guideList };
};
