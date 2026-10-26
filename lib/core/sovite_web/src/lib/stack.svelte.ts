// The parts of the stack the server runs, from the admin API's status,
// so that the navigation shows only their pages. Unknown (null) until
// the first status arrives: then every page is shown.

import type { Part, Stack } from './types.ts';

class StackState {
	parts = $state<Stack | null>(null);

	/** Whether `part` is on, or not known yet. */
	on(part: Part): boolean {
		return this.parts === null || this.parts[part];
	}
}

export const stack = new StackState();
