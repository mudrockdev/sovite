// Formatting for the UI, in the current locale.

import { getLocale } from '#lib/paraglide/runtime.js';

/** Bytes as "512 B", "1.5 KiB", "3.2 MiB". */
export function bytes(value: number): string {
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	let size = value;
	let unit = 0;

	while (size >= 1024 && unit < units.length - 1) {
		size /= 1024;
		unit++;
	}

	const digits = unit === 0 || size >= 10 ? 0 : 1;
	return `${size.toLocaleString(getLocale(), { maximumFractionDigits: digits })} ${units[unit]}`;
}

/** Seconds as "3d 4h", "2h 5m", "4m 10s". */
export function duration(seconds: number): string {
	const days = Math.floor(seconds / 86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);

	if (days > 0) return `${days}d ${hours}h`;
	if (hours > 0) return `${hours}h ${minutes}m`;
	return `${minutes}m ${Math.floor(seconds % 60)}s`;
}

/** An ISO 8601 time as a local date and time, or "" for none. */
export function dateTime(value: string | null | undefined): string {
	if (!value) return '';
	const date = new Date(value);
	if (Number.isNaN(date.getTime())) return value;
	return date.toLocaleString(getLocale(), { dateStyle: 'medium', timeStyle: 'medium' });
}
