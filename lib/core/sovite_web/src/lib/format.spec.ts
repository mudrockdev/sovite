import { describe, expect, it } from 'bun:test';
import { bytes, dateTime, duration } from './format.ts';

describe('bytes', () => {
	it('picks a unit', () => {
		expect(bytes(512)).toBe('512 B');
		expect(bytes(1536)).toBe('1.5 KiB');
		expect(bytes(20 * 1024 * 1024)).toBe('20 MiB');
	});
});

describe('duration', () => {
	it('shows the two largest units', () => {
		expect(duration(42)).toBe('0m 42s');
		expect(duration(3 * 3600 + 5 * 60)).toBe('3h 5m');
		expect(duration(2 * 86400 + 7200)).toBe('2d 2h');
	});
});

describe('dateTime', () => {
	it('formats times and leaves bad ones alone', () => {
		expect(dateTime(null)).toBe('');
		expect(dateTime('soon')).toBe('soon');
		expect(dateTime('2026-10-04T12:00:00Z')).toContain('2026');
	});
});
