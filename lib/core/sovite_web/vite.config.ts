import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { enhancedImages } from '@sveltejs/enhanced-img';
import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';

export default defineConfig({
	server: {
		proxy: {
			'/api': { target: 'http://127.0.0.1:9025', changeOrigin: false },
			'/metrics': { target: 'http://127.0.0.1:9025', changeOrigin: false }
		}
	},
	plugins: [
		enhancedImages(),
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// Message pages (/queue/ID) are not prerendered: the web server
			// serves 200.html for them, which loads with absolute paths.
			adapter: adapter({ fallback: '200.html' }),
			paths: { relative: false }
		}),
		paraglideVitePlugin({
			project: './project.inlang',
			outdir: './src/lib/paraglide',
			emitTsDeclarations: true,
			// The language picked in the UI, else the browser's.
			strategy: ['cookie', 'preferredLanguage', 'globalVariable', 'baseLocale']
		})
	]
});
