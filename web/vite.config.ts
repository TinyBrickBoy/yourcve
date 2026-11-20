import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const backend = 'http://localhost:8080';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// Single page app: the Go binary embeds web/build and serves index.html
			// for every unknown path.
			adapter: adapter({
				pages: 'build',
				assets: 'build',
				fallback: 'index.html',
				strict: true
			}),
			// Absolute asset URLs so the fallback page works on nested paths like /stacks/12
			paths: { relative: false }
		})
	],
	server: {
		proxy: {
			'/v1': { target: backend, changeOrigin: false },
			'/mcp': { target: backend, changeOrigin: false },
			'/healthz': { target: backend, changeOrigin: false }
		}
	}
});
