import { defineConfig } from 'vite';

// Relative asset paths keep the generated site deployable at either a custom
// domain or the repository sub-path used by GitHub Pages.
export default defineConfig({
  base: './',
});
