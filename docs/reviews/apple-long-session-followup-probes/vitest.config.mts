import { defineConfig } from '../../../ui/node_modules/vitest/dist/config.js';
import { fileURLToPath } from 'node:url';
const path = (relative: string): string => fileURLToPath(new URL(relative, import.meta.url));
export default defineConfig({
  root: path('../../../ui/'),
  resolve: { alias: [
    { find: /^vitest$/, replacement: path('../../../ui/node_modules/vitest/dist/index.js') },
    { find: /^react$/, replacement: path('../../../ui/node_modules/react/index.js') },
    { find: /^react-dom\/client$/, replacement: path('../../../ui/node_modules/react-dom/client.js') },
  ] },
  test: { environment: 'node', include: [path('./*.test.ts')] },
});
