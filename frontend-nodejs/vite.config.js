import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: 'public',
  base: '/',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: process.env.NODE_ENV !== 'production',
    minify: 'terser',
    target: 'es2015',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'public/index.html'),
        dashboard: resolve(__dirname, 'public/dashboard.html'),
        signin: resolve(__dirname, 'public/signin.html'),
        signup: resolve(__dirname, 'public/signup.html')
      },
      output: {
        manualChunks: {
          vendor: ['chart.js', 'socket.io-client'],
          auth: ['@supabase/supabase-js']
        }
      }
    },
    terserOptions: {
      compress: {
        drop_console: process.env.NODE_ENV === 'production',
        drop_debugger: true
      }
    },
    chunkSizeWarningLimit: 1000
  },
  server: {
    port: 3000,
    host: true,
    cors: true
  },
  preview: {
    port: 3001,
    host: true
  },
  plugins: [
    {
      name: 'html-injection',
      transformIndexHtml(html) {
        // Inject environment variables
        return html.replace(
          '</head>',
          `
          <script>
            window.ENV = {
              NODE_ENV: '${process.env.NODE_ENV || 'development'}',
              SUPABASE_URL: '${process.env.SUPABASE_URL || ''}',
              WS_URL: '${process.env.WS_URL || 'ws://localhost:8001'}'
            };
          </script>
          </head>`
        );
      }
    }
  ],
  optimizeDeps: {
    include: ['chart.js', '@supabase/supabase-js', 'socket.io-client']
  }
});
