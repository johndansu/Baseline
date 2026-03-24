import { defineConfig } from 'vite';
import { resolve } from 'path';
import { mkdirSync, copyFileSync } from 'fs';

export default defineConfig(({ mode }) => {
  const isProduction = mode === 'production' || process.env.NODE_ENV === 'production';

  return {
    root: 'public',
    base: '/',
    build: {
      outDir: '../dist',
      emptyOutDir: true,
      assetsDir: 'assets',
      sourcemap: !isProduction,
      minify: 'terser',
      target: 'es2015',
      rollupOptions: {
        input: {
          main: resolve(__dirname, 'public/index.html'),
          dashboard: resolve(__dirname, 'public/dashboard.html'),
          signin: resolve(__dirname, 'public/signin.html'),
          signup: resolve(__dirname, 'public/signup.html'),
          cliGuide: resolve(__dirname, 'public/cli-guide.html'),
          cliLogin: resolve(__dirname, 'public/cli-login.html')
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
          drop_console: isProduction,
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
              NODE_ENV: '${isProduction ? 'production' : (process.env.NODE_ENV || 'development')}',
              SUPABASE_URL: '${process.env.SUPABASE_URL || ''}',
              SUPABASE_ANON_KEY: '${process.env.SUPABASE_ANON_KEY || ''}',
              SUPABASE_AUTH_REDIRECT_TO: '${process.env.SUPABASE_AUTH_REDIRECT_TO || ''}',
              BASELINE_API_ORIGIN: '${process.env.BASELINE_API_ORIGIN || ''}',
              WS_URL: '${process.env.WS_URL || 'ws://localhost:8001'}'
            };
          </script>
          </head>`
          );
        }
      },
      {
        name: 'copy-runtime-config-scripts',
        closeBundle() {
          const distJSDir = resolve(__dirname, 'dist/js');
          mkdirSync(distJSDir, { recursive: true });
          copyFileSync(resolve(__dirname, 'public/js/runtime-config.js'), resolve(distJSDir, 'runtime-config.js'));
          copyFileSync(resolve(__dirname, 'public/js/supabase-config.js'), resolve(distJSDir, 'supabase-config.js'));
        }
      }
    ],
    optimizeDeps: {
      include: ['chart.js', '@supabase/supabase-js', 'socket.io-client']
    }
  };
});
