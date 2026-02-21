// eslint.config.js

// 🧱 Core ESLint rules
import js from '@eslint/js'

// 🌐 Predefined global variables (like `window`, `document`, etc.)
import globals from 'globals'

// ⚛️ React-specific hooks rules
import reactHooks from 'eslint-plugin-react-hooks'

// 🔄 React Fast Refresh for Vite/Next.js HMR safety
import reactRefresh from 'eslint-plugin-react-refresh'

export default [
  // ❌ Ignore build output
  { ignores: ['dist'] },

  {
    // 🎯 Apply to all JS and JSX files
    files: ['**/*.{js,jsx}'],

    languageOptions: {
      ecmaVersion: 2020, // or 'latest'
      globals: globals.browser,
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },

    // 🔌 Plugins must be imported explicitly
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },

    rules: {
      // ✅ Start with recommended rules
      ...js.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,

      // ⚠️ Allow unused UPPERCASE_VARS (commonly constants)
      'no-unused-vars': ['error', { varsIgnorePattern: '^[A-Z_]' }],

      // ⚛️ Enforce safe export patterns for React Fast Refresh
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },
]
