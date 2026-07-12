import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

export default [
  {
    // Type-only contract files require a TS parser/toolchain that is out of
    // scope for this JSX/Vite lint setup; esbuild strips their types at build.
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'playwright-report/**', '**/*.ts', '**/*.tsx'],
  },
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2021,
        ...globals.node,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    settings: {
      react: { version: 'detect' },
    },
    plugins: {
      react,
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...react.configs.recommended.rules,
      ...react.configs['jsx-runtime'].rules,
      ...reactHooks.configs.recommended.rules,
      // The new JSX transform makes React-in-scope unnecessary.
      'react/react-in-jsx-scope': 'off',
      'react/prop-types': 'off',
      // Legacy patterns present in the codebase — keep as warnings, not errors.
      'no-unused-vars': ['warn', { args: 'none', ignoreRestSiblings: true, varsIgnorePattern: '^_' }],
      'no-empty': ['warn', { allowEmptyCatch: true }],
      // ANSI escape stripping in log/timeline rendering uses control chars on purpose.
      'no-control-regex': 'off',
      'react/no-unescaped-entities': 'warn',
      'react/display-name': 'warn',
      // webkitdirectory / directory upload attributes are intentional.
      'react/no-unknown-property': ['warn', { ignore: ['directory'] }],
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      // react-hooks v7 ships several new, aggressive analyses (set-state-in-effect,
      // refs, immutability, purity, static-components, conditional-hook detection)
      // that flag long-standing patterns in this codebase. Surface them as
      // warnings so they guide refactors without blocking CI.
      'react-hooks/exhaustive-deps': 'warn',
      'react-hooks/rules-of-hooks': 'warn',
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/refs': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/static-components': 'warn',
    },
  },
  {
    // Test files and setup run under vitest / node with their own globals.
    files: ['**/*.test.{js,jsx}', '**/__tests__/**', 'src/test-setup.js', 'e2e/**', '*.config.js'],
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.vitest,
        vi: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        expect: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
      },
    },
  },
]
