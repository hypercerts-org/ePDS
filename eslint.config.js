import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import prettier from 'eslint-config-prettier'

export default tseslint.config(
  // Global ignores
  {
    ignores: [
      '**/dist/',
      'node_modules/',
      'tmp/',
      'vitest.config.ts',
      'eslint.config.js',
    ],
  },

  // Base JS rules
  eslint.configs.recommended,

  // TypeScript strict rules (type-checked)
  ...tseslint.configs.strictTypeChecked,

  // TypeScript-specific overrides
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Enforce `import type` for type-only imports (AGENTS.md convention)
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'separate-type-imports' },
      ],

      // Allow unused vars prefixed with _ (common pattern for intentional omission)
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],

      // These are too noisy for template-literal HTML and better-auth interop
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',

      // Allow non-null assertions — used sparingly with DOM getElementById etc.
      '@typescript-eslint/no-non-null-assertion': 'off',

      // Relax for Express handler patterns (void-returning async callbacks)
      '@typescript-eslint/no-misused-promises': [
        'error',
        { checksVoidReturn: { arguments: false } },
      ],

      // No default exports (AGENTS.md convention)
      'no-restricted-syntax': [
        'error',
        {
          selector: 'ExportDefaultDeclaration',
          message: 'Use named exports instead of default exports.',
        },
      ],
    },
  },

  // Disable formatting rules that conflict with Prettier
  prettier,
)
