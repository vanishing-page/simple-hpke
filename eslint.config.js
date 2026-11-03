import neostandard from 'newneostandard'
import tseslint from 'typescript-eslint'

// Local rule: forbid spaces around `|` and `&` in TypeScript union and
// intersection types, so `A|B` is required over `A | B`. Only flags
// operators whose operands share a line, leaving multiline unions (one
// member per line) untouched.
const localPlugin = {
    rules: {
        'union-spacing': {
            meta: {
                type: 'layout',
                fixable: 'whitespace',
                schema: [],
                messages: {
                    before: "Unexpected space before '{{op}}' in type.",
                    after: "Unexpected space after '{{op}}' in type."
                }
            },
            create (context) {
                const sc = context.sourceCode
                const check = (node) => {
                    for (const member of node.types) {
                        const op = sc.getTokenBefore(member)
                        if (!op) continue
                        if (op.value !== '|' && op.value !== '&') continue
                        const prev = sc.getTokenBefore(op)
                        const next = sc.getTokenAfter(op)
                        // Only enforce when the operator sits inline
                        // between two members on a single line; leave
                        // multiline unions (leading/trailing pipe) be.
                        const inline = prev && next &&
                            prev.loc.end.line === op.loc.start.line &&
                            op.loc.end.line === next.loc.start.line
                        if (!inline) continue
                        if (prev.range[1] !== op.range[0]) {
                            context.report({
                                node: op,
                                messageId: 'before',
                                data: { op: op.value },
                                fix: (fixer) => fixer.removeRange(
                                    [prev.range[1], op.range[0]]
                                )
                            })
                        }
                        if (op.range[1] !== next.range[0]) {
                            context.report({
                                node: op,
                                messageId: 'after',
                                data: { op: op.value },
                                fix: (fixer) => fixer.removeRange(
                                    [op.range[1], next.range[0]]
                                )
                            })
                        }
                    }
                }
                return {
                    TSUnionType: check,
                    TSIntersectionType: check
                }
            }
        },

        // Local rule: require exactly one space after the colon and none
        // before it in object-literal (and object-pattern) properties, so
        // `{ a: 1 }` is required over `{ a:1 }`. Only visits `Property`
        // nodes, never `TSPropertySignature`, so type annotations and
        // type-literal members keep their no-space style (owned by
        // `@stylistic/type-annotation-spacing`). Enforced inline only,
        // leaving any multiline `key:\n  value` untouched.
        'object-colon-spacing': {
            meta: {
                type: 'layout',
                fixable: 'whitespace',
                schema: [],
                messages: {
                    before: "Unexpected space before ':' in object property.",
                    missing: "Expected a space after ':' in object property.",
                    extra: "Expected one space after ':' in object property."
                }
            },
            create (context) {
                const sc = context.sourceCode
                const isColon = (t) =>
                    t.type === 'Punctuator' && t.value === ':'
                return {
                    Property (node) {
                        if (node.shorthand || node.method) return
                        if (node.kind !== 'init') return
                        const colon = sc.getTokenAfter(node.key, isColon)
                        if (!colon) return
                        const prev = sc.getTokenBefore(colon)
                        const next = sc.getTokenAfter(colon)
                        if (!prev || !next) return
                        // No space before the colon (inline only).
                        if (prev.loc.end.line === colon.loc.start.line &&
                            prev.range[1] !== colon.range[0]) {
                            context.report({
                                node: colon,
                                messageId: 'before',
                                fix: (fixer) => fixer.removeRange(
                                    [prev.range[1], colon.range[0]]
                                )
                            })
                        }
                        // Exactly one space after the colon (inline only).
                        if (colon.loc.end.line !== next.loc.start.line) return
                        const gap = next.range[0] - colon.range[1]
                        if (gap === 0) {
                            context.report({
                                node: colon,
                                messageId: 'missing',
                                fix: (fixer) => fixer.insertTextAfter(
                                    colon, ' '
                                )
                            })
                        } else if (gap > 1) {
                            context.report({
                                node: colon,
                                messageId: 'extra',
                                fix: (fixer) => fixer.replaceTextRange(
                                    [colon.range[1], next.range[0]], ' '
                                )
                            })
                        }
                    }
                }
            }
        }
    }
}

export default tseslint.config(
    {
        ignores: [
            'lib.es5.d.ts',
            'dist/**',
            'public/**',
            'test/*.js',
            'api-docs/*'
        ]
    },

    // JavaScript Standard Style, TypeScript-aware (flat-config successor
    // to `eslint-config-standard`). Stylistic rules live under the
    // `@stylistic/` namespace.
    ...neostandard({ ts: true }),

    // Standard Style overrides, applied to every file.
    {
        rules: {
            '@stylistic/operator-linebreak': 'off',
            '@stylistic/multiline-ternary': 'off',
            '@stylistic/no-multiple-empty-lines': ['error', {
                max: 1,
                maxEOF: 1
            }],
            '@stylistic/indent': ['error', 4, {
                SwitchCase: 1,
                ignoredNodes: ['TemplateLiteral *']
            }],
            '@stylistic/comma-dangle': 'off',
            '@stylistic/no-multi-spaces': ['error', {
                ignoreEOLComments: true
            }]
        }
    },

    // `@typescript-eslint/recommended` plus our TypeScript overrides,
    // scoped to TypeScript files where the parser and plugin are active.
    {
        files: ['**/*.ts', '**/*.tsx'],
        extends: [tseslint.configs.recommended],
        plugins: { local: localPlugin },
        rules: {
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-unused-vars': ['error', {
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_',
                caughtErrorsIgnorePattern: '^_'
            }],
            '@typescript-eslint/consistent-type-imports': ['error', {
                prefer: 'type-imports'
            }],
            // No space around the colon in type annotations
            // (`const x:T`, params, returns). `=>` in function types
            // stays spaced via `@stylistic/arrow-spacing` (on by
            // default from neostandard), not the deprecated
            // `overrides.arrow` here.
            '@stylistic/type-annotation-spacing': ['error', {
                before: false,
                after: false
            }],
            // Object literals require a space after the colon (`{ a: 1 }`),
            // owned by `local/object-colon-spacing`. Type-literal members
            // keep no space (`classes?:string[]`) via
            // `type-annotation-spacing` above, so `key-spacing` — which
            // conflates the two — stays off here.
            '@stylistic/key-spacing': 'off',
            'local/object-colon-spacing': 'error',
            // Let `local/union-spacing` own union/intersection spacing.
            '@stylistic/space-infix-ops': ['error', { ignoreTypes: true }],
            'local/union-spacing': 'error'
        }
    }
)
