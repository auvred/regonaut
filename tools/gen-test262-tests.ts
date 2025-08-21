import fs from 'node:fs/promises'
import path from 'node:path'
import assert from 'node:assert/strict'
import { load as yamlParse } from 'js-yaml'
import { parseSync, traverse } from '@babel/core'

const rootDir = path.join(import.meta.dirname, '..')
const testsDir = path.join(rootDir, 'test262', 'test')
const distDir = path.join(rootDir, 'test262-generated')

await fs.rm(distDir, { recursive: true, force: true })

const dirents = (
  await Promise.all([
    fs.readdir(path.join(testsDir, 'built-ins', 'RegExp'), {
      recursive: true,
      withFileTypes: true,
    }),
    fs.readdir(path.join(testsDir, 'language', 'literals', 'regexp'), {
      recursive: true,
      withFileTypes: true,
    }),
  ])
).flat()

const tests = await Promise.all(
  dirents
    .filter(dirent => dirent.isFile() && !dirent.name.includes('_FIXTURE'))
    .map(async dirent => {
      const filepath = path.join(dirent.parentPath, dirent.name)
      const source = await fs.readFile(filepath, 'utf8')
      const metadata = yamlParse(
        source.substring(source.indexOf('/*---') + 5, source.indexOf('---*/')),
      ) as {
        includes?: string[]
        negative?: {
          phase: 'parse' | 'resolution' | 'runtime'
          type: string
        }
      }

      return {
        source,
        // haven't tested on Windows
        name: path.relative(testsDir, filepath).replaceAll('\\', '/'),
        metadata,
      }
    }),
)

const generated = new Map<string, { pattern: string; flags: string }>()

for (const test of tests) {
  const name = `syntax-error/${test.name}`
  if (test.metadata.negative?.phase !== 'parse') {
    continue
  }
  const babelCannotParse = {
    'language/literals/regexp/S7.8.5_A1.2_T1.js': '*',
    'language/literals/regexp/S7.8.5_A1.2_T2.js': '\\',
    'language/literals/regexp/S7.8.5_A2.2_T1.js': 'a\\',
  }[test.name]
  if (babelCannotParse != null) {
    generated.set(name, { pattern: babelCannotParse, flags: '' })
    continue
  }
  // invalid ECMAScript source code
  if (
    [
      'language/literals/regexp/S7.8.5_A1.2_T4.js',
      'language/literals/regexp/S7.8.5_A2.2_T2.js',
      'language/literals/regexp/S7.8.5_A1.3_T1.js',
      'language/literals/regexp/S7.8.5_A1.3_T3.js',
      'language/literals/regexp/S7.8.5_A2.3_T1.js',
      'language/literals/regexp/S7.8.5_A2.3_T3.js',
      'language/literals/regexp/S7.8.5_A2.5_T1.js',
      'language/literals/regexp/S7.8.5_A2.5_T3.js',
      'language/literals/regexp/S7.8.5_A2.5_T5.js',
      'language/literals/regexp/S7.8.5_A1.2_T3.js',
      'language/literals/regexp/S7.8.5_A1.5_T1.js',
      'language/literals/regexp/S7.8.5_A1.5_T3.js',
      'language/literals/regexp/regexp-first-char-no-line-separator.js',
      'language/literals/regexp/regexp-first-char-no-paragraph-separator.js',
      'language/literals/regexp/regexp-source-char-no-line-separator.js',
      'language/literals/regexp/regexp-source-char-no-paragraph-separator.js',
    ].includes(test.name)
  ) {
    continue
  }

  try {
    const ast = parseSync(test.source, {
      parserOpts: {
        errorRecovery: true,
      },
    })
    assert.ok(ast)
    traverse(ast, {
      RegExpLiteral: path => {
        const { pattern, flags } = path.node
        assert.ok(!generated.has(name))
        generated.set(name, { pattern, flags })
      },
    })
  } catch (e) {
    console.error(`${test.name}: ${e}`)
    process.exit(1)
  }
}

const createdDirs = new Set<string>()
await fs.mkdir(distDir)
await fs.writeFile(path.join(distDir, '.gitignore'), '*')
for (const [testname, content] of generated) {
  const dirs = testname.split('/')
  const filename = dirs.pop()
  assert.ok(filename)

  let resultingPath = distDir
  for (const dir of dirs) {
    resultingPath = path.join(resultingPath, dir)
    if (!createdDirs.has(resultingPath)) {
      createdDirs.add(resultingPath)
      await fs.mkdir(resultingPath)
    }
  }
  await fs.writeFile(
    path.join(resultingPath, filename),
    JSON.stringify(content),
  )
}
