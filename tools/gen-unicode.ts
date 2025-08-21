import fs from 'node:fs/promises'
import path from 'node:path'
import assert from 'node:assert/strict'
import url from 'node:url'
import child_process from 'node:child_process'

import ID_Start from '@unicode/unicode-16.0.0/Binary_Property/ID_Start/code-points.js'
import ID_Continue from '@unicode/unicode-16.0.0/Binary_Property/ID_Continue/code-points.js'

import _Simple_Uppercase_Mapping from '@unicode/unicode-16.0.0/Simple_Case_Mapping/Uppercase/code-points.js'
import _Uppercase_Mapping from '@unicode/unicode-16.0.0/Special_Casing/Uppercase/code-points.js'
// TODO: fix upstream types
// @ts-expect-error
const Simple_Uppercase_Mapping = _Simple_Uppercase_Mapping as Map<
  number,
  number
>
// @ts-expect-error
const Uppercase_Mapping = _Uppercase_Mapping as Map<number, number[]>

import Space_Separator from '@unicode/unicode-16.0.0/General_Category/Space_Separator/code-points.js'

import _Case_Folding_C from '@unicode/unicode-16.0.0/Case_Folding/C/code-points.js'
import _Case_Folding_S from '@unicode/unicode-16.0.0/Case_Folding/S/code-points.js'
// @ts-expect-error
const Case_Folding_C = _Case_Folding_C as Map<number, number>
// @ts-expect-error
const Case_Folding_S = _Case_Folding_S as Map<number, number>

import PropertyValueAliases from 'unicode-property-value-aliases-ecmascript'

import Basic_Emoji from '@unicode/unicode-16.0.0/Sequence_Property/Basic_Emoji/index.js'
import Emoji_Keycap_Sequence from '@unicode/unicode-16.0.0/Sequence_Property/Emoji_Keycap_Sequence/index.js'
import RGI_Emoji_Modifier_Sequence from '@unicode/unicode-16.0.0/Sequence_Property/RGI_Emoji_Modifier_Sequence/index.js'
import RGI_Emoji_Flag_Sequence from '@unicode/unicode-16.0.0/Sequence_Property/RGI_Emoji_Flag_Sequence/index.js'
import RGI_Emoji_Tag_Sequence from '@unicode/unicode-16.0.0/Sequence_Property/RGI_Emoji_Tag_Sequence/index.js'
import RGI_Emoji_ZWJ_Sequence from '@unicode/unicode-16.0.0/Sequence_Property/RGI_Emoji_ZWJ_Sequence/index.js'
import RGI_Emoji from '@unicode/unicode-16.0.0/Sequence_Property/RGI_Emoji/index.js'

const maxLatin1 = 0xff
const max16bit = 0xffff
const maxUnicode = 0x10ffff

const ecmaWhiteSpace = [
  0x9, // \t
  0xb, // line tabulation
  0xc, // form feed (\f)
  0xfeff, // zero width no-break space
  ...Space_Separator,
]
const ecmaLineTerminators = [
  0xa, // \n
  0xd, // \r
  0x2028, // line separator
  0x2029, // paragraph separator
]

// NOTE: i manually copied them here from table-binary-unicode-properties.html
// - it's not guaranteed that every alias from PropertyAliases.txt is supported
// in ECMA-262
// - not all binary properties are allowed by ECMA-262
const propertyAliases = new Map([
  ['ASCII', 'ASCII'],
  ['ASCII_Hex_Digit', 'ASCII_Hex_Digit'],
  ['AHex', 'ASCII_Hex_Digit'],
  ['Alphabetic', 'Alphabetic'],
  ['Alpha', 'Alphabetic'],
  ['Any', 'Any'],
  ['Assigned', 'Assigned'],
  ['Bidi_Control', 'Bidi_Control'],
  ['Bidi_C', 'Bidi_Control'],
  ['Bidi_Mirrored', 'Bidi_Mirrored'],
  ['Bidi_M', 'Bidi_Mirrored'],
  ['Case_Ignorable', 'Case_Ignorable'],
  ['CI', 'Case_Ignorable'],
  ['Cased', 'Cased'],
  ['Changes_When_Casefolded', 'Changes_When_Casefolded'],
  ['CWCF', 'Changes_When_Casefolded'],
  ['Changes_When_Casemapped', 'Changes_When_Casemapped'],
  ['CWCM', 'Changes_When_Casemapped'],
  ['Changes_When_Lowercased', 'Changes_When_Lowercased'],
  ['CWL', 'Changes_When_Lowercased'],
  ['Changes_When_NFKC_Casefolded', 'Changes_When_NFKC_Casefolded'],
  ['CWKCF', 'Changes_When_NFKC_Casefolded'],
  ['Changes_When_Titlecased', 'Changes_When_Titlecased'],
  ['CWT', 'Changes_When_Titlecased'],
  ['Changes_When_Uppercased', 'Changes_When_Uppercased'],
  ['CWU', 'Changes_When_Uppercased'],
  ['Dash', 'Dash'],
  ['Default_Ignorable_Code_Point', 'Default_Ignorable_Code_Point'],
  ['DI', 'Default_Ignorable_Code_Point'],
  ['Deprecated', 'Deprecated'],
  ['Dep', 'Deprecated'],
  ['Diacritic', 'Diacritic'],
  ['Dia', 'Diacritic'],
  ['Emoji', 'Emoji'],
  ['Emoji_Component', 'Emoji_Component'],
  ['EComp', 'Emoji_Component'],
  ['Emoji_Modifier', 'Emoji_Modifier'],
  ['EMod', 'Emoji_Modifier'],
  ['Emoji_Modifier_Base', 'Emoji_Modifier_Base'],
  ['EBase', 'Emoji_Modifier_Base'],
  ['Emoji_Presentation', 'Emoji_Presentation'],
  ['EPres', 'Emoji_Presentation'],
  ['Extended_Pictographic', 'Extended_Pictographic'],
  ['ExtPict', 'Extended_Pictographic'],
  ['Extender', 'Extender'],
  ['Ext', 'Extender'],
  ['Grapheme_Base', 'Grapheme_Base'],
  ['Gr_Base', 'Grapheme_Base'],
  ['Grapheme_Extend', 'Grapheme_Extend'],
  ['Gr_Ext', 'Grapheme_Extend'],
  ['Hex_Digit', 'Hex_Digit'],
  ['Hex', 'Hex_Digit'],
  ['IDS_Binary_Operator', 'IDS_Binary_Operator'],
  ['IDSB', 'IDS_Binary_Operator'],
  ['IDS_Trinary_Operator', 'IDS_Trinary_Operator'],
  ['IDST', 'IDS_Trinary_Operator'],
  ['ID_Continue', 'ID_Continue'],
  ['IDC', 'ID_Continue'],
  ['ID_Start', 'ID_Start'],
  ['IDS', 'ID_Start'],
  ['Ideographic', 'Ideographic'],
  ['Ideo', 'Ideographic'],
  ['Join_Control', 'Join_Control'],
  ['Join_C', 'Join_Control'],
  ['Logical_Order_Exception', 'Logical_Order_Exception'],
  ['LOE', 'Logical_Order_Exception'],
  ['Lowercase', 'Lowercase'],
  ['Lower', 'Lowercase'],
  ['Math', 'Math'],
  ['Noncharacter_Code_Point', 'Noncharacter_Code_Point'],
  ['NChar', 'Noncharacter_Code_Point'],
  ['Pattern_Syntax', 'Pattern_Syntax'],
  ['Pat_Syn', 'Pattern_Syntax'],
  ['Pattern_White_Space', 'Pattern_White_Space'],
  ['Pat_WS', 'Pattern_White_Space'],
  ['Quotation_Mark', 'Quotation_Mark'],
  ['QMark', 'Quotation_Mark'],
  ['Radical', 'Radical'],
  ['Regional_Indicator', 'Regional_Indicator'],
  ['RI', 'Regional_Indicator'],
  ['Sentence_Terminal', 'Sentence_Terminal'],
  ['STerm', 'Sentence_Terminal'],
  ['Soft_Dotted', 'Soft_Dotted'],
  ['SD', 'Soft_Dotted'],
  ['Terminal_Punctuation', 'Terminal_Punctuation'],
  ['Term', 'Terminal_Punctuation'],
  ['Unified_Ideograph', 'Unified_Ideograph'],
  ['UIdeo', 'Unified_Ideograph'],
  ['Uppercase', 'Uppercase'],
  ['Upper', 'Uppercase'],
  ['Variation_Selector', 'Variation_Selector'],
  ['VS', 'Variation_Selector'],
  ['White_Space', 'White_Space'],
  ['space', 'White_Space'],
  ['XID_Continue', 'XID_Continue'],
  ['XIDC', 'XID_Continue'],
  ['XID_Start', 'XID_Start'],
  ['XIDS', 'XID_Start'],
])

let generated = `// Code generated by tools/gen-unicode.ts. DO NOT EDIT.

package regonaut

var unicodeID_Start = ${genCharSetFromCodepoints(ID_Start)}
var unicodeID_Continue = ${genCharSetFromCodepoints(ID_Continue)}
var ecmaID_Start = ${genCharSetFromCodepoints([...ID_Start, codepointOfChar('_'), codepointOfChar('$')])}
var ecmaID_Continue = ${genCharSetFromCodepoints([...ID_Continue, codepointOfChar('$')])}
var ecmaWhiteSpaceOrLineTerminator = ${genCharSetFromCodepoints([
  ...ecmaWhiteSpace,
  ...ecmaLineTerminators,
])}
${genIsRuneFunc('isEcmaLineTerminator', ecmaLineTerminators)}
`

// Even though toUppercase relies on Uppercase_Mapping from SpecialCasing.txt,
// Canonicalize ignores one-to-many mapped codepoints. So to make sure that all
// mappings in Uppercase_Mapping are one-to-many we use this assertion.
for (const [code, mapping] of Uppercase_Mapping) {
  assert.ok(
    mapping.length > 1 || mapping[0] === code,
    `Expected ${codepointToReadable(code)} to have one-to-many mapping. Got: ${JSON.stringify(mapping.map(codepointToReadable))}`,
  )
}

generated += `var unicodeUppercase_Mapping = ${genMapping(Simple_Uppercase_Mapping)}`

// Just in case assert that C and S do not intersect
assert.equal(
  new Set(Case_Folding_C.keys()).intersection(new Set(Case_Folding_S.keys()))
    .size,
  0,
)
const simpleCaseFolding = new Map([...Case_Folding_C, ...Case_Folding_S])
generated += `var unicodeSimpleCaseFolding = ${genMapping(simpleCaseFolding)}\n`

// Fun fact: this table consists only of two characters: 0x17f and 0x212. Proof:
//
// for (let i = 0; i < 0x10ffff; i++) {
//   let c = String.fromCodePoint(i);
//   !/[a-z0-9_]/i.exec(c) && /\w/ui.exec(c) && console.log(i.toString(16), c)
// }
const ecmaExtraWordChars = Array.from(
  simpleCaseFolding
    .entries()
    .filter(([k, v]) => !isASCIIWordChar(k) && isASCIIWordChar(v))
    .map(([k]) => k),
)
generated += `var ecmaExtraWordChars = ${genCharSetFromCodepoints(ecmaExtraWordChars)}
${genIsRuneFunc('isEcmaExtraWordChar', ecmaExtraWordChars)}
`

{
  const scriptUnknownTableName = tableName('ScriptOrExtensions', 'Unknown')
  const assignedScriptRanges: Range[] = []
  const rangeTables = new Map<string, Map<string, string>>()
  for (const propertyName of [
    'General_Category',
    'Script',
    'Script_Extensions',
  ] as const) {
    const m = new Map<string, string>()
    rangeTables.set(propertyName, m)
    for await (const { propertyValue, codepoints } of iterPropertyValues(
      propertyName,
    )) {
      const t = tableName(propertyName, propertyValue)
      if (propertyName === 'Script' || propertyName === 'Script_Extensions') {
        m.set('Unknown', scriptUnknownTableName)
      }
      m.set(propertyValue, t)
      generated += `var ${t} = ${genCharSetFromCodepoints(codepoints)}\n`

      if (propertyName === 'Script') {
        let index = 0
        while (index < codepoints.length) {
          const from = codepoints[index]
          while (
            index + 1 < codepoints.length &&
            codepoints[index] + 1 === codepoints[index + 1]
          ) {
            index++
          }
          assignedScriptRanges.push({ from, to: codepoints[index] })
          index++
        }
      }
    }
  }
  assignedScriptRanges.sort((a, b) => a.from - b.from)

  // assert so that we don't add an empty unassigned range
  assert.equal(assignedScriptRanges[0].from, 0)

  const unassignedScriptRanges: { from: number; to: number }[] = []
  for (let i = 0; i < assignedScriptRanges.length - 1; i++) {
    if (assignedScriptRanges[i].to + 1 !== assignedScriptRanges[i + 1].from) {
      unassignedScriptRanges.push({
        from: assignedScriptRanges[i].to + 1,
        to: assignedScriptRanges[i + 1].from - 1,
      })
    }
  }
  unassignedScriptRanges.push({
    from: assignedScriptRanges.at(-1)!.to + 1,
    to: maxUnicode,
  })
  generated += `var ${scriptUnknownTableName} = ${genCharSetFromRanges(unassignedScriptRanges)}\n`

  for (const [propertyName, aliases] of PropertyValueAliases) {
    const tables = rangeTables.get(propertyName)!
    for (const [propertyValueAlias, propertyValue] of aliases) {
      if (
        (propertyName === 'Script' || propertyName === 'Script_Extensions') &&
        propertyValue === 'Katakana_Or_Hiragana'
      ) {
        // https://github.com/tc39/ecma262/issues/3590
        // Katakana_Or_Hiragana doesn't include any codepoints
        assert.equal(tables.has(propertyValue), false)
      } else if (
        (propertyName === 'Script' || propertyName === 'Script_Extensions') &&
        propertyValue === 'Unknown'
      ) {
        tables.set(propertyValueAlias, scriptUnknownTableName)
      } else {
        tables.set(propertyValueAlias, tableName(propertyName, propertyValue))
      }
    }

    generated += `var unicodePropertyValueAliases_${propertyName} = map[string]*charSet{\n${Array.from(
      tables,
    )
      .map(([alias, table]) => `\t"${alias}": ${table},\n`)
      .join('')}}\n`
  }
}

{
  for (const property of new Set(propertyAliases.values())) {
    const { default: codepoints }: { default: number[] } = await import(
      `@unicode/unicode-16.0.0/Binary_Property/${property}/code-points.js`
    )
    generated += `var ${tableName('Binary_Property', property)} = ${genCharSetFromCodepoints(codepoints)}\n`
  }
  generated += `var unicodePropertyAliases = map[string]*charSet{\n`
  for (const [alias, property] of propertyAliases) {
    generated += `\t"${alias}": ${tableName('Binary_Property', property)},\n`
  }
  generated += `}\n`
}

for (const [name, sequences] of Object.entries({
  Basic_Emoji,
  Emoji_Keycap_Sequence,
  RGI_Emoji_Modifier_Sequence,
  RGI_Emoji_Flag_Sequence,
  RGI_Emoji_Tag_Sequence,
  RGI_Emoji_ZWJ_Sequence,
  RGI_Emoji,
})) {
  let min = Number.MAX_VALUE
  let max = 0
  generated += `var unicode${name} = &charSet{strings: stringSet{\n\ts: map[string]struct{}{\n`
  for (const sequence of sequences) {
    generated += `\t\t${JSON.stringify(sequence)}: struct{}{},\n`
    const { length } = [...sequence]
    min = Math.min(min, length)
    max = Math.max(max, length)
  }
  generated += `\t},\n\tminlen: ${min},\n\tmaxlen: ${max},\n}}\n`
}

{
  const outputPath = path.join(
    import.meta.dirname,
    '..',
    'unicode_generated.go',
  )
  await fs.writeFile(outputPath, generated)

  const { status, error } = child_process.spawnSync('go', ['fmt', outputPath], {
    stdio: 'inherit',
  })
  if (error != null) {
    throw error
  }
  process.exit(status)
}

function codepointToReadable(codepoint: number): string {
  return `U+${codepoint.toString(16).padStart(4, '0')}`
}
function codepointToHex(codepoint: number): string {
  return `0x${codepoint.toString(16).padStart(4, '0')}`
}

function genCharSetFromCodepoints(codepoints: number[]): string {
  codepoints = codepoints.toSorted((a, b) => a - b)
  let res = `&charSet{chars: []charRange{\n`

  let index = 0
  while (index < codepoints.length) {
    const lo = codepoints[index]
    while (
      index + 1 < codepoints.length &&
      codepoints[index] + 1 === codepoints[index + 1]
    ) {
      index++
    }
    const hi = codepoints[index]
    res += `\t{${codepointToHex(lo)}, ${codepointToHex(hi)}},\n`
    index++
  }

  res += `}}\n`
  return res
}

type Range = { from: number; to: number }
function genCharSetFromRanges(ranges: Range[]): string {
  ranges = ranges.toSorted((a, b) => a.from - b.from)
  let res = `&charSet{chars: []charRange{\n`

  for (const { from, to } of ranges) {
    res += `\t{${codepointToHex(from)}, ${codepointToHex(to)}},\n`
  }
  res += `}}\n`

  return res
}

function genMapping(mapping: Map<number, number>): string {
  let res = `/* TODO(perf): */ map[rune]rune{\n`
  for (const [key, value] of mapping) {
    res += `\t${codepointToHex(key)}: ${codepointToHex(value)},\n`
  }
  return res + '}\n'
}

function isASCIIWordChar(codepoint: number): boolean {
  return /[a-z0-9_]/i.exec(String.fromCodePoint(codepoint)) != null
}

async function* iterPropertyValues(propertyName: string) {
  const baseName = `@unicode/unicode-16.0.0/${propertyName}`
  for (const propertyValueEntry of await fs.readdir(
    url.fileURLToPath(import.meta.resolve(baseName)),
    { withFileTypes: true },
  )) {
    if (!propertyValueEntry.isDirectory()) {
      continue
    }
    const propertyValue = propertyValueEntry.name
    const { default: codepoints }: { default: number[] } = await import(
      `${baseName}/${propertyValue}/code-points.js`
    )
    yield { propertyValue, codepoints }
  }
}
function tableName(propertyName: string, propertyValue: string): string {
  return `__table_${propertyName}_${propertyValue}`
}
function codepointOfChar(str: string) {
  assert.equal(str.length, 1)
  return str.codePointAt(0)!
}
function genIsRuneFunc(name: string, codepoints: number[]) {
  return `func ${name}(r rune) bool {
\treturn ${codepoints.map(t => `r == ${codepointToHex(t)}`).join(' ||\n\t\t')}
}
`
}
