package regonaut

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v2"
	"gotest.tools/v3/assert"

	"path/filepath"
	"testing"
)

const (
	flagHasIndicies Flag = FlagAnnexB << (iota + 1)
	flagGlobal
)

func parseFlags(str string) (Flag, error) {
	var flags Flag
	for _, char := range str {
		var m Flag
		switch char {
		case 'd':
			m = flagHasIndicies
		case 'g':
			m = flagGlobal
		case 'i':
			m = FlagIgnoreCase
		case 'm':
			m = FlagMultiline
		case 's':
			m = FlagDotAll
		case 'u':
			m = FlagUnicode
		case 'v':
			m = FlagUnicodeSets
		case 'y':
			m = FlagSticky
		default:
			return 0, newSyntaxError("invalid flag")
		}
		if flags&m != 0 {
			return 0, newSyntaxError("duplicate flag")
		}
		flags |= m
	}
	return flags, nil
}

func Test262(t *testing.T) {
	currentDir := getCurrentDir()
	rootDir := filepath.Join(currentDir, "test262")
	testsDir := filepath.Join(rootDir, "test")
	harnessDir := filepath.Join(rootDir, "harness")
	generatedDir := filepath.Join(currentDir, "test262-generated")
	generatedSyntaxErrorDir := filepath.Join(generatedDir, "syntax-error")

	harness := map[string][]byte{}

	{
		harnessFiles, err := os.ReadDir(harnessDir)
		assert.NilError(t, err)
		for _, file := range harnessFiles {
			if !file.Type().IsRegular() {
				continue
			}

			p := filepath.Join(harnessDir, file.Name())

			content, err := os.ReadFile(p)
			assert.NilError(t, err)
			harness[file.Name()] = content
		}
	}

	type testEntry struct {
		path string
		name string
	}
	type testMetadata struct {
		Includes []string
		Negative struct {
			Phase string
			Type  string
		}
	}
	type testSyntaxError struct {
		Pattern string
		Flags   string
	}
	type testParsed struct {
		testEntry
		metadata    testMetadata
		source      []byte
		syntaxError *testSyntaxError
		compiled    []byte
	}
	findTests := func(basepath string) []testEntry {
		res := []testEntry{}
		assert.NilError(t, filepath.WalkDir(basepath, func(testPath string, d fs.DirEntry, err error) error {
			if d == nil || !d.Type().IsRegular() || strings.Contains(testPath, "_FIXTURE") {
				return nil
			}

			testName, err := filepath.Rel(testsDir, testPath)

			if err != nil {
				return err
			}
			res = append(res, testEntry{path: testPath, name: testName})
			return nil
		}))
		return res
	}

	syntaxErrorGenerated := map[string]testSyntaxError{}
	assert.NilError(t, filepath.WalkDir(generatedSyntaxErrorDir, func(p string, d fs.DirEntry, err error) error {
		if d == nil || !d.Type().IsRegular() {
			return nil
		}
		name, err := filepath.Rel(generatedSyntaxErrorDir, p)
		if err != nil {
			return err
		}
		c, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var s testSyntaxError
		if err := json.Unmarshal(c, &s); err != nil {
			return nil
		}
		syntaxErrorGenerated[name] = s
		return nil
	}))

	parseTests := func(tests []testEntry) []testParsed {
		parsed := make([]testParsed, len(tests))
		for i, entry := range tests {
			test := &parsed[i]
			test.testEntry = entry
			content, err := os.ReadFile(test.path)
			assert.NilError(t, err)
			metadataStart := []byte("/*---")
			metadataEnd := []byte("---*/")
			metadataSource := content[bytes.Index(content, metadataStart)+len(metadataStart) : bytes.Index(content, metadataEnd)]

			assert.NilError(t, yaml.Unmarshal(metadataSource, &test.metadata))

			test.metadata.Includes = append(test.metadata.Includes, "assert.js", "sta.js")

			if s, ok := syntaxErrorGenerated[test.name]; ok {
				test.syntaxError = &s
				assert.Equal(t, test.metadata.Negative.Phase, "parse")
				continue
			}

			assert.Equal(t, test.metadata.Negative.Phase == "parse", false)

			compiledSize := len(content)
			for _, inc := range test.metadata.Includes {
				compiledSize += len(harness[inc]) + 1
			}

			test.compiled = make([]byte, compiledSize)
			compiledSize = 0
			for _, inc := range test.metadata.Includes {
				src := harness[inc]
				copy(test.compiled[compiledSize:], src)
				compiledSize += len(src)
				test.compiled[compiledSize] = '\n'
				compiledSize++
			}
			copy(test.compiled[compiledSize:], content)
		}
		return parsed
	}

	runTests := func(annexB bool, tests []testParsed) {
		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				if test.metadata.Negative.Phase == "parse" {
					f, err := parseFlags(test.syntaxError.Flags)
					if err != nil {
						return
					}
					if annexB {
						f |= FlagAnnexB
					}
					_, err = Compile(test.syntaxError.Pattern, f)
					if err != nil {
						return
					}
					t.Fatal("expected syntax error to be thrown")
				}

				worker, err := nodeJsWorkers.getWorker()
				defer nodeJsWorkers.releaseWorker(worker)
				assert.NilError(t, err)

				assert.NilError(t, worker.sendMessage(nodeJsWorkerMsgTypeTest262Start, test.compiled))

				buf := []byte{}

				for {
					msgType, err := worker.receiveMessage()
					assert.NilError(t, err)
					buf = buf[:0]
					switch msgType {
					case nodeJsWorkerMsgTypeTest262End:
						if len(worker.payloadBuf) > 0 {
							t.Fatal(string(worker.payloadBuf))
						}
						return
					case nodeJsWorkerMsgTypeTest262RegExpCompile:
						var offset uint32 = 0
						flagsLen := uint32(worker.payloadBuf[offset])
						offset++
						flags := string(worker.payloadBuf[offset : offset+flagsLen])
						offset += flagsLen
						patternLen := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
						offset += 4
						pattern := make([]uint16, patternLen/2)
						for i := range pattern {
							pattern[i] = binary.LittleEndian.Uint16(worker.payloadBuf[offset+uint32(i)*2:])
						}

						f, err := parseFlags(flags)
						if annexB {
							f |= FlagAnnexB
						}
						if err == nil {
							_, err = CompileUtf16(pattern, f)
						}
						var response byte = 1
						if err == nil {
							response = 0
						}
						worker.sendMessage(nodeJsWorkerMsgTypeTest262RegExpCompile, []byte{response})
					case nodeJsWorkerMsgTypeTest262RegExpExec:
						var offset uint32 = 0
						lastIndex := int(binary.LittleEndian.Uint32(worker.payloadBuf[offset:]))
						offset += 4
						flagsLen := uint32(worker.payloadBuf[offset])
						offset++
						flags := string(worker.payloadBuf[offset : offset+flagsLen])
						offset += flagsLen
						patternLen := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
						offset += 4
						pattern := make([]uint16, patternLen/2)
						for i := range pattern {
							pattern[i] = binary.LittleEndian.Uint16(worker.payloadBuf[offset+uint32(i)*2:])
						}
						offset += patternLen
						sourceLen := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
						offset += 4
						source := make([]uint16, sourceLen/2)
						for i := range source {
							source[i] = binary.LittleEndian.Uint16(worker.payloadBuf[offset+uint32(i)*2:])
						}
						offset += sourceLen

						f, err := parseFlags(flags)
						assert.NilError(t, err)
						if annexB {
							f |= FlagAnnexB
						}
						re, err := CompileUtf16(pattern, f)
						assert.NilError(t, err)

						if lastIndex > len(source) {
							worker.sendMessage(nodeJsWorkerMsgTypeTest262RegExpExecNotMatched, []byte{0, 0, 0, 0})
							continue
						}
						startPos := 0
						if f&(flagGlobal|FlagSticky) != 0 {
							startPos = lastIndex
						}
						match := re.FindMatchStartingAt(source, startPos)
						if match == nil {
							if f&(FlagSticky|flagGlobal) == 0 {
								buf, err = binary.Append(buf, binary.LittleEndian, uint32(lastIndex))
								assert.NilError(t, err)
								worker.sendMessage(nodeJsWorkerMsgTypeTest262RegExpExecNotMatched, buf)
							} else {
								worker.sendMessage(nodeJsWorkerMsgTypeTest262RegExpExecNotMatched, []byte{0, 0, 0, 0})
							}
							continue
						}

						buf, err = binary.Append(buf, binary.LittleEndian, uint32(len(match.Groups)))
						assert.NilError(t, err)
						for _, g := range match.Groups {
							buf, err = binary.Append(buf, binary.LittleEndian, uint32(g.Start))
							assert.NilError(t, err)
							buf, err = binary.Append(buf, binary.LittleEndian, uint32(g.End))
							assert.NilError(t, err)
						}

						buf, err = binary.Append(buf, binary.LittleEndian, uint32(len(match.NamedGroups)))
						assert.NilError(t, err)
						type withFirstIndex struct {
							name string
							o    int
						}
						ordered := make([]withFirstIndex, len(re.c.namedCaptures))
						i := 0
						for g, v := range re.c.namedCaptures {
							ordered[i] = withFirstIndex{g, v[0]}
							i++
						}
						slices.SortFunc(ordered, func(a withFirstIndex, b withFirstIndex) int {
							return a.o - b.o
						})
						for _, o := range ordered {
							g := match.NamedGroups[o.name]
							assert.NilError(t, appendStringToBuf(&buf, []byte(o.name)))
							buf, err = binary.Append(buf, binary.LittleEndian, uint32(g.Start))
							assert.NilError(t, err)
							buf, err = binary.Append(buf, binary.LittleEndian, uint32(g.End))
							assert.NilError(t, err)
						}
						worker.sendMessage(nodeJsWorkerMsgTypeTest262RegExpExecMatched, buf)
					}
				}
			})
		}
	}

	runTests(false, parseTests(slices.DeleteFunc(findTests(filepath.Join(testsDir, "built-ins", "RegExp")), func(test testEntry) bool {
		n := strings.TrimPrefix(test.name, "built-ins/RegExp/")
		return strings.HasPrefix(n, "escape/") || // issue with $262.createRealm
			strings.HasPrefix(n, "prototype/") || // unrelated to regular expressions
			strings.HasPrefix(n, "Symbol.species/") ||
			// related to prototype/property descriptors testing
			n == "proto-from-ctor-realm.js" ||
			n == "from-regexp-like-short-circuit.js" ||
			n == "from-regexp-like.js" ||
			n == "call_with_non_regexp_same_constructor.js" ||
			n == "prop-desc.js" ||
			n == "named-groups/groups-object-subclass.js" ||
			n == "named-groups/groups-object-subclass-sans.js" ||
			n == "S15.10.7_A3_T2.js" ||
			n == "S15.10.7_A3_T1.js" ||
			n == "S15.10.4.1_A7_T1.js" ||
			n == "S15.10.4.1_A7_T2.js" ||
			n == "S15.10.3.1_A3_T1.js" ||
			n == "S15.10.3.1_A3_T2.js"
	})))
	runTests(false, parseTests(slices.DeleteFunc(findTests(filepath.Join(testsDir, "language", "literals", "regexp")), func(test testEntry) bool {
		// Tests without a generated syntax error use eval to parse the regexp
		// literal at runtime. Or test RegularExpressionLiteral syntax (its behavior
		// as part of ECMAScript source code). These are not trivial to extract, but
		// maybe one day I'll manage to do it.
		_, ok := syntaxErrorGenerated[test.name]
		return !ok
	})))
	runTests(true, parseTests(slices.DeleteFunc(findTests(filepath.Join(testsDir, "annexB", "built-ins", "RegExp")), func(test testEntry) bool {
		n := strings.TrimPrefix(test.name, "annexB/built-ins/RegExp/")
		return strings.HasPrefix(n, "legacy-accessors/") || // unrelated to regular expressions
			strings.HasPrefix(n, "prototype/")
	})))
	runTests(true, parseTests(slices.DeleteFunc(findTests(filepath.Join(testsDir, "annexB", "language", "literals", "regexp")), func(test testEntry) bool {
		return false
	})))
}
