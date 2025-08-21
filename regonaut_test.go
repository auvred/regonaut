package regonaut

import (
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"gotest.tools/v3/assert"
)

const nilMatch = "!SPECIAL_NIL_MATCH!"

var nilMatchUtf16 = u16e(nilMatch)

func ensureCap(b []byte, needed int) []byte {
	if b == nil || cap(b) < needed {
		b = make([]byte, needed)
	}
	return b
}

type nodeJsWorker struct {
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	payloadBuf []byte
}

func newNodeJsWorker() (*nodeJsWorker, error) {
	w := &nodeJsWorker{}
	cmd := exec.Command(
		"node",
		filepath.Join(getCurrentDir(), "tools", "test-runner.ts"),
	)
	var err error
	w.stdin, err = cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %v", err)
	}
	w.stdout, err = cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *nodeJsWorker) sendMessage(msgType nodeJsWorkerMsgType, payload []byte) error {
	var header [5]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)))
	header[4] = byte(msgType)
	_, err := w.stdin.Write(header[:])
	if err != nil {
		return err
	}
	_, err = w.stdin.Write(payload)
	return err
}
func (w *nodeJsWorker) receiveMessage() (nodeJsWorkerMsgType, error) {
	var header [5]byte
	_, err := io.ReadFull(w.stdout, header[:])
	if err != nil {
		return 0, fmt.Errorf("error receiving header: %v", err)
	}
	payloadLen := binary.LittleEndian.Uint32(header[:])
	messageType := nodeJsWorkerMsgType(header[4])

	w.payloadBuf = ensureCap(w.payloadBuf, int(payloadLen))[:payloadLen]

	if _, err := io.ReadFull(w.stdout, w.payloadBuf); err != nil {
		return 0, fmt.Errorf("error receiving payload: %v", err)
	}
	return messageType, nil
}

type nodeJsWorkerPool struct {
	mu      sync.Mutex
	maxSize int
	size    int
	queue   chan *nodeJsWorker
}

var nodeJsWorkers nodeJsWorkerPool

func init() {
	nodeJsWorkers.maxSize = 14 //runtime.GOMAXPROCS(0)
	nodeJsWorkers.queue = make(chan *nodeJsWorker, nodeJsWorkers.maxSize)
}

type nodeJsWorkerMsgType uint8

const (
	nodeJsWorkerMsgTypeTest262End nodeJsWorkerMsgType = iota
	nodeJsWorkerMsgTypeTest262Start
	nodeJsWorkerMsgTypeTest262RegExpExec
	nodeJsWorkerMsgTypeTest262RegExpExecMatched
	nodeJsWorkerMsgTypeTest262RegExpExecNotMatched
	nodeJsWorkerMsgTypeTest262RegExpCompile
	nodeJsWorkerMsgTypeTestRegExpExec
	nodeJsWorkerMsgTypeTestRegExpExecError
	nodeJsWorkerMsgTypeTestRegExpExecMatched
	nodeJsWorkerMsgTypeTestRegExpExecNotMatched
	nodeJsWorkerMsgTypeTestRegExpSyntaxError
)

func getCurrentDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

func (p *nodeJsWorkerPool) releaseWorker(w *nodeJsWorker) {
	p.queue <- w
}

func (p *nodeJsWorkerPool) getWorker() (*nodeJsWorker, error) {
	var w *nodeJsWorker
	p.mu.Lock()
	if p.size < p.maxSize {
		select {
		case w = <-p.queue:
			p.mu.Unlock()
		default:
			p.size++
			p.mu.Unlock()
			var err error
			w, err = newNodeJsWorker()
			if err != nil {
				p.mu.Unlock()
				return nil, err
			}
		}
	} else {
		p.mu.Unlock()
		w = <-p.queue
	}

	return w, nil
}

type runner struct {
	t         *testing.T
	runNodeJs bool
	flag      Flag
}

func utf16Decode(v []uint16) ([]byte, bool) {
	valid := true
	res := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		r := rune(v[i])
		if isLowSurrogate(r) {
			valid = false
		} else if isHighSurrogate(r) {
			if i+1 < len(v) {
				lo := rune(v[i+1])
				if isLowSurrogate(lo) {
					r = utf16.DecodeRune(r, lo)
					i++
				} else {
					valid = false
				}
			} else {
				valid = false
			}
		}
		res = utf8.AppendRune(res, r)
	}
	return res, valid
}
func u16e(s string) []uint16 {
	return utf16.Encode([]rune(s))
}
func runeToWTF8(r rune) []byte {
	return []byte{
		0b11100000 | byte(r>>12),
		0b10000000 | (byte(r>>6) & 0b111111),
		0b10000000 | (byte(r) & 0b111111),
	}
}

func appendStringToBuf[T byte | uint16](buf *[]byte, str []T) error {
	start := len(*buf)
	*buf = append(*buf, 0, 0, 0, 0)
	var err error
	*buf, err = binary.Append(*buf, binary.LittleEndian, str)
	binary.LittleEndian.PutUint32((*buf)[start:], uint32(len(*buf)-start-4))
	return err
}

type testResult struct {
	error       string
	matched     bool
	groups      [][]uint16
	namedGroups map[string][]uint16
}

func (r *runner) testCase(tryUtf8 bool, pattern, source []uint16, run func(t *testing.T, baseline, actualUtf8, actualUtf16 *testResult)) {
	r.t.Run("", func(t *testing.T) {
		t.Parallel()
		patternS := stringSource{
			utf16:   pattern,
			isUtf16: true,
		}
		sourceS := stringSource{
			utf16:   source,
			isUtf16: true,
		}
		flagsString := r.flagsString()
		t.Logf(
			"new RegExp(%q, %q).exec(%q)\n",
			patternS.stringInRange(0, len(patternS.utf16)),
			flagsString,
			sourceS.stringInRange(0, len(sourceS.utf16)),
		)

		actualUtf16 := &testResult{}
		if re, err := CompileUtf16(pattern, r.flag); err != nil {
			actualUtf16.error = err.Error()
		} else {
			match := re.FindMatch(source)
			if match != nil {
				actualUtf16.matched = true
				actualUtf16.groups = make([][]uint16, len(match.Groups))
				actualUtf16.namedGroups = make(map[string][]uint16, len(match.NamedGroups))
				for i, g := range match.Groups {
					actualUtf16.groups[i] = g.Data()
				}
				for name, g := range match.NamedGroups {
					actualUtf16.namedGroups[name] = g.Data()
				}
			}
		}

		var actualUtf8 *testResult
		if tryUtf8 {
			actualUtf8 = &testResult{}
			if patternUtf8, ok := utf16Decode(pattern); !ok {
				actualUtf8.error = "couldn't convert pattern to utf8"
			} else if sourceUtf8, ok := utf16Decode(source); !ok {
				actualUtf8.error = "couldn't convert source to utf8"
			} else {
				if re, err := Compile(string(patternUtf8), r.flag); err != nil {
					actualUtf8.error = err.Error()
				} else {
					match := re.FindMatch(sourceUtf8)
					if match != nil {
						actualUtf8.matched = true
						actualUtf8.groups = make([][]uint16, len(match.Groups))
						actualUtf8.namedGroups = make(map[string][]uint16, len(match.NamedGroups))
						for i, g := range match.Groups {
							d := g.Data()
							if d != nil {
								actualUtf8.groups[i] = u16e(string(d))
							}
						}
						for name, g := range match.NamedGroups {
							d := g.Data()
							if d == nil {
								actualUtf8.namedGroups[name] = nil
							} else {
								actualUtf8.namedGroups[name] = u16e(string(d))
							}
						}
					}
				}
			}
		}

		var baseline *testResult

		if r.runNodeJs {
			baseline = &testResult{}
			worker, err := nodeJsWorkers.getWorker()
			assert.NilError(t, err)
			buf := append([]byte{byte(len(flagsString))}, []byte(flagsString)...)
			assert.NilError(t, appendStringToBuf(&buf, pattern))
			assert.NilError(t, appendStringToBuf(&buf, source))
			assert.NilError(t, worker.sendMessage(nodeJsWorkerMsgTypeTestRegExpExec, buf))
			msg, err := worker.receiveMessage()
			assert.NilError(t, err)
			switch msg {
			case nodeJsWorkerMsgTypeTestRegExpExecError:
				baseline.error = string(worker.payloadBuf)
			case nodeJsWorkerMsgTypeTestRegExpExecMatched:
				baseline.matched = true
				var offset uint32 = 0
				namedGroupsCount := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
				offset += 4
				baseline.namedGroups = make(map[string][]uint16, namedGroupsCount)
				for i := uint32(0); i < namedGroupsCount; i++ {
					nameLen := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
					offset += 4
					name := string(worker.payloadBuf[offset : offset+nameLen])
					offset += nameLen
					valueLen := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
					offset += 4
					baseline.namedGroups[name] = make([]uint16, valueLen/2)
					src := worker.payloadBuf[offset : offset+valueLen]
					if len(src) > 0 {
						for i := range baseline.namedGroups[name] {
							baseline.namedGroups[name][i] = binary.LittleEndian.Uint16(src[i*2:])
						}
						if slices.Equal(baseline.namedGroups[name], nilMatchUtf16) {
							baseline.namedGroups[name] = nil
						}
					}
					offset += valueLen
				}
				groupsCount := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
				offset += 4
				baseline.groups = make([][]uint16, groupsCount)
				for i := uint32(0); i < groupsCount; i++ {
					valueLen := binary.LittleEndian.Uint32(worker.payloadBuf[offset:])
					offset += 4
					baseline.groups[i] = make([]uint16, valueLen/2)
					src := worker.payloadBuf[offset : offset+valueLen]
					if len(src) > 0 {
						for j := range baseline.groups[i] {
							baseline.groups[i][j] = binary.LittleEndian.Uint16(src[j*2:])
						}
						if slices.Equal(baseline.groups[i], nilMatchUtf16) {
							baseline.groups[i] = nil
						}
					}
					offset += valueLen
				}
			case nodeJsWorkerMsgTypeTestRegExpExecNotMatched:
			default:
				t.Fatalf("unknown msg: %v", msg)
			}
			nodeJsWorkers.releaseWorker(worker)
		}

		run(t, baseline, actualUtf8, actualUtf16)
	})
}

func formatTestResult(res *testResult) string {
	if res == nil {
		return "-- skipped --"
	}
	if res.error != "" {
		return res.error
	}
	if !res.matched {
		return "<not matched>"
	}

	var out strings.Builder

	printStr := func(g []uint16) {
		if g == nil {
			out.WriteString("undefined")
		} else if t, ok := utf16Decode(g); ok {
			fmt.Fprintf(&out, "%q", t)
		} else {
			fmt.Fprintf(&out, "%q {", t)
			for i, e := range g {
				fmt.Fprintf(&out, "%#x", e)
				if i < len(g)-1 {
					out.WriteString(", ")
				}
			}
			out.WriteByte('}')
		}
	}

	out.WriteByte('[')
	for i, g := range res.groups {
		printStr(g)
		if i != len(res.groups)-1 {
			out.WriteString(", ")
		}
	}
	out.WriteString("] / {")
	i := 0
	for name, g := range res.namedGroups {
		fmt.Fprintf(&out, "%q", name)
		out.WriteString(": ")
		printStr(g)
		if i != len(res.namedGroups)-1 {
			out.WriteString(", ")
		}
		i++
	}
	out.WriteByte('}')

	return out.String()
}

func (r *runner) compareTestResults(t *testing.T, baseline, expected, actualUtf8, actualUtf16 *testResult) {
	uint16Equal := func(a, b []uint16) bool { return slices.Equal(a, b) }
	valid := (baseline == nil || baseline.error == "") && actualUtf16.error == "" && expected.matched == actualUtf16.matched && (actualUtf8 == nil || (expected.matched == actualUtf8.matched && actualUtf8.error == ""))
	if valid && expected.matched {
		valid = slices.EqualFunc(expected.groups, actualUtf16.groups[1:], uint16Equal) &&
			maps.EqualFunc(expected.namedGroups, actualUtf16.namedGroups, uint16Equal) &&
			(actualUtf8 == nil || (slices.EqualFunc(expected.groups, actualUtf8.groups[1:], uint16Equal) &&
				maps.EqualFunc(expected.namedGroups, actualUtf8.namedGroups, uint16Equal)))
	}

	if baseline != nil {
		valid = valid && expected.matched == baseline.matched
		if valid && expected.matched {
			valid = slices.EqualFunc(expected.groups, baseline.groups, uint16Equal) &&
				maps.EqualFunc(expected.namedGroups, baseline.namedGroups, uint16Equal)
		}
	}

	if len(actualUtf16.groups) > 0 {
		actualUtf16.groups = actualUtf16.groups[1:]
	}
	if actualUtf8 != nil && len(actualUtf8.groups) > 0 {
		actualUtf8.groups = actualUtf8.groups[1:]
	}

	if !valid {
		t.Fatalf(`Invalid result:
  Node.js:         %v
  Expected:        %v
  Actual (utf16):  %v
  Actual (utf8):   %v
`, formatTestResult(baseline), formatTestResult(expected), formatTestResult(actualUtf16), formatTestResult(actualUtf8))
	}
}

// Match
func (r *runner) m(pattern, source string, expectedGroups ...string) {
	expected := make([][]uint16, len(expectedGroups))
	for i, c := range expectedGroups {
		if c != nilMatch {
			expected[i] = u16e(c)
		}
	}
	r._m16(true, u16e(pattern), u16e(source), expected...)
}
func (r *runner) m16(pattern, source []uint16, expectedGroups ...[]uint16) {
	r._m16(false, pattern, source, expectedGroups...)
}
func (r *runner) m16s(pattern, source string, expectedGroups ...string) {
	expected := make([][]uint16, len(expectedGroups))
	for i, c := range expectedGroups {
		if c != nilMatch {
			expected[i] = u16e(c)
		}
	}
	r._m16(false, u16e(pattern), u16e(source), expected...)
}
func (r *runner) _m16(tryUtf8 bool, pattern, source []uint16, expectedGroups ...[]uint16) {
	r.testCase(tryUtf8, pattern, source, func(t *testing.T, baseline, actualUtf8, actualUtf16 *testResult) {
		r.compareTestResults(t, baseline, &testResult{
			matched:     true,
			namedGroups: map[string][]uint16{},
			groups:      expectedGroups,
		}, actualUtf8, actualUtf16)
	})
}

type gr = map[string]string
type gr16 = map[string][]uint16

// Match with named groups
func (r *runner) mg(pattern, source string, expectedNamedGroups gr, expectedGroups ...string) {
	expectedNamed := make(map[string][]uint16, len(expectedNamedGroups))
	expected := make([][]uint16, len(expectedGroups))
	for i, c := range expectedGroups {
		if c != nilMatch {
			expected[i] = u16e(c)
		}
	}
	for name, c := range expectedNamedGroups {
		if c == nilMatch {
			expectedNamed[name] = nil
		} else {
			expectedNamed[name] = u16e(c)
		}
	}
	r._mg16(true, u16e(pattern), u16e(source), expectedNamed, expected...)
}
func (r *runner) mg16(pattern, source []uint16, expectedNamedGroups gr16, expectedGroups ...[]uint16) {
	r._mg16(false, pattern, source, expectedNamedGroups, expectedGroups...)
}
func (r *runner) _mg16(tryUtf8 bool, pattern, source []uint16, expectedNamedGroups gr16, expectedGroups ...[]uint16) {
	r.testCase(tryUtf8, pattern, source, func(t *testing.T, baseline, actualUtf8, actualUtf16 *testResult) {
		r.compareTestResults(t, baseline, &testResult{
			matched:     true,
			namedGroups: expectedNamedGroups,
			groups:      expectedGroups,
		}, actualUtf8, actualUtf16)
	})
}

// Not Match
func (r *runner) n(pattern, source string) {
	r._n16(true, u16e(pattern), u16e(source))
}
func (r *runner) n16(pattern, source []uint16) {
	r._n16(false, pattern, source)
}
func (r *runner) n16s(pattern, source string) {
	r._n16(false, u16e(pattern), u16e(source))
}
func (r *runner) _n16(tryUtf8 bool, pattern, source []uint16) {
	r.testCase(tryUtf8, pattern, source, func(t *testing.T, baseline, actualUtf8, actualUtf16 *testResult) {
		r.compareTestResults(t, baseline, &testResult{}, actualUtf8, actualUtf16)
	})
}

// Syntax Error
func (r *runner) se(pattern string) {
	r._se(true, u16e(pattern))
}
func (r *runner) se16s(pattern string) {
	r._se(false, u16e(pattern))
}
func (r *runner) se16(pattern []uint16) {
	r._se(false, pattern)
}
func (r *runner) _se(tryUtf8 bool, pattern []uint16) {
	r.t.Run("", func(t *testing.T) {
		t.Parallel()
		patternS := stringSource{
			utf16:   pattern,
			isUtf16: true,
		}
		flagsString := r.flagsString()
		t.Logf(
			"Expected SyntaxError: new RegExp(%q, %q)\n",
			patternS.stringInRange(0, len(patternS.utf16)),
			flagsString,
		)

		valid := true

		actualUtf16Report := "-- no error --"
		_, err := CompileUtf16(pattern, r.flag)
		if err != nil {
			actualUtf16Report = "SyntaxError: " + err.Error()
		} else {
			valid = false
		}
		actualUtf8Report := "-- skipped --"
		if tryUtf8 {
			if patternUtf8, ok := utf16Decode(pattern); ok {
				_, err := Compile(string(patternUtf8), r.flag)
				if err != nil {
					actualUtf8Report = "SyntaxError: " + err.Error()
				} else {
					valid = false
					actualUtf8Report = "-- no error --"
				}
			}
		}

		nodeJsReport := "-- skipped --"
		if r.runNodeJs {
			worker, err := nodeJsWorkers.getWorker()
			assert.NilError(t, err)
			buf := append([]byte{byte(len(flagsString))}, []byte(flagsString)...)
			patternLenStart := len(buf)
			buf = append(buf, 0, 0, 0, 0)
			buf, err = binary.Append(buf, binary.LittleEndian, pattern)
			assert.NilError(t, err)
			binary.LittleEndian.PutUint32(buf[patternLenStart:], uint32(len(buf)-patternLenStart-4))
			assert.NilError(t, err)
			assert.NilError(t, worker.sendMessage(nodeJsWorkerMsgTypeTestRegExpSyntaxError, buf))
			_, err = worker.receiveMessage()
			assert.NilError(t, err)
			if len(worker.payloadBuf) != 0 {
				nodeJsReport = string(worker.payloadBuf)
			} else {
				nodeJsReport = "-- no error --"
				valid = false
			}
			nodeJsWorkers.releaseWorker(worker)
		}

		if !valid {
			t.Fatalf(`Invalid result:
  Node.js:         %v
  Expected:        SyntaxError
  Actual (utf16):  %v
  Actual (utf8):   %v
`, nodeJsReport, actualUtf16Report, actualUtf8Report)
		}
	})
}

const (
	i = FlagIgnoreCase
	m = FlagMultiline
	s = FlagDotAll
	u = FlagUnicode
	v = FlagUnicodeSets
	b = FlagAnnexB
)

var flagMap = map[Flag]byte{
	FlagIgnoreCase:  'i',
	FlagMultiline:   'm',
	FlagDotAll:      's',
	FlagUnicode:     'u',
	FlagUnicodeSets: 'v',
}

func (r runner) f(f Flag) *runner {
	r.flag |= f
	return &r
}

func (r *runner) flagsString() string {
	res := make([]byte, 0, len(flagMap))
	for flag, letter := range flagMap {
		if flag&r.flag != 0 {
			res = append(res, letter)
		}
	}
	return string(res)
}

// Skip the comparison with Node.js. This is useful for testing features without Annex B amendmends.
func (r runner) noNode() *runner {
	r.runNodeJs = false
	return &r
}

func newRunner(t *testing.T) runner {
	return runner{
		t:         t,
		runNodeJs: true,
	}
}

var (
	// https://codepoints.net/U+1F431
	catX                  = "1f431"
	catHX, catLX          = "d83d", "dc31"
	catHXU, catLXU        = "D83D", "DC31"
	catHN, catLN   uint16 = 0xd83d, 0xdc31
	// https://codepoints.net/U+10330
	ahsaX                   = "10330"
	ahsaHX, ahsaLX          = "d800", "df30"
	ahsaHXU, ahsaLXU        = "D800", "DF30"
	ahsaHN, ahsaLN   uint16 = 0xd800, 0xdf30
	// https://codepoints.net/U+2126
	omh = "Ω"
	// https://codepoints.net/U+03A9
	capOmega = "Ω"
	// https://codepoints.net/U+03C9
	smallOmega = "ω"
)

func TestHelperFunctions(t *testing.T) {
	assert.Equal(t, isHexDigit('0'-1), false)
	assert.Equal(t, isHexDigit('0'), true)
	assert.Equal(t, isHexDigit('5'), true)
	assert.Equal(t, isHexDigit('9'), true)
	assert.Equal(t, isHexDigit('9'+1), false)
	assert.Equal(t, isHexDigit('a'-1), false)
	assert.Equal(t, isHexDigit('a'), true)
	assert.Equal(t, isHexDigit('d'), true)
	assert.Equal(t, isHexDigit('f'), true)
	assert.Equal(t, isHexDigit('f'+1), false)
	assert.Equal(t, isHexDigit('A'-1), false)
	assert.Equal(t, isHexDigit('A'), true)
	assert.Equal(t, isHexDigit('D'), true)
	assert.Equal(t, isHexDigit('F'), true)
	assert.Equal(t, isHexDigit('F'+1), false)

	assert.Equal(t, isASCIIWordChar('0'-1), false)
	assert.Equal(t, isASCIIWordChar('0'), true)
	assert.Equal(t, isASCIIWordChar('5'), true)
	assert.Equal(t, isASCIIWordChar('9'), true)
	assert.Equal(t, isASCIIWordChar('9'+1), false)
	assert.Equal(t, isASCIIWordChar('a'-1), false)
	assert.Equal(t, isASCIIWordChar('a'), true)
	assert.Equal(t, isASCIIWordChar('m'), true)
	assert.Equal(t, isASCIIWordChar('z'), true)
	assert.Equal(t, isASCIIWordChar('z'+1), false)
	assert.Equal(t, isASCIIWordChar('A'-1), false)
	assert.Equal(t, isASCIIWordChar('A'), true)
	assert.Equal(t, isASCIIWordChar('M'), true)
	assert.Equal(t, isASCIIWordChar('Z'), true)
	assert.Equal(t, isASCIIWordChar('Z'+1), false)
	assert.Equal(t, isASCIIWordChar('_'-1), false)
	assert.Equal(t, isASCIIWordChar('_'), true)
	assert.Equal(t, isASCIIWordChar('_'+1), false)

	assert.Equal(t, parseHexDigit('0'), uint16(0))
	assert.Equal(t, parseHexDigit('1'), uint16(1))
	assert.Equal(t, parseHexDigit('2'), uint16(2))
	assert.Equal(t, parseHexDigit('3'), uint16(3))
	assert.Equal(t, parseHexDigit('4'), uint16(4))
	assert.Equal(t, parseHexDigit('5'), uint16(5))
	assert.Equal(t, parseHexDigit('6'), uint16(6))
	assert.Equal(t, parseHexDigit('7'), uint16(7))
	assert.Equal(t, parseHexDigit('8'), uint16(8))
	assert.Equal(t, parseHexDigit('9'), uint16(9))
	assert.Equal(t, parseHexDigit('a'), uint16(10))
	assert.Equal(t, parseHexDigit('b'), uint16(11))
	assert.Equal(t, parseHexDigit('c'), uint16(12))
	assert.Equal(t, parseHexDigit('d'), uint16(13))
	assert.Equal(t, parseHexDigit('e'), uint16(14))
	assert.Equal(t, parseHexDigit('f'), uint16(15))
}

func TestCharSet(t *testing.T) {
	const (
		union = iota
		intersection
		subtraction
	)

	runChars := func(t *testing.T, name string, op int, cases [][3][]charRange) {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases {
				t.Run("", func(t *testing.T) {
					a := charSet{chars: c[0]}
					b := charSet{chars: c[1]}
					switch op {
					case union:
						a.union(&b)
					case intersection:
						a.intersection(&b)
					case subtraction:
						a.subtraction(&b)
					}
					expected := c[2]
					actual := a.chars
					assert.DeepEqual(t, expected, actual, cmp.AllowUnexported(charSet{}), cmp.AllowUnexported(charRange{}))
				})
			}
		})
	}
	runStrings := func(t *testing.T, name string, op int, cases [][3][]string) {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases {
				t.Run("", func(t *testing.T) {
					var (
						a charSet
						b charSet
					)
					if c[0] != nil {
						a.strings = stringSet{s: map[string]struct{}{}}
						for _, s := range c[0] {
							a.strings.s[s] = struct{}{}
						}
					}
					if c[1] != nil {
						b.strings = stringSet{s: map[string]struct{}{}}
						for _, s := range c[1] {
							b.strings.s[s] = struct{}{}
						}
					}
					switch op {
					case union:
						a.union(&b)
					case intersection:
						a.intersection(&b)
					case subtraction:
						a.subtraction(&b)
					}
					var expected map[string]struct{}
					if c[2] != nil {
						expected = map[string]struct{}{}
						for _, s := range c[2] {
							expected[s] = struct{}{}
						}
					}
					actual := a.strings.s
					assert.DeepEqual(t, expected, actual, cmp.AllowUnexported(charSet{}), cmp.AllowUnexported(charRange{}))
				})
			}
		})
	}

	t.Run("chars", func(t *testing.T) {
		runChars(t, "union", union, [][3][]charRange{
			{nil, nil, nil},
			{nil, {{1, 2}}, {{1, 2}}},
			{{{1, 2}}, nil, {{1, 2}}},
			{{{5, 10}}, {{5, 10}}, {{5, 10}}},
			{{{5, 10}}, {{6, 9}}, {{5, 10}}},
			{{{5, 10}}, {{6, 11}}, {{5, 11}}},
			{{{5, 10}}, {{4, 9}}, {{4, 10}}},
			{{{5, 10}}, {{4, 11}}, {{4, 11}}},
			{{}, {{1, 2}, {4, 4}}, {{1, 2}, {4, 4}}},
			{{{1, 2}, {4, 4}}, {}, {{1, 2}, {4, 4}}},
			{{{5, 10}}, {{10, 15}}, {{5, 15}}},
			{{{5, 10}}, {{11, 15}}, {{5, 15}}},
			{
				{{1, 3}, {10, 12}, {17, 17}},
				{{2, 4}, {13, 15}, {20, 20}},
				{{1, 4}, {10, 15}, {17, 17}, {20, 20}},
			},
			{{{10, 10}}, {{11, 11}}, {{10, 11}}},
			{{{5, 10}, {13, 15}}, {{11, 11}}, {{5, 11}, {13, 15}}},
			{{{5, 10}, {13, 15}}, {{12, 12}}, {{5, 10}, {12, 15}}},
			{{{5, 10}, {13, 15}}, {{11, 13}}, {{5, 15}}},
			{{{5, 10}, {12, 15}}, {{11, 11}}, {{5, 15}}},
		})

		runChars(t, "intersection", intersection, [][3][]charRange{
			{nil, nil, nil},
			{nil, {{1, 2}}, nil},
			{{{1, 2}}, nil, nil},
			{{{1, 2}}, {{1, 2}}, {{1, 2}}},
			{{{5, 10}}, {{6, 9}}, {{6, 9}}},
			{{{5, 10}}, {{6, 11}}, {{6, 10}}},
			{{{5, 10}}, {{4, 9}}, {{5, 9}}},
			{{{5, 10}}, {{4, 11}}, {{5, 10}}},
			{{{6, 8}}, {{1, 2}, {5, 7}}, {{6, 7}}},
			{{}, {}, {}},
			{{{1, 5}}, {}, {}},
			{{}, {{1, 5}}, {}},
			{{{1, 3}}, {{5, 7}}, {}},
			{{{5, 7}}, {{1, 3}}, {}},
			{{{1, 5}}, {{6, 10}}, {}},
			{{{1, 5}, {10, 15}}, {{3, 12}}, {{3, 5}, {10, 12}}},
			{{{5, 15}}, {{8, 10}}, {{8, 10}}},
			{{{8, 10}}, {{5, 15}}, {{8, 10}}},
			{{{1, 2}, {5, 6}}, {{1, 2}, {5, 6}}, {{1, 2}, {5, 6}}},
			{{{3, 12}}, {{1, 4}, {5, 7}, {10, 15}}, {{3, 4}, {5, 7}, {10, 12}}},
		})

		runChars(t, "subtraction", subtraction, [][3][]charRange{
			{nil, nil, nil},
			{nil, {{1, 2}}, nil},
			{{{1, 2}}, nil, {{1, 2}}},
			{{}, {{1, 2}}, {}},
			{{{1, 2}}, {{3, 5}}, {{1, 2}}},
			{{{1, 5}}, {{0, 1}}, {{2, 5}}},
			{{{1, 5}}, {{1, 1}}, {{2, 5}}},
			{{{1, 5}}, {{0, 2}}, {{3, 5}}},
			{{{1, 5}}, {{1, 2}}, {{3, 5}}},
			{{{1, 5}}, {{2, 3}}, {{1, 1}, {4, 5}}},
			{{{1, 5}}, {{2, 4}}, {{1, 1}, {5, 5}}},
			{{{1, 5}}, {{2, 5}}, {{1, 1}}},
			{{{1, 5}}, {{1, 5}}, {}},
			{{{1, 5}}, {{0, 6}}, {}},
			{{{1, 5}}, {{4, 6}}, {{1, 3}}},
			{{{1, 5}}, {{4, 5}}, {{1, 3}}},
			{{{1, 5}}, {{5, 5}}, {{1, 4}}},
			{{{3, 3}}, {{1, 2}}, {{3, 3}}},
			{{{3, 3}}, {{1, 1}, {2, 2}}, {{3, 3}}},
			{{{3, 3}, {6, 7}}, {{4, 5}}, {{3, 3}, {6, 7}}},
		})

		t.Run("contains", func(t *testing.T) {
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}}}).containsRune(3), false)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}}}).containsRune(1), true)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}, {4, 4}, {6, 7}}}).containsRune(4), true)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}, {4, 4}, {6, 7}}}).containsRune(1), true)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}, {4, 4}, {6, 7}}}).containsRune(6), true)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}, {4, 4}, {6, 7}}}).containsRune(5), false)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}, {4, 4}, {6, 7}}}).containsRune(3), false)
			assert.Equal(t, (&charSet{chars: []charRange{{1, 2}, {4, 4}, {6, 7}, {9, 10}}}).containsRune(10), true)
		})

		t.Run("complement", func(t *testing.T) {
			cases := [][2][]charRange{
				{nil, {{0, 0x10ffff}}},
				{{}, {{0, 0x10ffff}}},
				{{{5, 5}}, {{0, 4}, {6, 0x10ffff}}},
				{{{3, 5}, {8, 9}}, {{0, 2}, {6, 7}, {10, 0x10ffff}}},
				{{{3, 5}, {8, 9}, {12, 15}}, {{0, 2}, {6, 7}, {10, 11}, {16, 0x10ffff}}},
				{{{0, 5}, {8, 9}, {12, 15}}, {{6, 7}, {10, 11}, {16, 0x10ffff}}},
				{{{0, 5}, {8, 9}, {12, 0x10ffff}}, {{6, 7}, {10, 11}}},
				{{{3, 5}, {8, 9}, {12, 0x10ffff}}, {{0, 2}, {6, 7}, {10, 11}}},
			}

			for _, c := range cases {
				t.Run("", func(t *testing.T) {
					s := &charSet{chars: c[0]}
					s.complement()
					expected := c[1]
					actual := s.chars
					assert.DeepEqual(t, expected, actual, cmp.AllowUnexported(charRange{}))
				})
			}
		})

		t.Run("maybeSimpleCaseFolding", func(t *testing.T) {
			run := func(input, expected []charRange) {
				t.Run("", func(t *testing.T) {
					assert.DeepEqual(t, (&charSet{chars: input}).maybeSimpleCaseFolding(FlagUnicodeSets|FlagIgnoreCase).chars, expected, cmp.AllowUnexported(charRange{}))
				})
			}

			run([]charRange{{'Ā', 'č'}}, []charRange{{'Ā' + 1, 'Ā' + 1}, {259, 259}, {261, 261}, {263, 263}, {265, 265}, {267, 267}, {'č', 'č'}})
		})

		t.Run("unionChar", func(t *testing.T) {
			cases := []struct {
				base     []charRange
				char     rune
				expected []charRange
			}{
				{nil, 'a', []charRange{{0x61, 0x61}}},
				{[]charRange{}, 'a', []charRange{{0x61, 0x61}}},
				{[]charRange{{5, 10}, {15, 20}}, 7, []charRange{{5, 10}, {15, 20}}},
				{[]charRange{{5, 10}, {15, 20}}, 12, []charRange{{5, 10}, {12, 12}, {15, 20}}},
				{[]charRange{{5, 10}, {15, 20}}, 11, []charRange{{5, 11}, {15, 20}}},
				{[]charRange{{5, 10}, {15, 20}}, 14, []charRange{{5, 10}, {14, 20}}},
				{[]charRange{{5, 10}, {12, 20}}, 11, []charRange{{5, 20}}},
				{[]charRange{{5, 10}, {15, 20}}, 25, []charRange{{5, 10}, {15, 20}, {25, 25}}},
				{[]charRange{{5, 5}}, 1, []charRange{{1, 1}, {5, 5}}},
				{[]charRange{{5, 5}}, 4, []charRange{{4, 5}}},
			}

			for _, c := range cases {
				t.Run("", func(t *testing.T) {
					set := &charSet{chars: c.base}
					set.unionChar(c.char)
					expected := c.expected
					actual := set.chars
					assert.DeepEqual(t, expected, actual, cmp.AllowUnexported(charRange{}))
				})
			}
		})
	})

	t.Run("strings", func(t *testing.T) {
		runStrings(t, "union", union, [][3][]string{
			{nil, nil, nil},
			{nil, {"b"}, {"b"}},
			{{"b"}, nil, {"b"}},
			{{}, {"b"}, {"b"}},
			{{"a"}, {}, {"a"}},
			{{"a"}, {"b"}, {"a", "b"}},
		})

		runStrings(t, "intersection", intersection, [][3][]string{
			{nil, nil, nil},
			{nil, {"b"}, nil},
			{{"b"}, nil, nil},
			{{}, {}, {}},
			{{}, {"b"}, {}},
			{{"a"}, {}, {}},
			{{"a"}, {"b"}, {}},
			{{"a", "b"}, {"b"}, {"b"}},
			{{"a", "b"}, {"b", "c"}, {"b"}},
			{{"a", "b", "c"}, {"b", "c"}, {"b", "c"}},
		})

		runStrings(t, "subtraction", subtraction, [][3][]string{
			{nil, nil, nil},
			{nil, {"b"}, nil},
			{{"b"}, nil, {"b"}},
			{{"b"}, {}, {"b"}},
			{{"b"}, {"c"}, {"b"}},
			{{"b", "c"}, {"c"}, {"b"}},
			{{"b", "c"}, {"c", "b"}, {}},
		})

		t.Run("fold", func(t *testing.T) {
			s := charSet{strings: stringSet{s: map[string]struct{}{}}}
			s = s.fold(func(c rune) rune { return c })
			assert.Equal(t, s.strings.minlen, 0)
			assert.Equal(t, s.strings.maxlen, 0)
		})
	})
}

func TestBasicQuantifiers(t *testing.T) {
	r := newRunner(t)

	r.m("...", "foo")
	r.m("f.o", "foo")
	r.m("foo", "foo")
	r.n("bar", "foo")

	r.n(".", "\n")
	r.n(".", "\r")
	r.n(".", "\u2028")
	r.n(".", "\u2029")
	r.f(s).m(".", "\n")
	r.f(s).m(".", "\r")
	r.f(s).m(".", "\u2028")
	r.f(s).m(".", "\u2029")

	r.f(i).m("a", "A")
	r.f(i).m("A", "a")
	r.f(i).m("a", "a")
	r.f(i).m("A", "A")
	r.f(v|i).m("a", "A")
	r.f(v|i).m("A", "a")
	r.f(v|i).m("a", "a")
	r.f(v|i).m("A", "A")
	r.f(u|i).m("a", "A")
	r.f(u|i).m("A", "a")
	r.f(u|i).m("a", "a")
	r.f(u|i).m("A", "A")

	r.f(i).n16s(omh, capOmega)
	r.f(i).n16s(omh, smallOmega)

	r.f(i).m("(ð)", "Ð", "Ð")
	r.f(i).m("(Ð)", "ð", "ð")
	r.n("(ð)", "Ð")
	r.n("(Ð)", "ð")
	r.f(i).m("(ｙ)", "Ｙ", "Ｙ")
	r.f(i).m("(Ｙ)", "ｙ", "ｙ")
	r.n("(ｙ)", "Ｙ")
	r.n("(Ｙ)", "ｙ")
	r.f(u|i).m("(\U00016e7c)", "\U00016e5c", "\U00016e5c")
	r.f(v|i).m("(\U00010400)", "\U00010428", "\U00010428")

	// SpecialCasing.txt unconditional one-to-many mapping
	r.f(u|i).n("ﬀ", "ff")
	r.f(u|i).n("ﬀ", "FF")
	r.f(u|i).n("ff", "ﬀ")
	r.f(u|i).n("FF", "ﬀ")
	// SpecialCasing.txt language-sensitive mapping
	r.f(u|i).n("İ", "i")
	r.f(u|i).n("i", "İ")

	// Uppercase_Mapping maps omh sign to itself
	// Uppercase_Mapping maps small omega to cap omega
	// Uppercase_Mapping maps cap omega to cap omega
	// CaseFolding.txt maps omh sign to small omega
	// CaseFolding.txt maps small omega to small omega
	// CaseFolding.txt maps cap omega to small omega
	r.f(u|i).m("("+smallOmega+")", omh, omh)
	r.f(u|i).m("("+capOmega+")", omh, omh)
	r.f(i).n16s("("+smallOmega+")", omh)
	r.f(i).n16s("("+capOmega+")", omh)

	r.m("(.)", "§", "§")

	r.m("(foo|bar)", "foo", "foo")
	r.m("(foo)|(bar)", "foo", "foo", nilMatch)
	r.m("(foo)|(bar)", "bar", nilMatch, "bar")
	r.m("((foo)|(bar))", "foo", "foo", "foo", nilMatch)

	r.m("(a|)", "a", "a")
	r.m("(a||)", "a", "a")
	r.m("(|a)", "a", "")
	r.m("(|a|)", "a", "")
	r.m("(||a)", "a", "")

	r.m("(foo)", "foo", "foo")
	r.m("(foo)bar", "foobar", "foo")
	r.m("foo(bar)", "foobar", "bar")
	r.m("(foo)(bar)", "foobar", "foo", "bar")

	r.m("a+", "a")
	r.m("a+", "aaa")
	r.m("(a)+", "aaa", "a")
	r.m("(a|b+)", "abb", "a")
	r.m("(a|b+)", "bbb", "bbb")
	r.m("(a|b)+", "aba", "a")
	r.m("(a|b)+", "bab", "b")
	r.m("(a+)*", "a", "a")
	r.m("(a+)*", "b", nilMatch)
	r.m("(a*)+", "a", "a")
	r.m("(a*)+", "b", "")

	r.m("a*", "a")
	r.m("a*", "aa")
	r.m("(a)*", "aa", "a")
	r.m("(a*)", "aa", "aa")
	r.m("(a*)(a)", "aaa", "aa", "a")
	r.m("(a|b)*", "aba", "a")
	r.m("(a|b)*a", "aba", "b")
	r.m("(aa|aabaac|ba|b|c)*", "aabaac", "ba")
	r.m("(a*)*", "a", "a")

	r.m("(a?)(a)", "a", "", "a")
	r.m("a?b", "b")
	r.m("(a?)b", "b", "")
	r.m("(a)?b", "b", nilMatch)
	r.m("a?b", "ab")
	r.m("(a)?b", "ab", "a")
	r.m("(a?)b", "ab", "a")
	r.m("(a|b)?b", "ab", "a")
	r.m("(a|b)?b", "bb", "b")
	r.m("(a?)?", "a", "a")

	r.m("(a{0,2})", "a", "a")
	r.m("(a{0,2})(b?)", "ae", "a", "")
	r.m("(a{0,2})(b{0,2})", "ae", "a", "")
	r.m("(a{0,2})(b{0,2})", "be", "", "b")
	r.m("(a{0,1})", "aa", "a")
	r.m("(a{0,2})", "aa", "aa")
	r.m("(a{0,2})", "aaa", "aa")
	r.m("(a{000,002})", "aaa", "aa")
	r.m("((a|b){0,3})", "ababa", "aba", "a")

	r.m("(a{0,9223372036854775806})", "a", "a")
	r.m("(a{0,9223372036854775807})", "a", "a") // math.MaxInt
	r.m("(a{0,9223372036854775808})", "a", "a")
	r.m("(a{0,92233720368547758089999999})", "a", "a")

	r.m("(a{0,99999}){0,99999}", "a", "a")
	r.m("(a{0,99999})*", "a", "a")
	r.m("(a*){0,99999}", "a", "a")

	r.m("(a{1,2})", "a", "a")
	r.m("(a{1,2})", "aa", "aa")
	r.m("(a{1,2})", "aaa", "aa")
	r.m("(a{001,002})", "aaa", "aa")
	r.m("(a{1,2})(a)", "aa", "a", "a")
	r.m("(a{1,2})(a?)", "aa", "aa", "")
	r.m("((a|b){1,3})", "ababa", "aba", "a")

	r.m("(a{1,99999}){0,99999}", "a", "a")
	r.m("(a{1,99999})*", "a", "a")
	r.m("(a*){1,99999}", "a", "a")
	r.m("(a{1,99999}){1,99999}", "aa", "aa")
	r.m("(a{1,2}){1,2}", "aa", "aa")
	r.m("((a{1,1}){1,2})", "aa", "aa", "a")

	r.m("(a{2,3})", "aa", "aa")
	r.m("(a{2,3})", "aaa", "aaa")
	r.m("(a{2,3})", "aaaa", "aaa")
	r.m("(a{2,4})", "aaaa", "aaaa")
	r.m("(a{2,4})(a)", "aaaa", "aaa", "a")
	r.m("(a{2,4})(a{1,2})", "aaaa", "aaa", "a")
	r.m("(a{2,4})(a{2,2})", "aaaa", "aa", "aa")
	r.m("(a{002,003})", "aaaa", "aaa")
	r.m("((foo){2,3})", "foofoofoofoo", "foofoofoo", "foo")

	r.m("(a*){1,99999}", "a", "a")
	r.m("(a*){2,99999}", "a", "")
	r.m("(a{1,99999})*", "a", "a")
	r.m("(a{2,99999})*", "a", nilMatch)

	r.m("(0){0}", "a", nilMatch)
	r.m("(0){0}", "0", nilMatch)
	r.m("(a)|(0){0}", "a", "a", nilMatch)
	r.m("(a)|(0){0}", "0", nilMatch, nilMatch)
	r.m("(0){0}|(a)", "a", nilMatch, nilMatch)
	r.m("(0){0}|(a)", "0", nilMatch, nilMatch)

	r.m("((a+)?(b+)?(c))*", "a", nilMatch, nilMatch, nilMatch, nilMatch)
	r.m("((a+)?(b+)?(c))*", "ac", "ac", "a", nilMatch, "c")
	r.m("(z)((a+)?(b+)?(c))*", "zaacbbb", "z", "aac", "aa", nilMatch, "c")
	r.m("(z)((a+)?(b+)?(c))*", "zaacbbbc", "z", "bbbc", nilMatch, "bbb", "c")
	r.m("((a)|(b)){2}", "ab", "b", nilMatch, "b")
	r.m("((a)|(b)){2,3}", "aab", "b", nilMatch, "b")
	r.m("((a)|(b)){1,2}", "ab", "b", nilMatch, "b")
	r.m("((a)|(b)){1,2}?b$", "abb", "b", nilMatch, "b")

	r.m("(a??)", "a", "")
	r.m("(a??)(a)", "a", "", "a")
	r.m("(a??)(a)", "aa", "", "a")
	r.m("(a??)*", "a", "a")
	r.m("(a??)*(a)", "a", nilMatch, "a")
	r.m("(a??)*(a)", "aa", "a", "a")

	r.m("(a*?)", "a", "")
	r.m("(a*?)", "a", "")
	r.m("(a*?)*", "a", "a")
	r.m("(a*?)*", "aa", "a")
	r.m("(a*?)*?", "a", nilMatch)
	r.m("(b+)*?", "a", nilMatch)
	r.m("(b*?)+", "a", "")

	r.m("(a{0,5}?)", "a", "")
	r.m("(a{0,5}?)", "a", "")
	r.m("(a{0,5}?)*", "a", "a")
	r.m("(a{0,5}?)*", "aa", "a")
	r.m("(a{0,5}?)*?", "a", nilMatch)
	r.m("(b+)*?", "a", nilMatch)
	r.m("(b{0,5}?)+", "a", "")

	r.m("(a*?){0,5}", "a", "a")
	r.m("(a*?){0,5}", "aa", "a")
	r.m("(a*?){0,5}?", "a", nilMatch)
	r.m("(b+){0,5}?", "a", nilMatch)

	r.m("(a{0,5}?){0,5}", "a", "a")
	r.m("(a{0,5}?){0,5}", "aa", "a")
	r.m("(a{0,5}?){0,5}?", "a", nilMatch)

	r.m("(a+?)", "a", "a")
	r.m("(a+?)", "aa", "a")
	r.m("(a+?)*", "aa", "a")
	r.m("((a+?)*)", "aa", "aa", "a")
	r.m("((a+?)+)", "aa", "aa", "a")

	r.m("(a{1,5}?)", "a", "a")
	r.m("(a{1,5}?)", "aa", "a")
	r.m("(a{1,5}?)*", "aa", "a")
	r.m("((a{1,5}?)*)", "aa", "aa", "a")
	r.m("((a{1,5}?)+)", "aa", "aa", "a")

	r.m("((a{1,5}?)*?)", "aa", "", nilMatch)
	r.m("((a{1,5}?)+?)", "aa", "a", "a")

	r.m("(a{2,5}?)", "aa", "aa")
	r.m("(a{2,5}?)", "aaa", "aa")
	r.m("(a{2,5}?)*", "aaa", "aa")
	r.m("((a{2,5}?)*)", "aaaa", "aaaa", "aa")
	r.m("((a{2,5}?)*)", "aaaaa", "aaaa", "aa")

	r.m("(a{2,})", "aa", "aa")
	r.m("(a{2,})", "aaa", "aaa")
	r.n("(a{2,})", "a")

	r.m("a(b{2})", "abbb", "bb")

	r.se("a{5,4}")

	r.se("{2}")
	r.se("{2,}")
	r.se("{2,3}")
	r.noNode().se("{")
	r.noNode().se("}")
	r.noNode().se("a{a")
	r.noNode().se("a{2")
	r.noNode().se("a{2,,}")
	r.noNode().se("a{2,a}")
	r.noNode().se("a{2,2")

	r.se("?")
	r.se("*")
	r.se("+")
	r.se(".*??")
	r.se(".+*")
	r.se(".*+")

	r.se(`(`)
	r.se(`(?`)
	r.se(`)`)
}

func TestAnnexB(t *testing.T) {
	r := newRunner(t).noNode()
	// TODO: run with annexB=false when B() is called (it's expected to throw)
	b := newRunner(t).f(b)

	b.m16s(`\0`, "\x00")
	b.m16s(`\01`, "\x01")
	r.se(`\01`)
	b.m16s(`\02`, "\x02")
	b.m16s(`\03`, "\x03")
	b.m16s(`\04`, "\x04")
	b.m16s(`\05`, "\x05")
	b.m16s(`\06`, "\x06")
	b.m16s(`\07`, "\x07")
	b.m16s(`\08`, "\x008")
	r.se(`\08`)
	b.m16s(`\09`, "\x009")
	b.m16s(`\1`, "\x01")
	b.m16s(`\2`, "\x02")
	b.m16s(`\3`, "\x03")
	b.m16s(`\18`, "\x018")
	b.m16s(`\19`, "\x019")
	b.m16s(`\1a`, "\x01a")
	b.m16s(`\11`, "\x09")
	b.m16s(`\37`, "\x1f")
	b.m16s(`\258`, "\x158")
	b.m16s(`\157`, "\x6f")
	b.m16s(`\377`, "\u00ff")
	b.m16s(`\4`, "\x04")
	b.m16s(`\5`, "\x05")
	b.m16s(`\6`, "\x06")
	b.m16s(`\7`, "\x07")
	b.m16s(`\48`, "\x048")
	b.m16s(`\57`, "\x2f")
	b.m16s(`\611`, "\x311")
	b.m16s(`\70`, "\x38")
	b.m16s(`(?<=\1(a))d`, "aad", "a")
	b.n16s(`(?<=\1(?:a))d`, "aad")
	b.mg(`(?<=\1(?<b>a))d`, "aad", gr{"b": "a"}, "a")
	b.m16s(`\1.(?<=a)d`, "\x01ad")
	b.m16s(`\1.(?<!a)d`, "\x01bd")
	b.se(`\1(`)
	b.m16s(`\1\(`, "\x01(")
	b.m16s(`\1\(`, "\x01(")
	b.m16s(`\1`, "\x01(")
	b.m16s(`\1[(]`, "\x01(")
	b.m16s(`^\1[\](]$`, "\x01]")
	b.m16s(`(a)\1`, "aa", "a")
	b.m16s(`(a)\2`, "a\x02", "a")
	b.m16s(`(?:a)\1`, "a\x01")
	b.m16s(`[\01-\05]`, "\x01")
	b.m16s(`[\01-\05]`, "\x03")
	b.m16s(`[\01-\05]`, "\x05")
	b.n16s(`[\3-\05]`, "\x02")
	b.m16s(`[\3-\05]`, "\x05")
	b.se(`[\37-\05]`)
	b.m16s(`[\48]`, "\x04")
	b.m16s(`[\48]`, "8")

	r.f(u).se(`\1`)
	r.f(u).se(`\2`)
	r.f(u).se(`\3`)
	r.f(u).se(`\34`)
	r.f(u).se(`\4`)
	r.f(u).se(`\5`)
	r.f(u).se(`\6`)
	r.f(u).se(`\7`)
	r.f(u).se(`\8`)
	r.f(u).se(`\9`)
	r.f(u).se(`[\1]`)
	r.f(u).se(`[\2]`)
	r.f(u).se(`[\3]`)
	r.f(u).se(`[\4]`)
	r.f(u).se(`[\5]`)
	r.f(u).se(`[\6]`)
	r.f(u).se(`[\7]`)
	r.f(u).se(`[\8]`)
	r.f(u).se(`[\9]`)

	b.m16s(`\c`, "\\c")
	b.m16s(`\c0`, "\\c0")
	b.m16s(`\c"`, "\\c\"")
	b.m16s(`\ca`, "\x01")
	b.m16s(`\cZ`, "\x1a")
	b.m16s(`[\c]`, "\\")
	b.m16s(`[\c]`, "c")
	b.se(`[\c-a]`)
	b.m16s(`[\c-e]`, "\\")
	b.m16s(`[\c-e]`, "c")
	b.m16s(`[\c-e]`, "d")
	b.m16s(`[\c-e]`, "e")
	b.n16s(`[\c-e]`, "f")
	b.se(`[e-\c]`)
	b.m16s(`[Z-\c]`, "[")
	b.m16s(`[Z-\c]`, "c")
	b.m16s(`[Z-\c]`, "\\")
	b.m16s(`[\ca]`, "\x01")
	b.m16s(`[\c0]`, "\x10")
	b.m16s(`[\c5]`, "\x15")
	b.m16s(`[\c9]`, "\x19")
	b.m16s(`[\c_]`, "\x1f")

	b.m16s(`\_`, "_") // unicode ID_Continue
	b.m16s(`\^`, "^")
	b.m16s(`\+`, "+")
	b.m16s(`\}`, "}")
	b.m16s(`\a`, "a")
	b.m16s(`\x`, "x")
	b.m16s(`\x0`, "x0")
	b.m16s(`\xq`, "xq")
	b.m16s(`\x0q`, "x0q")
	b.m16s(`\xaa`, "\u00aa")

	b.m16s(`\u`, "u")
	b.m16s(`\u000`, "u000")
	b.m16s(`\u0001`, "\u0001")
	b.m16s(`^\u{1}$`, "u")
	b.m16s(`^\u{2}$`, "uu")
	b.m16s(`\u1000`, "\u1000")
	b.m16s(`\u10q0`, "u10q0")
	b.m16s(`[\u10q0-3]`, "u")
	b.m16s(`[\u10q0-3]`, "1")
	b.m16s(`[\u10q0-3]`, "0")
	b.m16s(`[\u10q0-3]`, "q")
	b.m16s(`[\u10q0-3]`, "2")
	b.m16s(`[r-\u10q0]`, "t")
	b.m16s(`[r-\u10q0]`, "q")
	b.m16s(`[r-\u1000]`, "\u0999")

	b.m16s(`\k<a>`, "k<a>")
	b.m16s(`\k`, "k")
	b.se(`\k<a>(?<b>)`)
	b.se(`(?<b>)\k<a>`)
	b.se(`(?<a>)\k`)
	b.mg(`(?<a>a)\k<a>`, "aa", gr{"a": "a"}, "a")

	b.m16s(`[\s-\d]`, " ")
	b.m16s(`[\s-\d]`, "0")
	b.m16s(`[\s-\d]`, "-")
	b.m16s(`[a-\d]`, "a")
	b.m16s(`[a-\d]`, "0")
	b.m16s(`[a-\d]`, "-")
	b.m16s(`[\s-a]`, " ")
	b.m16s(`[\s-a]`, "a")
	b.m16s(`[\s-a]`, "-")
	b.m16s(`[\-]`, "-")
	b.n16s(`[\-]`, "\\")

	b.m16s(`a{`, "a{")
	b.n16s(`a{`, "a}")
	b.m16s(`a{1`, "a{1")
	b.m16s(`a{1a`, "a{1a")
	b.m16s(`a{,`, "a{,")
	b.m16s(`a{1,`, "a{1,")
	b.m16s(`a{1,a`, "a{1,a")
	b.m16s(`a{1,1`, "a{1,1")
	b.n16s(`a{1,1`, "a}1,1")
	b.m16s(`a{1,1a`, "a{1,1a")
	b.m16s(`a{1,1a}`, "a{1,1a}")
	b.n16s(`a{1,1a}`, "a{1,1a{")
	b.m16s(`{`, "{")
	b.n16s(`{`, "}")
	b.m16s(`{1`, "{1")
	b.m16s(`{1a`, "{1a")
	b.m16s(`{,`, "{,")
	b.m16s(`{1,`, "{1,")
	b.m16s(`{1,a`, "{1,a")
	b.m16s(`{1,1`, "{1,1")
	b.m16s(`{1,1a`, "{1,1a")
	b.m16s(`{1,1a}`, "{1,1a}")
	b.se(`{1,1}`)
	b.se(`{1,}`)
	b.se(`{1}`)
	b.m16s(`(?<={)a`, "{a")
	b.m16s(`(?<={1)a`, "{1a")
	b.m16s(`(?<=e{)a`, "e{a")
	b.m16s(`(?<=e{1)a`, "e{1a")
	b.m16s(`(?<=})a`, "}a")

	b.m16s(`]`, "]")
	b.n16s(`]`, "[")
	b.m16s(`[ab]]`, "a]")
	b.m16s(`(?<=])a`, "]a")

	b.se(`*`)
	b.se(`+`)
	b.se(`?`)

	b.m16s(`\p`, `\p`)
	b.f(i).m16s(`\p`, `\p`)
	b.f(i).m16s(`\p`, `\P`)
	b.m16s(`\P`, `\P`)
	b.f(i).m16s(`\P`, `\p`)
	b.f(i).m16s(`\P`, `\P`)
	b.m16s(`\p{ASCII}`, "p{ASCII}")
	b.m16s(`\P{Basic_Emoji}`, "P{Basic_Emoji}")
}

func TestNamedGroups(t *testing.T) {
	r := newRunner(t)

	r.mg("(?<a>b)", "b", gr{"a": "b"}, "b")
	r.se("(?<>b)")
	r.se("(?<>b)")
	r.se("(?<")
	r.se("(?<a>a")
	r.se("(?a")
	r.se("(?<\n>)")
	r.se(`(?<\n>)`)
	r.se(`(?<\x00>)`)
	r.se(`(?<\0>)`)
	r.se("(?<a>b)(?<a>b)")

	r.mg(`(?<a>b)(\k<a>)`, "bb", gr{"a": "b"}, "b", "b")
	r.mg(`(?<a>b)a(?<b>\k<a>{2})a(\k<b>{3})`, "babbabbbbbb", gr{"a": "b", "b": "bb"}, "b", "bb", "bbbbbb")
	r.mg(`(?<a>\k<a>)`, "foo", gr{"a": ""}, "")
	r.mg(`(?<a>\k<b>)(?<b>foo)`, "foo", gr{"a": "", "b": "foo"}, "", "foo")
	r.mg(`(?<a>\k<b>)(?<b>\k<a>)`, "foo", gr{"a": "", "b": ""}, "", "")

	r.mg(`(?<=(\k<a>{2})(?<a>b))c`, "abbbc", gr{"a": "b"}, "bb", "b")

	r.mg("(?<a1>a)", "a", gr{"a1": "a"}, "a")
	r.se("(?<1a>a)")
	r.se("(?<a >a)")
	r.mg(`(?<a1>a)\k<a1>`, "aa", gr{"a1": "a"}, "a")
	r.noNode().se(`\k<1a>`)
	r.noNode().se(`\k<a >`)
	r.noNode().se(`\k`)
	r.noNode().se(`\k<`)
	r.noNode().se(`\k<a`)
	r.noNode().se(`\k<a>`)
	r.f(u).se(`\k<a>`)
	r.se(`(?<b>)\k<a>`)

	r.se(`(?<x>)(?<x>)`)
	r.n(`(?<x>a)|(?<x>b)`, "c")
	r.se(`(?<x>)((?<y>)|(?<x>))`)
	r.se(`(?<x>)((?<x>)|(?<y>))`)
	r.se(`((?<x>))((?<y>)|(?<x>))`)
	r.se(`((?<a>)|(?<x>))((?<y>)|(?<x>))`)

	r.mg(`(?:(?<x>a)|(?<x>b))(\k<x>)`, "aa", gr{"x": "a"}, "a", nilMatch, "a")
	r.n(`(?:(?<x>a)|(?<x>b))(\k<x>)`, "ab")
	r.n(`(?:(?<x>a)|(?<x>b))(\k<x>)`, "ba")
	r.mg(`(?:(?<x>a)|(?<x>b))(\k<x>)`, "bb", gr{"x": "b"}, nilMatch, "b", "b")
	r.mg(`(?:(?<x>b)|(?<x>a))(\k<x>)`, "aa", gr{"x": "a"}, nilMatch, "a", "a")
	r.n(`(?:(?<x>b)|(?<x>a))(\k<x>)`, "ab")
	r.n(`(?:(?<x>b)|(?<x>a))(\k<x>)`, "ba")
	r.mg(`(?:(?<x>b)|(?<x>a))(\k<x>)`, "bb", gr{"x": "b"}, "b", nilMatch, "b")
	r.mg(`(?:(?:(?<x>a)|(?<x>b))(\k<x>)){2}`, "aabb", gr{"x": "b"}, nilMatch, "b", "b")
	r.mg(`(?:(?:(?<x>b)|(?<x>a))(\k<x>)){2}`, "aabb", gr{"x": "b"}, "b", nilMatch, "b")

	r.mg(`(?:(?<a>a)|(?<b>b)){2}`, "ab", gr{"a": nilMatch, "b": "b"}, nilMatch, "b")

	r.mg16(u16e("a(?<high>.)(?<low>.)b"), u16e("a🐱b"), gr16{"high": []uint16{catHN}, "low": []uint16{catLN}}, []uint16{catHN}, []uint16{catLN})
	r.mg16(u16e("(?<a>.)(?<b>..)(?<c>..)(?<d>.)"), u16e("🐱🐱🐱"), gr16{"a": []uint16{catHN}, "b": []uint16{catLN, catHN}, "c": []uint16{catLN, catHN}, "d": []uint16{catLN}}, []uint16{catHN}, []uint16{catLN, catHN}, []uint16{catLN, catHN}, []uint16{catLN})
	r.mg16([]uint16{'(', '?', '<', ahsaHN, ahsaLN, '>', 'a', ')'}, []uint16{'a'}, gr16{"𐌰": []uint16{'a'}}, []uint16{'a'})
	r.se16([]uint16{'(', '?', '<', +catHN, catLN, '>', 'a', ')'})
	r.se16([]uint16{'(', '?', '<', ahsaHN, '>', 'a', ')'})
	r.se16([]uint16{'(', '?', '<', ahsaLN, '>', 'a', ')'})
	r.se("(?<🐱>a)")
	r.f(u).mg16([]uint16{'(', '?', '<', ahsaHN, ahsaLN, '>', 'a', ')'}, u16e("a"), gr16{"𐌰": u16e("a")}, u16e("a"))
	r.f(u).se16([]uint16{'(', '?', '<', catHN, catLN, '>', 'a', ')'})
	r.f(u).se16([]uint16{'(', '?', '<', ahsaHN, '>', 'a', ')'})
	r.f(v).mg16([]uint16{'(', '?', '<', ahsaHN, ahsaLN, '>', 'a', ')'}, u16e("a"), gr16{"𐌰": u16e("a")}, u16e("a"))
	r.f(v).se16([]uint16{'(', '?', '<', catHN, catLN, '>', 'a', ')'})
	r.f(v).se16([]uint16{'(', '?', '<', ahsaHN, '>', 'a', ')'})
	r.f(v).se("(?<🐱>a)")

	r.mg(`(?<\u`+ahsaHX+`\u`+ahsaLX+`>a)`, "a", gr{"𐌰": "a"}, "a")
	r.mg(`(?<\u`+ahsaHXU+`\u`+ahsaLXU+`>a)`, "a", gr{"𐌰": "a"}, "a")
	r.se(`(?<\u` + catHX + `\u` + catLX + `>a)`)
	r.se(`(?<\u` + catHXU + `\u` + catLXU + `>a)`)
	r.mg(`(?<\u0066\u006f\u006f>a)`, "a", gr{"foo": "a"}, "a")
	r.mg(`(?<\u{66}\u{006f}\u{06f}>a)`, "a", gr{"foo": "a"}, "a")
	r.se(`(?<\u66\u6f\u6f>a)`)
	r.se(`(?<\u003e>a)`) // U+003E '>'
	r.se(`(?<\U` + ahsaHX + `\U` + ahsaLX + `>a)`)
	r.se(`(?<\U` + ahsaHXU + `\U` + ahsaLXU + `>a)`)
	r.se(`(?<\U` + catHX + `\U` + catLX + `>a)`)
	r.se(`(?<\U` + catHXU + `\U` + catLXU + `>a)`)
	r.se(`(?<\uaaa>a)`)
	r.se(`(?<\uaa>a)`)
	r.se(`(?<\ua>a)`)
	r.se(`(?<\u>a)`)
	r.se(`(?<\>a)`)
	r.se(`(?<\uaaag>a)`)
	r.se(`(?<\uaaga>a)`)
	r.se(`(?<\uagaa>a)`)
	r.se(`(?<\ugaaa>a)`)

	r.mg(`(?<\u{41}>a)`, "a", gr{"A": "a"}, "a")
	r.mg(`(?<\u{41}>a)`, "a", gr{"A": "a"}, "a")
	r.mg(`(?<\u`+ahsaHX+`\u`+ahsaLX+">a)", "a", gr{"𐌰": "a"}, "a")
	r.se(`(?<\u{` + ahsaHX + `}\u{` + ahsaLX + "}>a)")
	r.se(`(?<\u{` + ahsaHX + `}>a)`)
	r.se(`(?<\u{` + ahsaLX + `}>a)`)
	r.se(`(?<\u` + ahsaHX + `>a)`)
	r.se(`(?<\u` + ahsaLX + `>a)`)
	r.se(`(?<\u` + ahsaHX + `a>a)`)
	r.se(`(?<\u` + ahsaLX + `a>a)`)
	r.mg(`(?<\u{`+ahsaX+`}>a)`, "a", gr{"𐌰": "a"}, "a")
	r.se(`(?<\u{` + catX + `}>a)`)
	r.mg(`(?<b\u{`+ahsaX+`}b>a)`, "a", gr{"b𐌰b": "a"}, "a")
	r.mg(`(?<\u{00000000000000`+ahsaX+`}>a)`, "a", gr{"𐌰": "a"}, "a")
	r.se(`(?<\u{11000}>a)`)
	r.se(`(?<\u{1ffff}>a)`)
	r.se(`(?<\u{1x}>a)`)
	r.se(`(?<\u{1_a}>a)`)
	r.mg(`(?<\u{`+ahsaX+`}>a)(\k<\u`+ahsaHX+`\u`+ahsaLX+`>)`, "aa", gr{"𐌰": "a"}, "a", "a")
}

func TestModifiers(t *testing.T) {
	r := newRunner(t)

	r.se("(?a)")
	r.se("(?|a)")
	r.m("(?:a)", "a")
	r.se("(?-:a)")
	r.se("(?i")
	r.se(`(?:`)
	r.se(`(?)`)
	r.se(`(?:[b-a])`)
	r.se("(?ii:a)")
	r.se("(?imi:a)")
	r.se("(?i-i:a)")
	r.se("(?mi-is:a)")
	r.se("(?im-si:a)")
	r.se("(?im-msi:a)")
	r.se("(?im-m;si:a)")
	r.se("(?i--m:a)")
	r.se("(?i-m-:a)")
	r.se("(?g:a)")
	r.se("(?i-g:a)")
	r.se("(?-g:a)")
	r.m("(?i:A)", "a")
	r.f(i).n("(?-i:A)", "a")
	r.f(i|m).n("(?m-i:A)", "a")
	r.f(i|m).m("(?mi-:A)", "a")
	r.m("(?i:A(?-i:A))", "AA")
	r.m("(?i:A(?-i:A))", "aA")
	r.n("(?i:A(?-i:A))", "aa")
}

func TestBasicAssertions(t *testing.T) {
	r := newRunner(t)

	r.m("(a)", "ba", "a")
	r.m("(a)", "cba", "a")
	r.m("(^a)", "a", "a")
	r.m("^(a)", "a", "a")
	r.n("^a", "ba")
	r.m("(a$)", "a", "a")
	r.m("(a)$", "a", "a")
	r.m("(^a$)", "a", "a")
	r.m("^(a$)", "a", "a")
	r.m("^(a)$", "a", "a")
	r.f(m).m("^a", "a")
	r.f(m).m("^a", "b\na")
	r.f(m).m("^a", "b\u2028a")
	r.f(m).m("^a", "b\u2029a")
	r.f(m).n("(.^a)", "b\na")
	r.f(m|s).m("(.^a)", "b\na", "\na")
	r.f(m).n(".^.", "\n🐱")
	r.f(m).m("a$", "a")
	r.f(m).m("a$", "b\na\n")
	r.f(m).m("a$", "b\na\u2028")
	r.f(m).m("a$", "b\na\u2029")
	r.f(m).n("a$", "b\nab")
	r.f(m).n("(a$.)", "a\nb")
	r.f(m|s).m("(a$.)", "a\nb", "a\n")

	r.m(`\ba`, "a")
	r.m(`\ba`, " a")
	r.m(`\ba`, "-a")
	r.m(`\ba`, ".a")
	r.m(`a\b`, "a ")
	r.m(`a\b`, "a.")
	r.f(u|i).n(`a\b`, "a\u017f")
	r.f(v|i).n(`a\b`, "a\u212a")

	r.n(`\ba`, "0a")
	r.n(`\ba`, "5a")
	r.n(`\ba`, "9a")
	r.n(`\bb`, "ab")
	r.n(`\ba`, "ka")
	r.n(`\ba`, "za")
	r.n(`\ba`, "Aa")
	r.n(`\ba`, "Ka")
	r.n(`\ba`, "Za")
	r.n(`\ba`, "_a")

	r.n(`\Ba`, " a")
	r.n(`\Ba`, "-a")
	r.n(`\Ba`, ".a")
	r.n(`a\B`, "a ")
	r.n(`a\B`, "a.")
	r.f(u|i).m(`a\B`, "a\u017f")
	r.f(v|i).m(`a\B`, "a\u212a")

	r.m(`\Ba`, "0a")
	r.m(`\Ba`, "5a")
	r.m(`\Ba`, "9a")
	r.m(`\Bb`, "ab")
	r.m(`\Ba`, "ka")
	r.m(`\Ba`, "za")
	r.m(`\Ba`, "Aa")
	r.m(`\Ba`, "Ka")
	r.m(`\Ba`, "Za")
	r.m(`\Ba`, "_a")

	r.m(`(\ba)`, " a", "a")
	r.m(`\b(a)`, " a", "a")
	r.m(`(\b)a`, " a", "")
	r.m(`(\Ba)`, "ba", "a")
	r.m(`\B(a)`, "ba", "a")
	r.m(`c.\b(a)`, "c a", "a")
	r.n(`c.\b(a)`, "cba")
	r.m(`c.\B(a)`, "cba", "a")
	r.n(`c.\B(a)`, "c a")
}

func TestZeroWidthAssertions(t *testing.T) {
	r := newRunner(t)

	r.m("((?=b))", "ab", "")
	r.m("(a(?=b))", "ab", "a")
	r.m("(a(?=(b)))", "ab", "a", "b")
	r.m("((a)(?=(b)))", "ab", "a", "a", "b")
	r.n("a(?=b)", "a")
	r.n("a(?=b)", "ac")
	r.m(`((?=ab))?a`, "ab", nilMatch)
	r.m(`((?=ab))*a`, "ab", nilMatch)
	r.m(`((?=ab)){0,2}a`, "ab", nilMatch)
	r.m(`((?=(ab)))?a`, "ab", nilMatch, nilMatch)

	r.se(`(?=`)
	r.se(`(?=(abc)`)
	r.se(`(?!`)
	r.se(`(?!(abc)`)
	r.se(`(?<=`)
	r.se(`(?<=(abc)`)
	r.se(`(?<!`)
	r.se(`(?<!(abc)`)
	r.se(`(?a)`)
	r.se(`(?=[b-a])`)
	r.se(`(?!=[b-a])`)

	r.m("(a(?!b))", "a", "a")
	r.m("(a(?!b))", "ac", "a")
	r.n("(a(?!b))", "ab")
	r.m("(a(?!b)|a)", "ab", "a")
	r.m("(a(?!(b))|a)", "ab", "a", nilMatch)
	r.m(`(?!a)|c`, "")

	r.m("((?<=a)b)", "ab", "b")
	r.m("((?<=(a))b)", "ab", "b", "a")
	r.m("((?<=(a))(b))", "ab", "b", "a", "b")
	r.m("((?<=a)(?=b))", "ab", "")
	r.m("((?<=a)c(?=b))", "acb", "c")
	r.n("(?<=a)b", "b")
	r.n("(?<=a)b", "cb")

	r.m("((?<!a)b)", "b", "b")
	r.m("((?<!a)b)", "cb", "b")
	r.n("((?<!a)b)", "ab")
	r.m("((?<!a)b|b)", "ab", "b")
	r.m("((?<!(a))b|b)", "ab", "b", nilMatch)

	r.m("(?<=([b-c]+))([c-d]+)", "cbcd", "cb", "cd")
	r.m("(?<=(ab))b", "aabb", "ab")
	r.m("(?<=([a-b]+))(.)", "abc", "a", "b")
	r.m("(?<=([a-b]+))(.)", "abb", "a", "b")

	r.m(`(?<=\b(a))(b)`, " ab", "a", "b")
	r.n(`(?<=\b(a))(b)`, "bab")

	r.f(b).se(`\b*`)
	r.f(b).se(`\B*`)
	r.f(b).se(`(?<=a)*`)
	r.f(b).se(`(?<!a)*`)
	r.f(b | u).se(`a(?=a)+`)
	r.f(b | v).se(`a(?=a)+`)
	r.f(b).m16s(`a(?=a)+`, "aa")
	r.f(b).n16s(`a(?=a)+`, "ab")
	r.f(b).m16s(`(.(?=x)+)`, "a bx", "b")
	r.f(b).m16s(`.(?=x){100}`, "ax")
	r.f(b).m16s(`([a-b](?!0)*)`, "a0 b", "a")
	r.f(b).m16s(`([a-b](?!0)+)`, "a0 b", "b")
	r.f(b).m16s(`([a-b](?!0){2})`, "a0 b", "b")
}

func TestCharacterClass(t *testing.T) {
	r := newRunner(t)

	r.n("([a-c])", "`")
	r.m("([a-c])", "a", "a")
	r.m("([a-c])", "b", "b")
	r.m("([a-c])", "c", "c")
	r.n("([a-c])", "d")

	r.n(`[B-b]`, "A")
	r.m(`[B-b]`, "D")
	r.m(`[B-b]`, "`")
	r.n(`[B-b]`, "c")
	r.f(i).m(`[B-b]`, "A")
	r.f(i).m(`[B-b]`, "D")
	r.f(i).m(`[B-b]`, "`")
	r.f(i).m(`[B-b]`, "c")
	r.f(v).n(`[B-b]`, "A")
	r.f(v).m(`[B-b]`, "D")
	r.f(v).m(`[B-b]`, "`")
	r.f(v).n(`[B-b]`, "c")
	r.f(v|i).m(`[B-b]`, "A")
	r.f(v|i).m(`[B-b]`, "D")
	r.f(v|i).m(`[B-b]`, "`")
	r.f(v|i).m(`[B-b]`, "c")
	r.f(v|i).m(`[B-CB-b]`, "E")
	r.f(v|i).m(`[B-CB-b]`, "e")
	r.f(v|i).m(`[B-CE]`, "e")

	r.se(`[c-a]`)
	r.se(`[`)
	r.se(`[^`)
	r.se(`[a`)
	r.se(`[a-`)
	r.se(`[a-\p{u}`)
	r.se(`[\`)

	r.m("([^a-c])", "`", "`")
	r.n("([^a-c])", "a")
	r.n("([^a-c])", "b")
	r.n("([^a-c])", "c")
	r.m("([^a-c])", "d", "d")

	r.n("([b-ce-f])", "a")
	r.m("([a-ce-f])", "a", "a")
	r.m("([a-ce-f])", "c", "c")
	r.n("([a-ce-f])", "d")
	r.m("([a-ce-f])", "e", "e")
	r.m("([a-ce-f])", "f", "f")
	r.n("([a-ce-f])", "g")

	r.m("([^a-ce-f])", "`", "`")
	r.n("([^a-ce-f])", "a")
	r.n("([^a-ce-f])", "b")
	r.n("([^a-ce-f])", "c")
	r.m("([^a-ce-f])", "d", "d")
	r.n("([^a-ce-f])", "e")
	r.n("([^a-ce-f])", "f")
	r.m("([^a-ce-f])", "g", "g")

	r.m("([a])", "a", "a")
	r.n("([b])", "a")
	r.m("([ab])", "a", "a")
	r.m("([ab])", "b", "b")
	r.m("([abc]+)", "dacbd", "acb")
	r.n("([abc]+)", "dethd")

	r.n("[]", "a")
	r.m("[^]", "a")
	r.m("b[^]", "cba")
	r.f(v).n("[]", "a")
	r.f(v).m("[^]", "a")
	r.f(v).m("b[^]", "cba")

	r.m("([-])", "-", "-")
	r.m("([--])", "-", "-")
	r.m("([---])", "-", "-")
	r.m("([----])", "-", "-")
	r.m("([a-])", "-", "-")
	r.m("([a-])", "a", "a")
	r.m("([-a])", "-", "-")
	r.m("([-a])", "a", "a")
	r.m(`[\w-]`, "a")
	r.m(`[\w-]`, "-")
	r.m(`[+--]`, "+")
	r.m(`[+--]`, ",")
	r.m(`[+--]`, "-")
	r.m(`[+---]`, ",")
	r.m(`[+---]`, "-")

	r.n("[ă-ć]", "Ă")
	r.m("[ă-ć]", "ă")
	r.m("[ă-ć]", "Ą")
	r.m("[ă-ć]", "Ć")
	r.m("[ă-ć]", "ć")
	r.n("[ă-ć]", "Ĉ")

	r.m(`[\d]`, "0")
	r.n(`[\d]`, "a")
	r.m(`[\da]`, "a")
	r.m(`[\da-c]`, "b")
	r.m(`[\da-c]`, "5")
	r.m(`[\dda-c]`, "d")
	r.m(`[da-c\d]`, "0")
	r.m(`[\da-c\d]`, "0")
	r.m(`[\d\w]`, "_")
	r.n(`[^\D\S]`, "5")
	r.n(`[^\D\S]`, " ")
	r.n(`[^\D\S]`, "a")
	r.m(`[^\D\s]`, "5")
	r.n(`[^\D\s]`, " ")
	r.noNode().se16s(`[\p{Letter}]`)
	r.noNode().se16s(`[\P{gc=Letter}]`)

	r.m(`[\u0061\u0062]`, "a")
	r.m(`[\u0061\u0062]`, "b")
	r.m(`[\u0061-\u0062]`, "b")
	r.noNode().se16s(`[\u{61}]`)
	r.m(`[\ra-b]`, "\r")
	r.m(`[\0-]`, "\x00")
	r.m(`[\0-]`, "-")
	r.m16([]uint16{'[', catLN, catHN, ']', '{', '2', '}'}, u16e("🐱"))
	r.m16(u16e(`[\u`+catLX+`\u`+catHX+"]{2}"), u16e("🐱"))
	r.m(`[\ca-\cC]`, "\x01")
	r.m(`[\ca-\cC]`, "\x02")
	r.m(`[\ca-\cC]`, "\x03")
	r.f(u).se(`[\c0]`)

	r.n(`[\-]`, "\\")
	r.m(`[\-]`, "-")
	r.f(u).n(`[\-]`, "\\")
	r.f(u).m(`[\-]`, "-")
	r.m(`[\b]`, "\u0008")

	r.m("([^a])", "b", "b")
	r.n("([^a])", "a")
	r.m("([^ab])", "c", "c")
	r.m("([^ab]+)", "abcdcba", "cdc")

	r.f(i).m("[o]", "O")
	r.f(u|i).m("[o]", "O")
	r.f(v|i).m("[o]", "O")
	r.f(v|i).m(`[\q{aa}]`, "aa")
	r.f(v|i).m(`[\q{aa}]`, "Aa")
	r.f(v|i).m(`[\q{aa}]`, "aA")
	r.f(v|i).m(`[\q{aa}]`, "AA")
	// bug in v8 (most probably https://issues.chromium.org/issues/373759990)
	// it works in webkit and quickjs
	r.f(v|i).noNode().m(`[\q{a}]`, "A")
	r.f(v|i).noNode().m(`[\q{a}]`, "A")

	r.noNode().se("[[a]]")
	r.f(v).m("[[a]]", "a")
	r.noNode().se("[[[a]]]")
	r.f(v).m("[[[a]]]", "a")

	r.f(v).se(`[(]`)
	r.f(v).se(`[)]`)
	r.f(v).se(`[[]`)
	r.f(v).se(`[]]`)
	r.f(v).se(`[{]`)
	r.f(v).se(`[}]`)
	r.f(v).se(`[/]`)
	r.f(v).se(`[-]`)
	r.f(v).se(`[\]`)
	r.f(v).se(`[|]`)

	r.f(v).m("[&]", "&")
	r.f(v).m("[!]", "!")
	r.f(v).m("[#]", "#")
	r.f(v).m("[$]", "$")
	r.f(v).m("[%]", "%")
	r.f(v).m("[*]", "*")
	r.f(v).m("[+]", "+")
	r.f(v).m("[,]", ",")
	r.f(v).m("[.]", ".")
	r.f(v).m("[:]", ":")
	r.f(v).m("[;]", ";")
	r.f(v).m("[<]", "<")
	r.f(v).m("[=]", "=")
	r.f(v).m("[>]", ">")
	r.f(v).m("[?]", "?")
	r.f(v).m("[@]", "@")
	r.f(v).m("[`]", "`")
	r.f(v).m("[~]", "~")

	r.f(v).se("[&&]")
	r.f(v).se("[!!]")
	r.f(v).se("[##]")
	r.f(v).se("[$$]")
	r.f(v).se("[%%]")
	r.f(v).se("[**]")
	r.f(v).se("[++]")
	r.f(v).se("[,,]")
	r.f(v).se("[..]")
	r.f(v).se("[::]")
	r.f(v).se("[;;]")
	r.f(v).se("[<<]")
	r.f(v).se("[==]")
	r.f(v).se("[>>]")
	r.f(v).se("[??]")
	r.f(v).se("[@@]")
	r.f(v).m("[^^]", "a")
	r.f(v).n("[^^]", "^")
	r.f(v).se("[^^^]")
	r.f(v).se("[``]")
	r.f(v).se("[~~]")

	r.f(v).m(`[\&]`, `&`)
	r.f(v).m(`[\-]`, `-`)
	r.f(v).m(`[\!]`, `!`)
	r.f(v).m(`[\#]`, `#`)
	r.f(v).m(`[\%]`, `%`)
	r.f(v).m(`[\,]`, `,`)
	r.f(v).m(`[\:]`, `:`)
	r.f(v).m(`[\;]`, `;`)
	r.f(v).m(`[\<]`, `<`)
	r.f(v).m(`[\=]`, `=`)
	r.f(v).m(`[\>]`, `>`)
	r.f(v).m(`[\@]`, `@`)
	r.f(v).m("[\\`]", "`")
	r.f(v).m(`[\~]`, `~`)
	r.f(v).m(`[\b]`, "\u0008")
	r.f(v).n(`[\b]`, "b")

	r.f(v).se(`[\q]`)
	r.f(v).se(`[\q`)
	r.f(v).se(`[\q{]`)
	r.f(v).se(`[\q{a]`)
	r.f(v).se(`[\q}]`)
	r.f(v).se(`[\qa]`)
	r.f(v).m(`[\q{\u0061}]`, "a")

	r.f(v).m(`([\q{ab}])`, "ab", "ab")
	r.f(v).m(`([\q{ab}])(....)`, "abcdef", "ab", "cdef")
	r.f(v).m(`([\q{ab|a|}])`, "ab", "ab")
	r.f(v).m(`([\q{ab|a|}])`, "ac", "a")
	r.f(v).m(`([\q{a|ab|}])`, "ab", "ab")
	r.f(v).m(`([\q{|a|ab}])`, "ab", "ab")
	r.f(v).m(`([\q{|a|ab}])`, "ac", "a")
	r.f(v).m(`([\q{|a|ab}])`, "c", "")
	r.f(v).m(`([\q{ab|a|}])b`, "ab", "a")
	r.f(v).m(`([\q{ab|a|}])b?`, "ab", "ab")
	r.f(v).m(`([\q{abcd|abc|ab|a|}])`, "abcde", "abcd")
	r.f(v).m(`([\q{abcd|abc|ab|a|}])d`, "abcde", "abc")
	r.f(v).m(`([\q{abcd|abc|ab|a|}])cd`, "abcde", "ab")
	r.f(v).m(`([\q{abcd|abc|ab|a|}])bcd`, "abcde", "a")
	r.f(v).m(`([\q{abcd|abc|ab|a|}])abcd`, "abcde", "")
	r.f(v).m(`([\q{abcd}\q{abc|ab}a\q{}])`, "abcde", "abcd")
	r.f(v).m(`([\q{abcd}\q{abc|ab}a\q{}])d`, "abcde", "abc")
	r.f(v).m(`([\q{abcd}\q{abc|ab}a\q{}])cd`, "abcde", "ab")
	r.f(v).m(`([\q{abcd}\q{abc|ab}a\q{}])bcd`, "abcde", "a")
	r.f(v).m(`([\q{abcd}\q{abc|ab}a\q{}])abcd`, "abcde", "")

	r.f(v).m(`[\q{a|ab}].`, "ab")
	r.f(v).n(`[\q{a|ab}]..`, "ab")
	r.f(v).m(`([\q{a|ab}])*b`, "aaabbab", "ab")

	r.f(v).se("[a&&&]")
	r.f(v).se("[&&&a]")
	r.f(v).m("[&-a]", ",")
	r.f(v).se(`[a&&]`)
	r.f(v).se(`[a&&bb]`)

	r.f(v).n(`[\q{b|c}d]`, "a")
	r.f(v).m(`[\q{b|c}d]`, "b")
	r.f(v).m(`[\q{b|c}d]`, "c")
	r.f(v).m(`[\q{b|c}d]`, "d")
	r.f(v).n(`[\q{b|c}d]`, "e")

	r.f(v).m(`[\q{aa|bb}--\q{bb}]`, "aa")
	r.f(v).n(`[\q{aa|bb}--\q{bb}]`, "bb")
	r.f(v).n(`[\q{aa|bb}--\q{bb}--\q{aa}]`, "bb")
	r.f(v).n(`[\q{aa|bb}--\q{bb}--\q{aa}]`, "bb")
	r.f(v|i).n(`[\q{aa}--\q{aa}]`, "aa")

	r.f(v).n(`([\q{aa|bb}&&\q{aa}])`, "bb")
	r.f(v).m(`([\q{aa|bb}&&\q{aa}])`, "aa", "aa")
	r.f(v).m(`([\q{aa|bb}&&\q{aa|}])`, "aa", "aa")
	r.f(v).m(`([\q{aa|bb|}&&\q{aa|}])`, "aa", "aa")
	r.f(v).m(`([\q{aa|bb|}&&\q{aa|}])..`, "aa", "")
	r.f(v).m(`([\q{aa|bb|}&&\q{}])`, "aa", "")
	r.f(v).m(`([\q{aa|bb|}&&\q{aa|}&&\q{aa}])`, "aa", "aa")

	r.f(v).n(`([[\q{aa}\q{bb}]--[[[\q{aa}][\q{cc}]]&&\q{aa}]])`, "aa")
	r.f(v).m(`([[\q{aa}\q{bb}]--[[[\q{aa}][\q{cc}]]&&\q{aa}]])`, "bb", "bb")
	r.f(v).n(`([[\q{aa}\q{bb}]--[[[\q{aa}][\q{cc}]]&&\q{aa}]])`, "cc")

	r.f(v|i).m(`[A&&A]`, "a")
	r.f(v|i).m(`[a&&a]`, "A")
	r.f(v|i).m(`[\q{A}&&A]`, "a")
	r.f(v|i).m(`[\q{A|BB}&&\q{BB}]`, "bB")
	r.f(v|i).m(`[A--B]`, "a")
	r.f(v|i).m(`[a--b]`, "A")
	r.f(v|i).n(`[a--A]`, "A")
	r.f(v|i).m(`([\q{ee||}a])`, "A", "A")

	r.f(v).m(`[\d]`, "0")
	r.f(v).n(`[\d]`, "a")
	r.f(v).n(`[\d--[0]]`, "0")
	r.f(v).m(`[\d--[0]]`, "1")
	r.f(v).m(`[\d--[0]][\d]`, "10")
	r.f(v).n(`[\D]`, "0")
	r.f(v).m(`[\D]`, "a")

	r.f(v).m(`[\w]`, "a")
	r.f(v).m(`[\w]`, "_")
	r.f(v).m(`[\w]`, "0")
	r.f(v).m(`[\w--\d]`, "Z")
	r.f(v).n(`[\w--\d]`, "0")
	r.f(v).n(`[\W&&\D]`, "a")
	r.f(v).m(`[\W&&\D]`, "\u017f")
	r.f(v).m(`[\w&&\d]`, "0")
	r.f(v).n(`[\W&&\d]`, "9")

	r.f(v).m(`[\s-- ]`, "\t")
	r.f(v).n(`[\s-- ]`, " ")
	r.f(v).m(`[\S]`, "a")
	r.f(v).se(`[`)
	r.f(v).se(`[&&]`)
	r.f(v).se(`[a&&]`)
	r.f(v).se(`[a&&`)
	r.f(v).se(`[&&a]`)
	r.f(v).se(`[a&&--]`)
	r.f(v).se(`[--]`)
	r.f(v).se(`[a--]`)
	r.f(v).se(`[a-]`)
	r.f(v).se(`[a-`)
	r.f(v).se(`[a--`)
	r.f(v).se(`[a-bc-`)
	r.f(v).se(`[a-&&]`)
	r.f(v).se(`[\0-\]`)
	r.f(v).se(`[--a]`)
	r.f(v).se(`[a--&&]`)
	r.f(v).se(`[b-a]`)
	r.f(v).se(`[ab-a]`)
	r.f(v).se(`[a\`)

	r.f(v).m(`[\p{Basic_Emoji}]`, "🐱")
	r.f(v).m(`[\p{RGI_Emoji}]`, "🐱")
	r.f(v).n(`[\p{RGI_Emoji}--\p{Basic_Emoji}]`, "🐱")
	r.f(v).m(`[\p{RGI_Emoji}--\p{Basic_Emoji}]`, "👍\U0001F3FB")
	r.f(u).m(`[\p{Hex}\P{Hex}]`, "a")

	r.f(v).se(`[^\q{}]`)
	r.f(v).se(`[^\q{a|}]`)
	r.f(v).se(`[^\q{\`)
	r.f(v).se(`[^\q{a|aa}]`)
	r.f(v).se(`[^\q{a||aa}]`)
	r.f(v).m(`[^\q{v}]`, "a")
	r.f(v).n(`[^\q{v}]`, "v")
	r.f(v).m(`[^[^\q{v}]]`, "v")
	r.f(v).n(`[^[^\q{v}]]`, "a")
	r.f(v).m(`[^[^\q{v}\q{a}]]`, "a")
	r.f(v).m(`[^[^\q{v}\q{a}]]`, "v")

	r.f(v).se(`[\p{aaa}]`)
	r.f(v).se(`[\a]`)
	r.f(v).se(`[^\p{RGI_Emoji}]`)
	r.f(v).se(`[^a[\p{RGI_Emoji}]]`)
	r.f(v).n(`[^a&&[\q{a|bb}]]`, "a")
	r.f(v).n(`[^a&&\q{aa}]`, "")
	r.f(v).se(`[^\q{aa}&&\q{aa}]`)
	r.f(v).se(`[^[[\q{aa}]]&&\q{aa}]`)
	r.f(v).n(`[^[[\q{a}--\q{aa}]]&&\q{aa}]`, "")
	r.f(v).se(`[^\q{aa}--b]`)
	r.f(u).se(`[\w--]`)
	r.f(u).se(`[--\w]`)
	r.f(v).se(`[a--ab]`)
	r.f(v).se(`[a--a&&b]`)
	r.f(v).m(`[^\q{a|b}--b]`, "b")
	r.f(v).n(`[^\q{a|b}--b]`, "a")

	r.f(v).m(`[a-bdf-g]`, "a")
	r.f(v).n(`[a-bdf-g]`, "c")
	r.f(v).m(`[a-bdf-g]`, "d")
	r.f(v).n(`[a-bdf-g]`, "e")
	r.f(v).m(`[a-bdf-g]`, "f")
	r.f(v).n(`[^a-bdf-g]`, "a")
	r.f(v).m(`[^a-bdf-g]`, "c")
	r.f(v).n(`[^a-bdf-g]`, "d")
	r.f(v).m(`[^a-bdf-g]`, "e")
	r.f(v).n(`[^a-bdf-g]`, "f")
}

func TestCharacterEscape(t *testing.T) {
	r := newRunner(t)

	r.m(`(\r)`, "\r", "\r")
	r.m(`(\n)`, "\n", "\n")
	r.m(`(\t)`, "\t", "\t")
	r.m(`(\v)`, "\v", "\v")
	r.m(`(\f)`, "\f", "\f")
	r.noNode().se(`\e`)

	r.m(`\cA`, "\u0001")
	r.n(`\cA`, "\u0000")
	r.m(`\cC`, "\u0003")
	r.m(`\cc`, "\u0003")
	r.noNode().se(`\c`)
	r.noNode().se(`\c_`)
	r.noNode().se(`\c0`)

	r.m(`\0`, "\u0000")
	r.n(`\0`, "\u0001")
	// in Annex B it's allowed in non-unicode mode
	r.f(u).se(`\00`)
	r.f(u).se(`\01`)
	r.noNode().se(`\01`)
	r.m(`\0a`, "\u0000a")

	r.m(`\x00`, "\u0000")
	r.m(`\x1f`, "\u001f")
	r.m(`\x61`, "a")
	r.m(`\xFF`, "ÿ")
	r.f(i).m(`\x61`, "A")
	r.f(i).m(`\x61`, "a")
	r.f(i).m(`\x41`, "A")
	r.f(i).m(`\x41`, "a")
	r.f(u).se(`\x`)
	r.f(u).se(`\x1`)
	r.f(u).se(`\xg`)
	r.f(u).se(`\xg1`)
	r.noNode().se(`\x`)
	r.noNode().se(`\x1`)
	r.noNode().se(`\xg`)
	r.noNode().se(`\xg1`)

	r.m(`\u0000`, "\u0000")
	r.m(`\u0061`, "a")
	r.m(`\u0061`, "a")
	r.f(u).se(`\ud800\u`)
	r.f(u).m16(u16e(`\u`+ahsaHX+`\u0061`), []uint16{ahsaHN, 'a'})
	// unicode mode to ignore Annex B compat
	r.f(u).se(`\u006`)
	r.f(u).se(`\u006x`)
	r.f(u).se(`\u`)
	r.f(u).se(`\uq`)
	r.m16(u16e(`\u`+catHX+`\u`+catLX), u16e("🐱"))
	r.f(u).m(`\u{00000000}`, "\x00")
	r.f(u).m(`\u{61}`, "a")
	r.noNode().se16s(`\u{61}`)
	r.f(u).se(`\u{61`)

	r.f(u).m(`\^`, `^`)
	r.f(u).m(`\$`, "$")
	r.f(u).m(`\\`, `\`)
	r.f(u).m(`\/`, `/`)
	r.f(u).m(`\.`, `.`)
	r.f(u).m(`\*`, `*`)
	r.f(u).m(`\+`, `+`)
	r.f(u).m(`\?`, `?`)
	r.f(u).m(`\(`, `(`)
	r.f(u).m(`\)`, `)`)
	r.f(u).m(`\[`, `[`)
	r.f(u).m(`\]`, `]`)
	r.f(u).m(`\{`, `{`)
	r.f(u).m(`\}`, `}`)
	r.f(u).m(`\|`, `|`)
	r.m(`\^`, `^`)
	r.m(`\$`, "$")
	r.m(`\\`, `\`)
	r.m(`\/`, `/`)
	r.m(`\.`, `.`)
	r.m(`\*`, `*`)
	r.m(`\+`, `+`)
	r.m(`\?`, `?`)
	r.m(`\(`, `(`)
	r.m(`\)`, `)`)
	r.m(`\[`, `[`)
	r.m(`\]`, `]`)
	r.m(`\{`, `{`)
	r.m(`\}`, `}`)
	r.m(`\|`, `|`)
	r.se(`a\`)

	r.f(u).se(`\&`)
	r.f(u).se(`\"`)
	r.f(u).se(`\_`)
	r.f(u).se(`\@`)
	r.noNode().se(`\_`)
	r.m16s(`\@`, "@")
}

func TestCharacterClassEscape(t *testing.T) {
	r := newRunner(t)

	r.n(`(\d)`, "/")
	r.m(`(\d)`, "0", "0")
	r.m(`(\d)`, "5", "5")
	r.m(`(\d)`, "9", "9")
	r.n(`(\d)`, ":")

	r.m(`(\D)`, "/", "/")
	r.n(`(\D)`, "0")
	r.n(`(\D)`, "5")
	r.n(`(\D)`, "9")
	r.m(`(\D)`, ":", ":")
	r.m(`(\D)`, "a", "a")

	r.m16(u16e(`(\D)`), u16e("🐱"), []uint16{catHN})
	r.n(`\d`, "🐱")
	r.n(`\d`, "İ")

	r.m(`^\d+$`, "01")

	r.m(`(\s)`, " ", " ")
	r.m(`(\s)`, "\t", "\t")
	r.m(`(\s)`, "\n", "\n")
	r.m(`(\s)`, "\r", "\r")
	r.m(`(\s\s)`, "\r\n", "\r\n")
	r.m(`(\s)`, "\u000b", "\u000b")
	r.m(`(\s)`, "\u000c", "\u000c")
	r.n(`(\s)`, "\u0085")
	r.m(`(\s)`, "\u00a0", "\u00a0")
	r.m(`(\s)`, "\u1680", "\u1680")
	r.m(`(\s)`, " ", " ") // U+1680
	r.n(`(\s)`, "\u1999")
	r.m(`(\s)`, "\u2000", "\u2000")
	r.m(`(\s)`, "\u2001", "\u2001")
	r.m(`(\s)`, "\u2005", "\u2005")
	r.m(`(\s)`, "\u200a", "\u200a")
	r.n(`(\s)`, "\u200b")
	r.n(`(\s)`, "\u202e")
	r.m(`(\s)`, "\u202f", "\u202f")
	r.n(`(\s)`, "\u2030")
	r.n(`(\s)`, "\u204e")
	r.m(`(\s)`, "\u205f", "\u205f")
	r.n(`(\s)`, "\u2060")
	r.n(`(\s)`, "\u2fff")
	r.m(`(\s)`, "\u3000", "\u3000")
	r.n(`(\s)`, "\u3001")
	r.m(`(\s)`, "\ufeff", "\ufeff")
	r.n(`(\s)`, "\u2027")
	r.m(`(\s)`, "\u2028", "\u2028")
	r.m(`(\s)`, "\u2029", "\u2029")
	r.n(`(\s)`, "\u2030")
	r.n(`(\s)`, "⠀") // U+2800 Braille Pattern Blank

	r.n(`(\S)`, " ")
	r.n(`(\S)`, "\t")
	r.n(`(\S)`, "\n")
	r.n(`(\S)`, "\r")
	r.n(`(\S\S)`, "\r\n")
	r.n(`(\S)`, "\u000b")
	r.n(`(\S)`, "\u000c")
	r.m(`(\S)`, "\u0085", "\u0085")
	r.n(`(\S)`, "\u00a0")
	r.n(`(\S)`, "\u1680")
	r.m(`(\S)`, "\u1999", "\u1999")
	r.n(`(\S)`, "\u2000")
	r.n(`(\S)`, "\u2001")
	r.n(`(\S)`, "\u2005")
	r.n(`(\S)`, "\u200a")
	r.m(`(\S)`, "\u200b", "\u200b")
	r.m(`(\S)`, "\u202e", "\u202e")
	r.n(`(\S)`, "\u202f")
	r.m(`(\S)`, "\u2030", "\u2030")
	r.m(`(\S)`, "\u204e", "\u204e")
	r.n(`(\S)`, "\u205f")
	r.m(`(\S)`, "\u2060", "\u2060")
	r.m(`(\S)`, "\u2fff", "\u2fff")
	r.n(`(\S)`, "\u3000")
	r.m(`(\S)`, "\u3001", "\u3001")
	r.n(`(\S)`, "\ufeff")
	r.m(`(\S)`, "\u2027", "\u2027")
	r.n(`(\S)`, "\u2028")
	r.n(`(\S)`, "\u2029")
	r.m(`(\S)`, "\u2030", "\u2030")

	r.n(`(\w)`, "/")
	r.m(`(\w)`, "0", "0")
	r.m(`(\w)`, "5", "5")
	r.m(`(\w)`, "9", "9")
	r.n(`(\w)`, ":")
	r.n(`(\w)`, "@")
	r.m(`(\w)`, "A", "A")
	r.m(`(\w)`, "M", "M")
	r.m(`(\w)`, "Z", "Z")
	r.n(`(\w)`, "[")
	r.n(`(\w)`, "`")
	r.m(`(\w)`, "a", "a")
	r.m(`(\w)`, "m", "m")
	r.m(`(\w)`, "z", "z")
	r.n(`(\w)`, "{")
	r.m(`(\w)`, "_", "_")
	r.n(`(\w)`, "\u017f")
	r.n(`(\w)`, "\u212a")
	r.f(i).n16s(`[a-z]`, "\u017f")
	r.f(i).n16s(`[a-z]`, "\u212a")
	r.f(i).n16s(`\w`, "\u017f")
	r.f(i).n16s(`\w`, "\u212a")
	r.f(u).n16s(`\w`, "\u017f")
	r.f(v).n16s(`\w`, "\u212a")
	r.f(u|i).m(`\w`, "\u017f")
	r.f(v|i).m(`\w`, "\u212a")
	r.f(u|i).m(`[a-z]`, "\u017f")
	r.f(v|i).m(`[a-z]`, "\u212a")
	r.m(`(\W)`, "/", "/")
	r.n(`(\W)`, "0")
	r.n(`(\W)`, "5")
	r.n(`(\W)`, "9")
	r.m(`(\W)`, ":", ":")
	r.m(`(\W)`, "@", "@")
	r.n(`(\W)`, "Z")
	r.m(`(\W)`, "[", "[")
	r.m(`(\W)`, "`", "`")
	r.n(`(\W)`, "a")
	r.n(`(\W)`, "m")
	r.n(`(\W)`, "z")
	r.m(`(\W)`, "{", "{")
	r.n(`(\W)`, "_")

	r.f(i).m(`\w`, "S")
	r.f(i).m(`\w`, "s")
	r.f(i).m(`\w`, "K")
	r.f(i).m(`\w`, "k")
	r.f(u|i).m(`\w`, "S")
	r.f(u|i).m(`\w`, "s")
	r.f(u|i).m(`\w`, "K")
	r.f(u|i).m(`\w`, "k")
	r.f(v|i).m(`\w`, "S")
	r.f(v|i).m(`\w`, "s")
	r.f(v|i).m(`\w`, "K")
	r.f(v|i).m(`\w`, "k")

	r.f(u).m(`(\p{General_Category=Cased_Letter})`, "a", "a")
	r.f(u).m(`(\p{General_Category=Cased_Letter})`, "Z", "Z")
	r.f(u).n(`(\p{General_Category=Cased_Letter})`, "@")
	r.f(u).m(`(\p{gc=Lowercase_Letter})`, "a", "a")
	r.f(u).n(`(\p{gc=Lowercase_Letter})`, "Z")
	r.f(v).m(`(\p{General_Category=Nd})`, "෯", "෯")
	r.f(v).m(`(\p{gc=Nd})`, "෯", "෯")
	r.f(v).m(`(\p{Script=Common})`, "1", "1")
	r.f(v).m(`(\p{sc=Common})`, "1", "1")
	r.f(v).m(`(\p{Script=Zyyy})`, "1", "1")
	r.f(v).m(`(\p{sc=Zyyy})`, "1", "1")
	r.f(v).m(`(\p{Script=Cherokee})`, "Ꭽ", "Ꭽ")
	r.f(v).m(`(\p{sc=Cherokee})`, "Ꭽ", "Ꭽ")
	r.f(v).m(`(\p{Script_Extensions=Cherokee})`, "Ꭽ", "Ꭽ")
	r.f(v).m(`(\p{scx=Cherokee})`, "Ꭽ", "Ꭽ")
	r.f(u).m(`(\p{sc=Common})`, "ー", "ー")
	r.f(u).n(`(\p{scx=Common})`, "ー")
	r.f(u).m(`(\p{sc=Unknown})`, "\u0378", "\u0378")
	r.f(u).m(`(\p{sc=Zzzz})`, "\u0378", "\u0378")
	r.f(u).m16(u16e(`(\p{sc=Unknown})`), []uint16{catHN}, []uint16{catHN})
	r.f(u).m(`(\p{sc=Unknown})`, "\ue000", "\ue000")
	r.f(u).m(`(\p{sc=Unknown})`, "\U0010ffff", "\U0010ffff")
	r.f(u).se(`\p{AAA=Cased_Letter}`)
	r.f(u).se(`\p{AAA=BBB}`)
	r.f(u).se(`\p{General_Category=BBB}`)
	r.f(u).se(`\p{general_Category=Cased_Letter}`)
	r.f(u).se(`\p{General_Category=cased_Letter}`)
	r.f(u).se(`\p{General-Category=Cased_Letter}`)
	r.f(u).se(`\p{General_Category=Cased-Letter}`)
	r.f(u).se(`\p{General_Category=Cased_Letter`)
	r.f(u).se(`\p{General_Category`)
	r.f(u).se(`\p{General_Category=Katakana_Or_Hiragana}`)
	r.f(u).se(`\p{Basic_Emoji}`)
	r.f(u).se(`\p`)

	r.f(u|i).m(`\P{gc=Uppercase_Letter}`, "A")
	r.f(u|i).m(`\P{gc=Uppercase_Letter}`, "a")
	r.f(u|i).m(`\P{gc=Uppercase_Letter}`, "0")

	r.f(v).m(`(\p{Basic_Emoji})`, "⌚", "⌚") // less than 0xFFFF
	r.f(v).m(`(\p{Basic_Emoji})`, "a⌚b", "⌚")
	r.f(v).m(`(\p{Basic_Emoji})`, "🐱", "🐱")
	r.f(v).m(`(\p{Basic_Emoji})`, "a🐱b", "🐱")
	r.f(v).m(`(\p{Basic_Emoji})`, "©\ufe0f", "©\ufe0f")
	r.f(v).m(`(\p{Basic_Emoji})`, "a©\ufe0fb", "©\ufe0f")
	r.f(v).n(`(\p{Basic_Emoji})`, "\u00aa\ufe0f")
	r.f(v).n(`(\p{Basic_Emoji})`, "🌤") // Emoji_Presentation = false
	r.f(v).m(`(\p{Basic_Emoji})`, "🌤\ufe0f", "🌤\ufe0f")

	r.f(v).m(`(\p{Emoji_Keycap_Sequence})`, "#\ufe0f\u20e3", "#\ufe0f\u20e3")
	r.f(v).n(`(\p{Emoji_Keycap_Sequence})`, "#\ufe0f")
	r.f(v).n(`(\p{Emoji_Keycap_Sequence})`, "#\u20e3")
	r.f(v).n(`(\p{Emoji_Keycap_Sequence})`, "#")
	r.f(v).m(`(\p{Emoji_Keycap_Sequence})`, "*\ufe0f\u20e3", "*\ufe0f\u20e3")
	r.f(v).m(`(\p{Emoji_Keycap_Sequence})`, "0\ufe0f\u20e3", "0\ufe0f\u20e3")
	r.f(v).m(`(\p{Emoji_Keycap_Sequence})`, "5\ufe0f\u20e3", "5\ufe0f\u20e3")
	r.f(v).m(`(\p{Emoji_Keycap_Sequence})`, "9\ufe0f\u20e3", "9\ufe0f\u20e3")

	// use raw escapce sequence instead of literal emoji, because my terminal
	// emulator incorrectly renders emoji sequences
	r.f(v).m(`(\p{RGI_Emoji_Modifier_Sequence})`, "👍\U0001F3FB", "👍\U0001F3FB") // light skin tone
	r.f(v).m(`(\p{RGI_Emoji_Modifier_Sequence})`, "👍\U0001F3FC", "👍\U0001F3FC") // medium-light skin tone
	r.f(v).m(`(\p{RGI_Emoji_Modifier_Sequence})`, "👍\U0001F3FD", "👍\U0001F3FD") // medium skin tone
	r.f(v).m(`(\p{RGI_Emoji_Modifier_Sequence})`, "👍\U0001F3FE", "👍\U0001F3FE") // medium-dark skin tone
	r.f(v).m(`(\p{RGI_Emoji_Modifier_Sequence})`, "👍\U0001F3FF", "👍\U0001F3FF") // dark skin tone
	r.f(v).n(`(\p{RGI_Emoji_Modifier_Sequence})`, "🐱\U0001F3FB")
	r.f(v).n(`(\p{RGI_Emoji_Modifier_Sequence})`, "a\U0001F3FB")

	r.f(v).m(`(\p{RGI_Emoji_Flag_Sequence})`, "\U0001F1FA\U0001F1F8", "\U0001F1FA\U0001F1F8") // USA
	r.f(v).n(`(\p{RGI_Emoji_Flag_Sequence})`, "\U0001F1F8\U0001F1FA")                         // Soviet Union - not in RGI
	r.f(v).m(`(\p{RGI_Emoji_Flag_Sequence})`, "\U0001F1FF\U0001F1FC", "\U0001F1FF\U0001F1FC") // Zimbabwe
	r.f(v).m(`(\p{RGI_Emoji_Flag_Sequence})`, "\U0001F1FA\U0001F1F3", "\U0001F1FA\U0001F1F3") // United Nations

	r.f(v).m(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F", "🏴󠁧󠁢󠁥󠁮󠁧󠁿") // gbeng (England)
	r.f(v).m(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F", "🏴󠁧󠁢󠁳󠁣󠁴󠁿") // gbsct (Scotland)
	r.f(v).m(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F4\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007F", "🏴󠁧󠁢󠁷󠁬󠁳󠁿") // gbwls (Wales)
	r.f(v).n(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F4\U000E0067\U000E0062\U000E0077\U000E006A\U000E0073\U000E007F")
	r.f(v).n(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F4\U000E0062\U000E0062\U000E0077\U000E006A\U000E0073\U000E007F")
	r.f(v).n(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F3\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007F")
	r.f(v).n(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F3\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007E")
	r.f(v).n(`(\p{RGI_Emoji_Tag_Sequence})`, "\U0001F3F4\U000E0075\U000E0073\U000E0063\U000E0061\U000E007F") // usca (California) - not in RGI

	r.f(v).m(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏃\u200D➡\uFE0F", "🏃\u200D➡\uFE0F") // person running facing right
	r.f(v).n(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏃\u200D➡")
	r.f(v).n(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏃➡\uFE0F")
	r.f(v).n(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏃➡")
	r.f(v).m(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0F", "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0F") // woman running facing right: medium-dark skin tone
	r.f(v).m(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏃\U0001F3FE\u200D♀\uFE0F", "🏃\U0001F3FE\u200D♀\uFE0F")                           // woman running: medium-dark skin tone
	r.f(v).m(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🧑\u200d🧑\u200d🧒\u200d🧒", "🧑\u200d🧑\u200d🧒\u200d🧒")                               // family: adult, adult, child, child
	r.f(v).n(`(\p{RGI_Emoji_ZWJ_Sequence})`, "❤\uFE0F")
	r.f(v).m(`(\p{RGI_Emoji_ZWJ_Sequence})`, "❤\uFE0F\u200d🔥", "❤\uFE0F\u200d🔥") // heart on fire
	r.f(v).m(`(\p{RGI_Emoji_ZWJ_Sequence})`, "🏴\u200d☠\ufe0f", "🏴\u200d☠\ufe0f") // pirate flag

	r.f(v).m(`(\p{RGI_Emoji})`, "a🐱b", "🐱")
	r.f(v).m(`(\p{RGI_Emoji})`, "🌤\ufe0f", "🌤\ufe0f")
	r.f(v).m(`(\p{RGI_Emoji})`, "#\ufe0f\u20e3", "#\ufe0f\u20e3")
	r.f(v).m(`(\p{RGI_Emoji})`, "👍\U0001F3FB", "👍\U0001F3FB")                                                        // light skin tone
	r.f(v).m(`(\p{RGI_Emoji})`, "\U0001F1FA\U0001F1F8", "\U0001F1FA\U0001F1F8")                                      // USA
	r.f(v).m(`(\p{RGI_Emoji})`, "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F", "🏴󠁧󠁢󠁥󠁮󠁧󠁿") // gbeng (England)
	r.f(v).m(`(\p{RGI_Emoji})`, "🏃\u200D➡\uFE0F", "🏃\u200D➡\uFE0F")                                                  // person running facing right
	r.f(v).m(`(\p{RGI_Emoji})`, "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0F", "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0F")    // woman running facing right: medium-dark skin tone
	r.f(v).m(`(\p{RGI_Emoji})`, "🏴\u200d☠\ufe0f", "🏴\u200d☠\ufe0f")                                                  // pirate flag

	r.f(v).m(`(?<=(\p{RGI_Emoji}))b`, "a🐱b", "🐱")
	r.f(v).m(`(?<=(\p{RGI_Emoji_ZWJ_Sequence}))b`, "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0Fb", "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0F") // woman running facing right: medium-dark skin tone
	r.f(v).m("(?<=(\\p{RGI_Emoji_ZWJ_Sequence}))\u200D➡\uFE0Fb", "🏃\U0001F3FE\u200D♀\uFE0F\u200D➡\uFE0Fb", "🏃\U0001F3FE\u200D♀\uFE0F")
	r.f(v).m(`(?<=(\p{RGI_Emoji_ZWJ_Sequence}))b`, "🏃\U0001F3FE\u200D♀\uFE0Fb", "🏃\U0001F3FE\u200D♀\uFE0F") // woman running: medium-dark skin tone

	r.f(v).m(`(\p{ASCII_Hex_Digit})`, "0", "0")
	r.f(v).m(`(\p{AHex})`, "5", "5")
	r.f(v).m(`(\p{ASCII_Hex_Digit})`, "9", "9")
	r.f(v).m(`(\p{ASCII_Hex_Digit})`, "A", "A")
	r.f(v).m(`(\p{ASCII_Hex_Digit})`, "F", "F")
	r.f(v).m(`(\p{AHex})`, "f", "f")
	r.f(v).m(`(\p{AHex})`, "f", "f")
	r.f(v).m(`(\p{Emoji_Presentation})`, "🐱", "🐱")

	r.f(v).se(`\P{Basic_Emoji}`)
	r.f(v).se(`\P{Emoji_Keycap_Sequence}`)
	r.f(v).se(`\P{RGI_Emoji_Modifier_Sequence}`)
	r.f(v).se(`\P{RGI_Emoji_Flag_Sequence}`)
	r.f(v).se(`\P{RGI_Emoji_Tag_Sequence}`)
	r.f(v).se(`\P{RGI_Emoji_ZWJ_Sequence}`)
	r.f(v).se(`\P{RGI_Emoji}`)

	r.f(v).m(`\P{gc=Cased_Letter}`, "0")
	r.f(v).n(`\P{gc=Cased_Letter}`, "A")
	r.f(v).n(`\P{gc=Cased_Letter}`, "z")
	r.f(v).n(`\P{gc=Cased_Letter}`, "Ā")

	// https://issues.chromium.org/issues/373759990
	r.f(v|i).noNode().m(`\p{ASCII}`, "\u212a")
}

func TestBackreference(t *testing.T) {
	r := newRunner(t)

	r.m(`(a)(\1)`, "aa", "a", "a")
	r.n(`(a)(\1)`, "ab")
	r.m(`(a)(\2)`, "aa", "a", "")
	r.m(`(a)(\3)(b)`, "ab", "a", "", "b")
	r.m(`((a)|(b))(\3)`, "ab", "a", "a", nilMatch, "")
	r.m(`(ab)(\1)`, "ababc", "ab", "ab")
	r.m(`(ab)(\1)`, "abab", "ab", "ab")
	r.n(`(ab)(\1)`, "aba")

	r.noNode().se(`\1`)
	r.noNode().se(`(a)\2`)
	r.noNode().se(`(a)\3(b)`)

	r.m(`(?<=\1(a))b`, "baab", "a")
	r.m(`(?<=\1(ab))c`, "bababc", "ab")
	r.n(`(?<=\1(ab))b`, "bbabb")

	r.m(".*(?<=(..|...|....))(.*)", "xabcd", "cd", "")
	r.m(".*(?<=(xx|...|....))(.*)", "xabcd", "bcd", "")
	r.m(".*(?<=(xx|...))(.*)", "xxabcd", "bcd", "")
	r.m(".*(?<=(xx|xxx))(.*)", "xxabcd", "xx", "abcd")

	r.m(`(.)(?<=(\1))`, "a", "a", "a")
	r.m(`(.)(?<=(\1\1))`, "abb", "b", "bb")

	r.n(`(?<=([a-c]+)).\1`, "abcdbc")

	r.m(`(a+)(.)\1`, "aaba", "a", "b")
	r.n(`(?<=\1(\w+))c`, "ababdc")
	r.f(i).m(`(.)\1`, "cC", "c")
	r.f(i).m(`(.)\1`, "Cc", "C")

	r.m(`(.*?)a(?!(a+)b\2c)(.*)`, "baaabaac", "ba", nilMatch, "abaac")
}

func TestNonASCII(t *testing.T) {
	r := newRunner(t)

	r.m(`(.)(\1)`, "§§", "§", "§")
	r.m(`(.)(?<=(\1))`, "§§", "§", "§")
	r.m(`.`, string(runeToWTF8(0xd800)))

	r.m16(u16e("(a..b)"), u16e(`a🐱b`), u16e(`a🐱b`))
	r.mg16(u16e("(?<group>a..b)"), u16e(`a🐱b`), gr16{"group": u16e(`a🐱b`)}, u16e(`a🐱b`))
	r.m16(u16e("a(.)(.)b"), u16e(`a🐱b`), []uint16{catHN}, []uint16{catLN})

	r.f(u).n("(a..b)", `a🐱b`)
	r.f(v).n("(a..b)", `a🐱b`)
	r.f(u).m("(a.b)", `a🐱b`, `a🐱b`)
	r.f(u).m("a(.)b", `a🐱b`, `🐱`)
	r.f(v).m("(a.b)", `a🐱b`, `a🐱b`)

	r.m16(u16e("(.)(..)(..)(.)"), u16e("🐱🐱🐱"), []uint16{catHN}, []uint16{catLN, catHN}, []uint16{catLN, catHN}, []uint16{catLN})
	r.m16(u16e(`(.)(.)(\1)(\2)`), u16e("🐱🐱"), []uint16{catHN}, []uint16{catLN}, []uint16{catHN}, []uint16{catLN})
	r.m16(u16e(`(.)(.)(\2)(\1)`), []uint16{catHN, catLN, catLN, catHN}, []uint16{catHN}, []uint16{catLN}, []uint16{catLN}, []uint16{catHN})
	r.m16(u16e(`(.)(.)..(?<=(\1)(\2))`), u16e("🐱🐱"), []uint16{catHN}, []uint16{catLN}, []uint16{catHN}, []uint16{catLN})
	r.m("(🐱)", "🐱", "🐱")

	r.m("(?<=(🐱))a", "🐱a", "🐱")
	r.f(u).m("(?<=(🐱))a", "🐱a", "🐱")
	r.f(u).se("(?<🐱>a)")
	r.f(v).m("(?<=(🐱))a", "🐱a", "🐱")

	r.m16s(`\🐱`, "🐱")
	r.f(u).se(`\🐱`)
	r.f(v).se(`\🐱`)
	r.m16s(`\𝓍`, "𝓍")
	xH, xL := utf16.EncodeRune('𝓍')
	r.m16([]uint16{'\\', uint16(xH), uint16(xL)}, u16e("𝓍"))
	r.f(b).m16s(`\🐱`, "🐱")
	r.f(b).m16s(`\𝓍`, "𝓍")
	r.f(b).m16([]uint16{'\\', uint16(xH), uint16(xL)}, u16e("𝓍"))

	// Replacement char / RuneError
	r.m(".", "\ufffd")
	r.m("\ufffd", "\ufffd")

	// Invalid UTF-8
	r.m(string([]byte{0x80}), "\x80")
	r.m(string([]byte{0xBF}), "\xbf")
	r.m(string([]byte{0xC2}), "\xc2")                     // starts a 2-byte sequence, but no continuation
	r.m(string([]byte{0xE0, 0xA0}), "\xe0\xa0")           // starts 3-byte sequence, missing 3rd byte
	r.m(string([]byte{0xF0, 0x90, 0x80}), "\xf0\x90\x80") // starts 4-byte sequence, missing 4th byte
	r.m(string(runeToWTF8(0xd800)), string(runeToWTF8(0xd800)))
	r.m(string(runeToWTF8(0xdc00)), string(runeToWTF8(0xdc00)))
}

// This example should be kept in sync with README.md

func Example() {
	re := MustCompile(".+(?<foo>bAr)", FlagIgnoreCase)
	m := re.FindMatch([]byte("_Bar_"))
	fmt.Printf("Groups[0] - %q\n", m.Groups[0].Data())
	fmt.Printf("Groups[1] - %q\n", m.Groups[1].Data())
	fmt.Printf("NamedGroups[\"foo\"] - %q\n", m.NamedGroups["foo"].Data())

	// Output:
	//
	// Groups[0] - "_Bar"
	// Groups[1] - "Bar"
	// NamedGroups["foo"] - "Bar"
}

// This example should be kept in sync with README.md

// The U+1F431 CAT FACE (🐱).
// In UTF-16 without 'u', it appears as two separate surrogate code units (0xD83D, 0xDC31).
// With 'u', those are paired into one code point.
func Example_utf8_vs_Utf16() {
	var pattern = "c(.)(.)"
	var patternUtf16 = []uint16{'c', '(', '.', ')', '(', '.', ')'}

	var source = []byte("c🐱at")
	var sourceUtf16 = []uint16{'c', 0xD83D, 0xDC31, 'a', 't'}

	reUtf8 := MustCompile(pattern, 0)
	m1 := reUtf8.FindMatch(source)
	fmt.Printf("UTF-8:                   %q, %q\n", m1.Groups[1].Data(), m1.Groups[2].Data())

	reUtf8Unicode := MustCompile(pattern, FlagUnicode)
	m2 := reUtf8Unicode.FindMatch(source)
	fmt.Printf("UTF-8 (with 'u' flag):   %q, %q\n", m2.Groups[1].Data(), m2.Groups[2].Data())

	reUtf16 := MustCompileUtf16(patternUtf16, 0)
	m3 := reUtf16.FindMatch(sourceUtf16)
	fmt.Printf("UTF-16:                  %#v, %#v\n", m3.Groups[1].Data(), m3.Groups[2].Data())

	reUtf16Unicode := MustCompileUtf16(patternUtf16, FlagUnicode)
	m4 := reUtf16Unicode.FindMatch(sourceUtf16)
	fmt.Printf("UTF-16 (with 'u' flag):  %#v, %#v\n", m4.Groups[1].Data(), m4.Groups[2].Data())

	// Output:
	//
	// UTF-8:                   "🐱", "a"
	// UTF-8 (with 'u' flag):   "🐱", "a"
	// UTF-16:                  []uint16{0xd83d}, []uint16{0xdc31}
	// UTF-16 (with 'u' flag):  []uint16{0xd83d, 0xdc31}, []uint16{0x61}
}

func TestLibraryApi(t *testing.T) {
	shouldPanic := func(cb func()) func(t *testing.T) {
		return func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("did not panic on invalid pattern")
				}
			}()

			cb()
		}
	}
	t.Run("utf8", func(t *testing.T) {
		t.Run("MustCompile", shouldPanic(func() {
			MustCompile("*", 0)
		}))
		t.Run("FindMatchNilSource", func(t *testing.T) {
			match := MustCompile("a", 0).FindMatch(nil)
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("FindMatchNil", func(t *testing.T) {
			match := MustCompile("a", 0).FindMatch([]byte("b"))
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("FindMatchStartingAt", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte("ab"), 1)
			assert.Equal(t, len(match.Groups), 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte("b"))
		})
		t.Run("FindMatchStartingAtNegative", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte("ab"), -1)
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("FindMatchStartingAtBeyondEnd", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte("ab"), 3)
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("FindMatchStartingAtEndNil", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte("ab"), 2)
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("FindMatchStartingAtEndZeroWidth", func(t *testing.T) {
			match := MustCompile("(?:)", 0).FindMatchStartingAt([]byte("ab"), 2)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte{})
		})
		t.Run("FindMatchStartingAtMidCodepoint", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte("β"), 1)
			assert.Equal(t, match.Groups[0].Start, 0)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte("β"))
		})
		t.Run("FindMatchStartingAtMidCodepoint", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte("a🐱b"), 3)
			assert.Equal(t, match.Groups[0].Start, 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte("🐱"))
		})
		t.Run("FindMatchStartingAtMidInvalidCodepoint", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte{'a', 0xF0, 0x90, 0x80, 'b'}, 1)
			assert.Equal(t, match.Groups[0].Start, 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte{0xF0})
		})
		t.Run("FindMatchStartingAtMidInvalidCodepoint", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte{'a', 0xF0, 0x90, 0x80, 'b'}, 2)
			assert.Equal(t, match.Groups[0].Start, 2)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte{0x90})
		})
		t.Run("FindMatchStartingAtMidInvalidCodepoint", func(t *testing.T) {
			match := MustCompile(".", 0).FindMatchStartingAt([]byte{'a', 0xF0, 0x90, 0x80, 'b'}, 3)
			assert.Equal(t, match.Groups[0].Start, 3)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte{0x80})
		})
		t.Run("FindNextMatchNil", func(t *testing.T) {
			match := MustCompile("a", 0).FindNextMatch(nil)
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("FindNextMatch", func(t *testing.T) {
			re := MustCompile(".", 0)
			match := re.FindMatch([]byte("ab"))
			match = re.FindNextMatch(match)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte("b"))
		})
		t.Run("FindNextMatchAdvance", func(t *testing.T) {
			re := MustCompile("(?:)", 0)
			match := re.FindMatch([]byte("a"))
			assert.Equal(t, match.Groups[0].Start, 0)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte{})
			match = re.FindNextMatch(match)
			assert.Equal(t, match.Groups[0].Start, 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []byte{})
			match = re.FindNextMatch(match)
			assert.Equal(t, match, (*Match)(nil))
		})
		t.Run("AlwaysUnicode", func(t *testing.T) {
			match := MustCompile(omh, FlagIgnoreCase).FindMatch([]byte(smallOmega))
			assert.DeepEqual(t, match.Groups[0].Data(), []byte(smallOmega))
		})
	})
	t.Run("utf16", func(t *testing.T) {
		t.Run("MustCompile", shouldPanic(func() {
			MustCompileUtf16(u16e("*"), 0)
		}))
		t.Run("FindMatchNilSource", func(t *testing.T) {
			match := MustCompileUtf16(u16e("a"), 0).FindMatch(nil)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchNil", func(t *testing.T) {
			match := MustCompileUtf16(u16e("a"), 0).FindMatch(u16e("b"))
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAt", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), 0).FindMatchStartingAt(u16e("ab"), 1)
			assert.Equal(t, len(match.Groups), 1)
			assert.DeepEqual(t, match.Groups[0].Data(), u16e("b"))
		})
		t.Run("FindMatchStartingAtNegative", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), 0).FindMatchStartingAt(u16e("ab"), -1)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAtBeyondEnd", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), 0).FindMatchStartingAt(u16e("ab"), 3)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAtEndNil", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), 0).FindMatchStartingAt(u16e("ab"), 2)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAtEndZeroWidth", func(t *testing.T) {
			match := MustCompileUtf16(u16e("(?:)"), 0).FindMatchStartingAt(u16e("ab"), 2)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{})
		})
		t.Run("FindMatchStartingWithinSurrogatePair", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), 0).FindMatchStartingAt(u16e("🐱"), 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{catLN})
		})
		t.Run("FindMatchStartingWithinSurrogatePairUnicode", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), FlagUnicode).FindMatchStartingAt(u16e("🐱"), 1)
			assert.DeepEqual(t, match.Groups[0].Data(), u16e("🐱"))
		})
		t.Run("FindMatchStartingWithinSurrogatePairUnicodeSets", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), FlagUnicodeSets).FindMatchStartingAt(u16e("🐱"), 1)
			assert.DeepEqual(t, match.Groups[0].Data(), u16e("🐱"))
		})
		t.Run("FindMatchStartingWithinLoneSurrogate", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), FlagUnicode).FindMatchStartingAt([]uint16{catLN, catHN}, 0)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{catLN})
		})
		t.Run("FindMatchStartingWithinLoneSurrogate", func(t *testing.T) {
			match := MustCompileUtf16(u16e("."), FlagUnicode).FindMatchStartingAt([]uint16{'a', catLN, catHN}, 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{catLN})
		})
		t.Run("FindNextMatchNil", func(t *testing.T) {
			match := MustCompileUtf16(u16e("a"), 0).FindNextMatch(nil)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindNextMatch", func(t *testing.T) {
			re := MustCompileUtf16(u16e("."), 0)
			match := re.FindMatch(u16e("ab"))
			match = re.FindNextMatch(match)
			assert.DeepEqual(t, match.Groups[0].Data(), u16e("b"))
		})
		t.Run("FindNextMatchAdvance", func(t *testing.T) {
			re := MustCompileUtf16(u16e("(?:)"), 0)
			match := re.FindMatch(u16e("a"))
			assert.Equal(t, match.Groups[0].Start, 0)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{})
			match = re.FindNextMatch(match)
			assert.Equal(t, match.Groups[0].Start, 1)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{})
			match = re.FindNextMatch(match)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAtSticky", func(t *testing.T) {
			match := MustCompileUtf16(u16e(`\d`), 0).FindMatchStartingAtSticky(u16e("1a2"), 1)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAtSticky", func(t *testing.T) {
			match := MustCompileUtf16(u16e(`\d`), FlagSticky).FindMatchStartingAtSticky(u16e("1a2"), 1)
			assert.Equal(t, match, (*MatchUtf16)(nil))
		})
		t.Run("FindMatchStartingAtSticky", func(t *testing.T) {
			match := MustCompileUtf16(u16e(`\d`), 0).FindMatchStartingAtSticky(u16e("1a2"), 2)
			assert.DeepEqual(t, match.Groups[0].Data(), []uint16{'2'})
		})
	})
}
