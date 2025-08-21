// Package regonaut is an implementation of ECMAScript Regular Expressions.
package regonaut

import (
	"maps"
	"math"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Flag is a bitmask of RegExp options.
// The zero value corresponds to /pattern/ with no flags.
// Combine flags with bitwise OR, e.g. FlagIgnoreCase|FlagMultiline.
type Flag uint16

const (
	// Case-insensitive matching ("i" flag).
	FlagIgnoreCase Flag = 1 << iota

	// "^" and "$" match line boundaries ("m" flag).
	FlagMultiline

	// "." matches line terminators ("s" flag).
	FlagDotAll

	// Unicode-aware mode ("u" flag).
	// If this flag is set, FlagAnnexB is ignored.
	FlagUnicode

	// Unicode set notation and string properties ("v" flag).
	// If this flag is set, FlagAnnexB is ignored.
	FlagUnicodeSets

	// Sticky match from current position ("y" flag).
	FlagSticky

	// Enables Annex B web-compat features.
	// When FlagUnicode or FlagUnicodeSets is set,
	// this flag is cleared automatically by the compiler.
	FlagAnnexB

	flagEitherUnicode = FlagUnicode | FlagUnicodeSets
)

type patternDirection = int

const (
	patternDirectionForward  patternDirection = 1
	patternDirectionBackward patternDirection = -1
)

type SyntaxError struct {
	err string
}

func (e SyntaxError) Error() string {
	return e.err
}

var _ error = (*SyntaxError)(nil)

func newSyntaxError(err string) SyntaxError {
	return SyntaxError{err: err}
}

type namedCaptureAhead struct {
	name string
	end  int
}
type compiler struct {
	pattern            stringSource
	rawFlags           string
	flags              Flag
	byteCode           []func(vm *machine)
	capturesCount      int
	totalCapturesCount int
	namedCapturesAhead map[int]namedCaptureAhead
	namedCaptures      map[string][]int
	allNamedCaptures   map[string]struct{}
	direction          patternDirection
}

func (c *compiler) isUnicode() bool {
	return c.flags&(FlagUnicode|FlagUnicodeSets) != 0
}

func isASCIIWordChar[T uint16 | rune](c T) bool {
	return ((uint32(c) - '0') <= (9 - 0)) || (uint32(lowerASCII(c))-'a' <= 'z'-'a') || c == '_'
}

func (vm *machine) isEcmaWordCharacter(r rune) bool {
	return isASCIIWordChar(r) ||
		(vm.isUnicode() && vm.flags&FlagIgnoreCase != 0) &&
			isEcmaExtraWordChar(r)
}

func lowerASCII[T uint16 | rune](c T) T {
	return c | ('a' - 'A')
}

func isHexDigit(c uint16) bool {
	return ((c - '0') <= (9 - 0)) || (lowerASCII(c)-'a' <= 'f'-'a')
}

func isDigit(c uint16) bool {
	return (c - '0') <= 9
}
func isASCIILetterChar(c uint16) bool {
	return lowerASCII(c)-'a' <= 'z'-'a'
}

func parseHexDigit(c uint16) uint16 {
	return (c & 0b1111) + (c>>6)*9
}

type intLike interface {
	~int | ~rune
}

func max[T intLike](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T intLike](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func canonicalize(flags Flag, c rune) rune {
	caseInsensitive := flags&FlagIgnoreCase != 0
	if flags&flagEitherUnicode != 0 && caseInsensitive {
		folded, ok := unicodeSimpleCaseFolding[c]
		if ok {
			return folded
		}
		return c
	}
	if !caseInsensitive {
		return c
	}
	// TODO: in this branch of code, c is always <= 0xFFFF (in non-unicode mode
	// we're iterating over code units instead of codepoints), so keys > 0xFFFF
	// can be safely dropped from the unicodeUppercase_Mapping
	if uppercase, ok := unicodeUppercase_Mapping[c]; ok {
		if uppercase < 128 && c >= 128 {
			return c
		}
		return uppercase
	}
	return c
}

func simpleCaseFolding(c rune) rune {
	if res, ok := unicodeSimpleCaseFolding[c]; ok {
		return res
	}
	return c
}

type charRange struct {
	lo rune
	hi rune
}

// TODO(perf): use trie or something more clever
type stringSet struct {
	s map[string]struct{}
	// In Unicode codepoints
	minlen int
	// In Unicode codepoints
	maxlen int
}
type charSet struct {
	// Non-overlapping ranges sorted in ascending order
	chars   []charRange // TODO(perf): R16 & R32 for more efficient memory utilization?
	strings stringSet
}

func (s *charSet) clone() *charSet {
	res := *s
	res.chars = slices.Clone(res.chars)
	res.strings.s = maps.Clone(res.strings.s)
	return &res
}
func (s *charSet) union(other *charSet) {
	if s.chars == nil {
		s.chars = other.chars
	} else if other.chars != nil {
		chars := []charRange{}

		i := 0
		j := 0

		for {
			var next charRange
			if i < len(s.chars) && (j >= len(other.chars) || s.chars[i].lo < other.chars[j].lo) {
				next = s.chars[i]
				i++
			} else if j < len(other.chars) {
				next = other.chars[j]
				j++
			} else {
				break
			}
			if len(chars) == 0 {
				chars = append(chars, next)
				continue
			}
			r := &chars[len(chars)-1]
			if next.hi <= r.hi {
				continue
			}
			if next.lo <= r.hi+1 {
				r.hi = next.hi
				continue
			}
			chars = append(chars, next)
		}
		s.chars = chars
	}

	if s.strings.s != nil && other.strings.s != nil {
		maps.Copy(s.strings.s, other.strings.s)
		s.strings.minlen = min(s.strings.minlen, other.strings.minlen)
		s.strings.maxlen = max(s.strings.maxlen, other.strings.maxlen)
	} else if s.strings.s == nil {
		s.strings = other.strings
	}
}
func (s *charSet) unionChar(r rune) {
	if len(s.chars) == 0 {
		s.chars = []charRange{{lo: r, hi: r}}
		return
	}
	if r == s.chars[0].lo-1 {
		s.chars[0].lo--
		return
	}
	if r < s.chars[0].lo {
		s.chars = slices.Insert(s.chars, 0, charRange{lo: r, hi: r})
		return
	}
	// TODO(perf): binary search?
	for i := 0; i < len(s.chars); i++ {
		range_ := &s.chars[i]
		if range_.lo <= r && r <= range_.hi {
			return
		}
		if i < len(s.chars)-1 && range_.hi < r && r < s.chars[i+1].lo {
			if range_.hi+2 == s.chars[i+1].lo {
				range_.hi = s.chars[i+1].hi
				copy(s.chars[i+1:], s.chars[i+2:])
				s.chars = s.chars[:len(s.chars)-1]
			} else if range_.hi+1 == r {
				range_.hi++
			} else if s.chars[i+1].lo-1 == r {
				s.chars[i+1].lo--
			} else {
				s.chars = slices.Insert(s.chars, i+1, charRange{lo: r, hi: r})
			}
			return
		}
	}
	s.chars = append(s.chars, charRange{lo: r, hi: r})
}
func (s *charSet) unionString(str string) {
	if s.strings.s == nil {
		s.strings.s = map[string]struct{}{}
		s.strings.minlen = math.MaxInt
	}
	s.strings.s[str] = struct{}{}
	strlen := utf8.RuneCountInString(str)
	s.strings.minlen = min(s.strings.minlen, strlen)
	s.strings.maxlen = max(s.strings.maxlen, strlen)
}
func (s *charSet) intersection(other *charSet) {
	if s.chars == nil || other.chars == nil {
		s.chars = nil
	} else {
		chars := []charRange{}

		i := 0
		j := 0
		for i < len(s.chars) && j < len(other.chars) {
			a := s.chars[i]
			b := other.chars[j]

			lo := max(a.lo, b.lo)
			hi := min(a.hi, b.hi)

			if lo <= hi {
				chars = append(chars, charRange{lo: lo, hi: hi})
			}

			if a.hi < b.hi {
				i++
			} else {
				j++
			}
		}

		s.chars = chars
	}

	if s.strings.s == nil || other.strings.s == nil {
		s.strings = stringSet{}
		return
	}

	strs := stringSet{
		s:      map[string]struct{}{},
		minlen: math.MaxInt,
		maxlen: 0,
	}
	for k, v := range s.strings.s {
		if _, ok := other.strings.s[k]; ok {
			strs.s[k] = v
			strlen := utf8.RuneCountInString(k)
			strs.minlen = min(strs.minlen, strlen)
			strs.maxlen = max(strs.maxlen, strlen)
		}
	}
	if len(strs.s) == 0 {
		strs.minlen = 0
	}
	s.strings = strs
}
func (s *charSet) subtraction(other *charSet) {
	if s.chars != nil && other.chars != nil {
		chars := []charRange{}

		j := 0
		for _, sRange := range s.chars {
			for j < len(other.chars) && other.chars[j].hi < sRange.lo {
				j++
			}

			for j < len(other.chars) {
				oRange := other.chars[j]
				if oRange.lo > sRange.hi {
					break
				}
				if oRange.lo > sRange.lo {
					chars = append(chars, charRange{lo: sRange.lo, hi: oRange.lo - 1})
				}
				j++
				if oRange.hi < sRange.hi {
					sRange.lo = oRange.hi + 1
				} else {
					sRange.lo = sRange.hi + 1
				}
			}

			if sRange.lo <= sRange.hi {
				chars = append(chars, sRange)
			}
		}
		s.chars = chars
	}

	if s.strings.s == nil || other.strings.s == nil {
		return
	}
	strs := stringSet{
		s:      map[string]struct{}{},
		minlen: math.MaxInt,
		maxlen: 0,
	}
	for k, v := range s.strings.s {
		if _, ok := other.strings.s[k]; !ok {
			strs.s[k] = v
			strlen := utf8.RuneCountInString(k)
			strs.minlen = min(strs.minlen, strlen)
			strs.maxlen = max(strs.maxlen, strlen)
		}
	}
	if len(strs.s) == 0 {
		strs.minlen = 0
	}
	s.strings = strs
}
func (s *charSet) containsRune(r rune) bool {
	if s.chars == nil {
		return false
	}
	lo := 0
	hi := len(s.chars)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		range_ := s.chars[m]
		if range_.lo <= r && r <= range_.hi {
			return true
		}
		if r < range_.lo {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return false
}
func (s *charSet) maybeSimpleCaseFolding(flags Flag) charSet {
	if flags&(FlagUnicodeSets|FlagIgnoreCase) != FlagUnicodeSets|FlagIgnoreCase {
		return *s
	}
	return s.fold(simpleCaseFolding)
}
func (s *charSet) canonicalize(flags Flag) charSet {
	return s.fold(func(r rune) rune {
		return canonicalize(flags, r)
	})
}
func (s *charSet) fold(cb func(r rune) rune) charSet {
	// TODO(perf): this is SUPER ineffective. is there a better way?

	var res charSet

	if s.chars != nil {
		codepoints := []rune{}
		for _, range_ := range s.chars {
			for i := range_.lo; i <= range_.hi; i++ {
				codepoints = append(codepoints, cb(i))
			}
		}
		slices.Sort(codepoints)
		for i := 0; i < len(codepoints); {
			lo := codepoints[i]
			for i+1 < len(codepoints) && (codepoints[i] == codepoints[i+1] || codepoints[i]+1 == codepoints[i+1]) {
				i++
			}
			res.chars = append(res.chars, charRange{lo: lo, hi: codepoints[i]})
			i++
		}
	}

	if s.strings.s != nil {
		res.strings.s = map[string]struct{}{}
		res.strings.minlen = math.MaxInt
		res.strings.maxlen = 0
		buf := make([]rune, s.strings.maxlen)
		for str, _ := range s.strings.s {
			i := 0
			for _, r := range str {
				buf[i] = cb(r)
				i++
			}
			res.strings.s[string(buf[:i])] = struct{}{}
			res.strings.minlen = min(res.strings.minlen, i)
			res.strings.maxlen = max(res.strings.maxlen, i)
		}
		if len(s.strings.s) == 0 {
			res.strings.minlen = 0
		}
	}

	return res
}

// TODO: CharacterComplement -> AllCharacters returns CharSet of codepoints
// that do not have simple casefolding. My assumption is that we can simply
// invert to ranges to achieve the desired effect (since we will fold it
// later). But this assumption needs to be doublechecked.
func (s *charSet) complement() {
	if len(s.chars) == 0 {
		s.chars = []charRange{{lo: 0, hi: unicode.MaxRune}}
		return
	}
	// TODO(perf): we can avoid looping through all ranges if we store
	// []rune instead of []charRange

	if s.chars[0].lo == 0 {
		for i := 0; i < len(s.chars)-1; i++ {
			s.chars[i].lo = s.chars[i].hi + 1
			s.chars[i].hi = s.chars[i+1].lo - 1
		}
		lastRange := &s.chars[len(s.chars)-1]
		if lastRange.hi < unicode.MaxRune {
			lastRange.lo = lastRange.hi + 1
			lastRange.hi = unicode.MaxRune
		} else {
			s.chars = s.chars[:len(s.chars)-1]
		}
	} else {
		lastHi := s.chars[len(s.chars)-1].hi
		for i := len(s.chars) - 1; i >= 1; i-- {
			s.chars[i].hi = s.chars[i].lo - 1
			s.chars[i].lo = s.chars[i-1].hi + 1
		}
		s.chars[0].hi = s.chars[0].lo - 1
		s.chars[0].lo = 0
		if lastHi < unicode.MaxRune {
			s.chars = append(s.chars, charRange{lo: lastHi + 1, hi: unicode.MaxRune})
		}
	}
}

// Returns the position of inserted instruction
func (c *compiler) emit(v func(vm *machine)) int {
	pos := len(c.byteCode)
	c.byteCode = append(c.byteCode, v)
	return pos
}

func (c *compiler) compile() error {
	comptimeSticky := c.flags&FlagSticky == 0
	c.emit(func(vm *machine) {
		if vm.flags&FlagSticky == 0 && comptimeSticky {
			vm.pushBacktrackingFrame(vm.pc + 1)
			vm.pc += 2
		} else {
			vm.pc++
		}
	})
	c.emit(func(vm *machine) {
		if vm.flags&FlagSticky == 0 && comptimeSticky {
			vm.pc--
			vm.moveSP(patternDirectionForward)
		} else {
			vm.pc++
		}
	})

	c.capturesCount++

	c.emit(func(vm *machine) {
		vm.pc++
		vm.startCapture(0)

		vm.stack.push(vm.source.pos)
	})
	if err := c.compileDisjunction(); err != nil {
		return err
	}
	if !c.pattern.atEnd() {
		return newSyntaxError("extraneous characters at the end")
	}
	c.emit(func(vm *machine) {
		vm.pc++
		vm.endCapture(0)
	})
	return nil
}

// This function should be called only in non-'v' mode
func (c *compiler) getTotalCapturesCount() int {
	if c.totalCapturesCount != -1 {
		return c.totalCapturesCount
	}
	c.totalCapturesCount = c.capturesCount
	c.namedCapturesAhead = map[int]namedCaptureAhead{}
	patternCopy := c.pattern
	for !c.pattern.atEnd() {
		switch c.pattern.nextNthCodeUnitUnsafe(0) {
		case '(':
			c.pattern.pos++
			if !c.pattern.atEnd() {
				if c.pattern.nextNthCodeUnitUnsafe(0) == '?' {
					c.pattern.pos++
					next, _ := c.pattern.nextNthCodeUnit(0)
					nextnext, ended := c.pattern.nextNthCodeUnit(1)
					if !ended && next == '<' && nextnext != '=' && nextnext != '!' {
						c.totalCapturesCount++
						groupNameStart := c.pattern.pos
						name, err := c.parseGroupName()
						if err == nil {
							c.namedCapturesAhead[groupNameStart] = namedCaptureAhead{
								name: name,
								end:  c.pattern.pos,
							}
							c.allNamedCaptures[name] = struct{}{}
						}
						// invalid group name will be reported later
					}
				} else {
					c.totalCapturesCount++
				}
			}
		case '\\':
			c.pattern.pos++
			c.pattern.move(patternDirectionForward, c.isUnicode())
		case '[':
			c.pattern.pos++
		ScanCharacterClass:
			for !c.pattern.atEnd() {
				switch c.pattern.nextNthCodeUnitUnsafe(0) {
				case '\\':
					c.pattern.pos++
					c.pattern.move(patternDirectionForward, c.isUnicode())
				case ']':
					c.pattern.pos++
					break ScanCharacterClass
				default:
					c.pattern.pos++
				}
			}
		default:
			c.pattern.pos++
		}
	}
	c.pattern = patternCopy
	return c.totalCapturesCount
}

func (c *compiler) compileDisjunction() error {
	start := len(c.byteCode)
	initialNamedCaptures := maps.Clone(c.namedCaptures)
	namedCaptures := c.namedCaptures
	if err := c.compileAlternative(); err != nil {
		return err
	}

	for {
		char, ended := c.pattern.nextCodeUnit()
		if ended || char != '|' {
			break
		}
		c.pattern.pos++
		splitOffset := len(c.byteCode) - start + 1

		c.byteCode = slices.Insert(c.byteCode, start, func(vm *machine) {
			vm.pc++

			vm.pushBacktrackingFrame(vm.pc + splitOffset)
		})

		gotoOpPos := c.emit(nil)

		c.namedCaptures = maps.Clone(initialNamedCaptures)
		if err := c.compileAlternative(); err != nil {
			return err
		}
		for k, v := range c.namedCaptures {
			existing, ok := namedCaptures[k]
			if ok {
				namedCaptures[k] = append(existing, v...)
			} else {
				namedCaptures[k] = v
			}
		}

		gotoOffset := len(c.byteCode) - gotoOpPos - 1
		c.byteCode[gotoOpPos] = func(vm *machine) {
			vm.pc += 1 + gotoOffset
		}
	}
	c.namedCaptures = namedCaptures
	return nil
}
func (c *compiler) compileAlternative() error {
	alternativeStart := len(c.byteCode)

	for {
		char, ended := c.pattern.nextCodeUnit()
		if ended || char == '|' || char == ')' {
			break
		}
		termStart := len(c.byteCode)
		if err := c.compileTerm(); err != nil {
			return err
		}
		if c.direction == patternDirectionBackward {
			termEnd := len(c.byteCode)
			c.byteCode = slices.Insert(c.byteCode, alternativeStart, c.byteCode[termStart:termEnd]...)[:termEnd]
		}
	}
	return nil
}

// Returns whether assertion is found or not
func (c *compiler) compileAssertion() (bool, bool, error) {
	// compileTerm won't be called at the end of the pattern
	char := c.pattern.nextNthCodeUnitUnsafe(0)

	switch char {
	case '^':
		c.pattern.pos++
		c.emit(func(vm *machine) {
			vm.pc++

			if vm.flags&FlagMultiline == 0 {
				if !vm.source.atStart() {
					vm.noMatch()
				}
				return
			}
			if vm.source.atStart() {
				return
			}
			sourceCopy := vm.source
			src, moved := sourceCopy.move(patternDirectionBackward, vm.isUnicode())
			if !moved || !isEcmaLineTerminator(src) {
				vm.noMatch()
			}
		})
		return true, false, nil
	case '$':
		c.pattern.pos++
		c.emit(func(vm *machine) {
			vm.pc++

			if vm.flags&FlagMultiline == 0 {
				if !vm.source.atEnd() {
					vm.noMatch()
				}
				return
			}
			if vm.source.atEnd() {
				return
			}
			sourceCopy := vm.source
			src, moved := sourceCopy.move(patternDirectionForward, vm.isUnicode())
			if !moved || !isEcmaLineTerminator(src) {
				vm.noMatch()
			}
		})
		return true, false, nil
	case '\\':
		char, ended := c.pattern.nextNthCodeUnit(1)
		if ended {
			return false, false, nil
		}
		if char != 'b' && char != 'B' {
			return false, false, nil
		}
		c.pattern.pos += 2
		matchCondition := char != 'b'
		c.emit(func(vm *machine) {
			vm.pc++

			source := vm.source
			curr, _ := source.move(patternDirectionForward, vm.isUnicode())
			source = vm.source
			prev, _ := source.move(patternDirectionBackward, vm.isUnicode())

			if (vm.isEcmaWordCharacter(prev) == vm.isEcmaWordCharacter(curr)) == matchCondition {
				return
			}
			vm.noMatch()
		})
		return true, false, nil
	case '(':
		char, _ := c.pattern.nextNthCodeUnit(1)
		if char != '?' {
			return false, false, nil
		}

		char, _ = c.pattern.nextNthCodeUnit(2)

		direction := patternDirectionForward
		posAdvancement := 3

		if char == '<' {
			char, _ = c.pattern.nextNthCodeUnit(3)
			direction = patternDirectionBackward
			posAdvancement++
		}

		if char == '=' {
			c.pattern.pos += posAdvancement
			c.emit(func(vm *machine) {
				vm.pc++
				vm.stack.push(vm.source.pos)
				vm.stack.push(len(vm.backtrackingStack))
			})

			prevDir := c.direction
			c.direction = direction

			if err := c.compileDisjunction(); err != nil {
				return false, false, err
			}

			c.direction = prevDir

			if !c.pattern.consumeNextCodeUnit(')') {
				return false, false, newSyntaxError("unterminated assertion")
			}
			c.emit(func(vm *machine) {
				vm.pc++
				vm.backtrackingStack.truncate(vm.stack.pop())
				vm.source.pos = vm.stack.pop()
			})
			return true, direction == patternDirectionForward, nil
		} else if char == '!' {
			c.pattern.pos += posAdvancement
			instructionBeforeDisjunction := c.emit(nil)

			prevDir := c.direction
			c.direction = direction
			lenBeforeDisjunction := len(c.byteCode)

			if err := c.compileDisjunction(); err != nil {
				return false, false, err
			}

			disjunctionSize := len(c.byteCode) - lenBeforeDisjunction
			c.byteCode[instructionBeforeDisjunction] = func(vm *machine) {
				vm.pc++
				vm.pushBacktrackingFrame(vm.pc + disjunctionSize + 1)
				vm.stack.push(len(vm.backtrackingStack) - 1)
			}
			c.direction = prevDir

			if !c.pattern.consumeNextCodeUnit(')') {
				return false, false, newSyntaxError("unterminated assertion")
			}
			c.emit(func(vm *machine) {
				vm.backtrackingStack.truncate(vm.stack.pop())
				vm.noMatch()
			})
			return true, direction == patternDirectionForward, nil
		}
		return false, false, nil
	default:
		return false, false, nil
	}
}

func isHighSurrogate(r rune) bool {
	return (r >> 10) == (0xd800 >> 10)
}
func isLowSurrogate(r rune) bool {
	return (r >> 10) == (0xdc00 >> 10)
}
func isSurrogate(r rune) bool {
	return uint32(r)-0xd800 < 0xe000-0xd800
}

func (c *compiler) peek4HexDigits() (rune, bool) {
	fourthChar, ended := c.pattern.nextNthCodeUnit(3)
	if ended {
		return 0, false
	}
	if !isHexDigit(c.pattern.nextNthCodeUnitUnsafe(0)) ||
		!isHexDigit(c.pattern.nextNthCodeUnitUnsafe(1)) ||
		!isHexDigit(c.pattern.nextNthCodeUnitUnsafe(2)) ||
		!isHexDigit(fourthChar) {
		return 0, false
	}
	r := (rune(parseHexDigit(c.pattern.nextNthCodeUnitUnsafe(0))) << 12) |
		(rune(parseHexDigit(c.pattern.nextNthCodeUnitUnsafe(1))) << 8) |
		(rune(parseHexDigit(c.pattern.nextNthCodeUnitUnsafe(2))) << 4) |
		rune(parseHexDigit(fourthChar))
	return r, true
}

func (c *compiler) parseUnicodeEscapeSequence(unicodeMode bool) (rune, bool, error) {
	next, ended := c.pattern.nextCodeUnit()
	if ended {
		return 0, false, newSyntaxError("invalid Unicode escape")
	}
	if next == '{' && unicodeMode {
		c.pattern.pos++
		codepointStart := c.pattern.pos
		i := 0
		for ; ; i++ {
			char, ended := c.pattern.nextNthCodeUnit(i)
			if ended {
				return 0, false, newSyntaxError("invalid group name: invalid unicode escape")
			}
			if char == '}' {
				break
			}
		}
		codepointEnd := codepointStart + i
		src := c.pattern.stringInRange(codepointStart, codepointEnd)
		codepoint, err := strconv.ParseUint(src, 16, 64)
		if err != nil || codepoint > unicode.MaxRune {
			return 0, false, newSyntaxError("invalid group name: invalid unicode codepoint")
		}
		c.pattern.pos = codepointEnd + 1
		return rune(codepoint), true, nil
	}

	r, ok := c.peek4HexDigits()
	if !ok {
		return 0, false, newSyntaxError("invalid Unicode escape")
	}
	c.pattern.pos += 4
	if unicodeMode && isHighSurrogate(r) {
		if x, _ := c.pattern.nextNthCodeUnit(1); x == 'u' && c.pattern.nextNthCodeUnitUnsafe(0) == '\\' {
			c.pattern.pos += 2
			l, ok := c.peek4HexDigits()
			if ok && isLowSurrogate(l) {
				c.pattern.pos += 4
				r = utf16.DecodeRune(r, l)
			} else {
				c.pattern.pos -= 2
			}
		}
	}
	return r, false, nil
}

func (c *compiler) parseCharacterEscape() (rune, error) {
	// parseCharacterEscape is always called after parseCharacterClassEscape or similar
	char := c.pattern.nextNthCodeUnitUnsafe(0)
	switch char {
	case 't', 'n', 'v', 'f', 'r':
		c.pattern.pos++
		mapping := [...]rune{
			't' - 'f': '\t',
			'n' - 'f': '\n',
			'v' - 'f': '\v',
			'f' - 'f': '\f',
			'r' - 'f': '\r',
		}
		return mapping[char-'f'], nil
	case 'c':
		c.pattern.pos++
		ch, _ := c.pattern.nextCodeUnit()
		if !isASCIILetterChar(ch) {
			if c.flags&FlagAnnexB != 0 {
				c.pattern.pos--
				return '\\', nil
			}
			return 0, newSyntaxError(`invalid \c`)
		}
		c.pattern.pos++
		return rune(ch) % 32, nil
	case '0':
		next, _ := c.pattern.nextNthCodeUnit(1)
		if !isDigit(next) {
			c.pattern.pos++
			return 0, nil
		}
		if c.flags&FlagAnnexB == 0 {
			return 0, newSyntaxError("invalid decimal escape")
		}
		if next == '8' || next == '9' {
			c.pattern.pos++
			return 0, nil
		}
		fallthrough
	case '1', '2', '3':
		if c.flags&FlagAnnexB == 0 {
			return 0, newSyntaxError("invalid decimal escape")
		}
		first := char - '0'
		c.pattern.pos++
		second, _ := c.pattern.nextCodeUnit()
		second = second - '0'

		if second >= '8'-'0' {
			return rune(first), nil
		}

		c.pattern.pos++
		third, _ := c.pattern.nextCodeUnit()
		third = third - '0'

		if third >= '8'-'0' {
			return rune(first*8 + second), nil
		}

		c.pattern.pos++
		return rune(first)*64 + rune(second)*8 + rune(third), nil
	case '4', '5', '6', '7':
		if c.flags&FlagAnnexB == 0 {
			return 0, newSyntaxError("invalid decimal escape")
		}
		first := char - '0'
		c.pattern.pos++
		second, _ := c.pattern.nextCodeUnit()
		second = second - '0'

		if second >= '8'-'0' {
			return rune(first), nil
		}
		c.pattern.pos++
		return rune(first*8 + second), nil
	case 'x':
		c.pattern.pos++
		first, _ := c.pattern.nextCodeUnit()
		second, _ := c.pattern.nextNthCodeUnit(1)

		if isHexDigit(first) && isHexDigit(second) {
			c.pattern.pos += 2
			return (rune(parseHexDigit(first)) << 4) | rune(parseHexDigit(second)), nil
		} else if c.flags&FlagAnnexB == 0 {
			return 0, newSyntaxError(`invalid \x`)
		}
		return 'x', nil
	case 'u':
		c.pattern.pos++
		patternCopy := c.pattern
		r, _, err := c.parseUnicodeEscapeSequence(c.isUnicode())
		if err != nil && c.flags&FlagAnnexB != 0 {
			c.pattern = patternCopy
			return 'u', nil
		}
		return r, err
	case '^', '$', '\\', '/', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|':
		if c.isUnicode() {
			c.pattern.pos++
			return rune(char), nil
		}
		fallthrough
	default:
		if c.isUnicode() {
			return 0, newSyntaxError("invalid escape")
		}
		r, _ := c.pattern.move(patternDirectionForward, false)
		if c.flags&FlagAnnexB == 0 && unicodeID_Continue.containsRune(r) {
			return 0, newSyntaxError("invalid escape")
		}
		return r, nil
	}
}

func (c *compiler) parseGroupName() (string, error) {
	if !c.pattern.consumeNextCodeUnit('<') {
		return "", newSyntaxError("invalid group name")
	}
	name := []rune{}
	for {
		r, moved := c.pattern.move(patternDirectionForward, c.isUnicode())
		if !moved {
			return "", newSyntaxError("invalid group name")
		}
		if r == '\\' && c.pattern.consumeNextCodeUnit('u') {
			var err error
			var isCodepoint bool
			r, isCodepoint, err = c.parseUnicodeEscapeSequence(true)
			if err != nil {
				return "", err
			}
			if isCodepoint && isSurrogate(r) {
				return "", newSyntaxError("invalid group name")
			}
		}
		if r == '>' {
			if len(name) > 0 && isHighSurrogate(name[len(name)-1]) {
				return "", newSyntaxError("invalid group name: lone surrogate")
			}
			break
		} else if len(name) > 0 && isHighSurrogate(name[len(name)-1]) {
			if isLowSurrogate(r) {
				name[len(name)-1] = utf16.DecodeRune(name[len(name)-1], r)
			} else {
				return "", newSyntaxError("invalid group name: lone surrogate")
			}
		} else {
			name = append(name, r)
		}

		if isHighSurrogate(name[len(name)-1]) {
			continue
		}

		if len(name) == 1 && !ecmaID_Start.containsRune(name[0]) {
			return "", newSyntaxError("invalid group name: first codepoint is not ID_Start")
		} else if len(name) > 1 && !ecmaID_Continue.containsRune(name[len(name)-1]) {
			return "", newSyntaxError("invalid group name: codepoint is not ID_Continue")
		}
	}
	if len(name) == 0 {
		return "", newSyntaxError("empty group name")
	}
	return string(name), nil
}

func (c *compiler) parseClassSetCharacter() (rune, error) {
	char, ended := c.pattern.nextCodeUnit()
	if ended {
		return 0, newSyntaxError("unterminated class set")
	}
	switch char {
	case '\\':
		c.pattern.pos++
		nextChar, ended := c.pattern.nextCodeUnit()
		if ended {
			return 0, newSyntaxError("unterminated class set")
		}
		switch nextChar {
		case '&', '-', '!', '#', '%', ',', ':', ';', '<', '=', '>', '@', '`', '~':
			c.pattern.pos++
			return rune(nextChar), nil
		case 'b':
			c.pattern.pos++
			// backspace
			return '\u0008', nil
		case ']':
			return 0, newSyntaxError("class set: invalid character")
		}
		return c.parseCharacterEscape()
	case '(', ')', '[', ']', '{', '}', '/', '-', '|':
		return 0, newSyntaxError("class set: invalid character")
	case '&', '!', '#', '$', '%', '*', '+', ',', '.', ':', ';', '<', '=', '>', '?', '@', '^', '`', '~':
		if nextChar, ended := c.pattern.nextNthCodeUnit(1); !ended && nextChar == char {
			return 0, newSyntaxError("class set: invalid operation")
		}
		c.pattern.pos++
		return rune(char), nil
	default:
		r, _ := c.pattern.move(patternDirectionForward, true)
		return r, nil
	}
}

func (c *compiler) parseClassSetOperand() (*charSet, bool, bool, bool, error) {
	char, ended := c.pattern.nextCodeUnit()
	if ended {
		return nil, false, false, false, newSyntaxError("unterminated class set")
	}
	switch char {
	case '\\':
		className, ended := c.pattern.nextNthCodeUnit(1)
		if ended {
			return nil, false, false, false, newSyntaxError("unterminated class set")
		}
		c.pattern.pos++
		switch className {
		case 'q':
			c.pattern.pos++
			if !c.pattern.consumeNextCodeUnit('{') {
				return nil, false, false, false, newSyntaxError("class set: invalid character class")
			}
			classString := []rune{}
			set := &charSet{}
			for {
				if c.pattern.consumeNextCodeUnit('}') {
					if len(classString) == 1 {
						set.unionChar(classString[0])
					} else {
						set.unionString(string(classString))
					}
					(*set) = set.maybeSimpleCaseFolding(c.flags)
					return set, len(set.strings.s) > 0, false, false, nil
				}
				if c.pattern.consumeNextCodeUnit('|') {
					if len(classString) == 1 {
						set.unionChar(classString[0])
					} else {
						set.unionString(string(classString))
					}
					classString = classString[:0]
					continue
				}
				r, err := c.parseClassSetCharacter()
				if err != nil {
					return nil, false, false, false, err
				}
				classString = append(classString, r)
			}
		}
		s, err := c.parseCharacterClassEscape()
		if err != nil {
			return nil, false, false, false, err
		}
		if s == nil {
			c.pattern.pos--
			break
		}
		return s, len(s.strings.s) > 0, false, false, nil
	case '[':
		c.pattern.pos++
		s, mayContainStrings, err := c.compileClassSet()
		return s, mayContainStrings, false, false, err
	case ']':
		c.pattern.pos++
		return nil, false, false, true, nil
	}
	r, err := c.parseClassSetCharacter()
	if err != nil {
		return nil, false, false, false, err
	}
	set := &charSet{}
	set.chars = []charRange{{lo: r, hi: r}}
	return set, false, true, false, nil
}

func (c *compiler) compileClassSet() (*charSet, bool, error) {
	inverted := c.pattern.consumeNextCodeUnit('^')

	set, ch1MayContainStrings, ch1IsClassSetCharacter, foundEndOfClass, err := c.parseClassSetOperand()
	if err != nil {
		return nil, false, err
	}
	if foundEndOfClass {
		s := &charSet{}
		if inverted {
			s.complement()
		}
		return s, false, nil
	}

	// ClassIntersection
	next, _ := c.pattern.nextNthCodeUnit(0)
	nextnext, _ := c.pattern.nextNthCodeUnit(1)
	if next == '&' && nextnext == '&' {
		intersectionMayContainStrings := ch1MayContainStrings
		if ch1IsClassSetCharacter {
			(*set) = set.maybeSimpleCaseFolding(c.flags)
		}
		for {
			if !c.pattern.consumeNextCodeUnit('&') || !c.pattern.consumeNextCodeUnit('&') {
				return nil, false, newSyntaxError("class set: expected &&")
			}
			if c.pattern.consumeNextCodeUnit('&') {
				return nil, false, newSyntaxError("class set: & is not allowed here")
			}
			operand, mayContainStrings, isClassSetCharacter, foundEndOfClass, err := c.parseClassSetOperand()
			if err != nil {
				return nil, false, err
			}
			if foundEndOfClass {
				return nil, false, newSyntaxError("class set: invalid intersection")
			}
			if inverted && intersectionMayContainStrings && mayContainStrings {
				return nil, false, newSyntaxError("negated character class may contain strings")
			}
			intersectionMayContainStrings = intersectionMayContainStrings || mayContainStrings
			if isClassSetCharacter {
				(*operand) = operand.maybeSimpleCaseFolding(c.flags)
			}
			set.intersection(operand)
			if c.pattern.consumeNextCodeUnit(']') {
				if inverted {
					set.complement()
				}
				return set, intersectionMayContainStrings, nil
			}
		}
	}

	{
		// '-' is disallowed in ClassSetCharacter, so we can safely consume it here
		nextIsDash := c.pattern.consumeNextCodeUnit('-')
		// ClassSubtraction
		if nextIsDash && c.pattern.consumeNextCodeUnit('-') {
			if inverted && ch1MayContainStrings {
				return nil, false, newSyntaxError("negated character class may contain strings")
			}
			if ch1IsClassSetCharacter {
				(*set) = set.maybeSimpleCaseFolding(c.flags)
			}
			for {
				operand, _, isClassSetCharacter, foundEndOfClass, err := c.parseClassSetOperand()
				if err != nil {
					return nil, false, err
				}
				if foundEndOfClass {
					return nil, false, newSyntaxError("invalid character class")
				}
				if isClassSetCharacter {
					(*operand) = operand.maybeSimpleCaseFolding(c.flags)
				}
				set.subtraction(operand)
				if c.pattern.consumeNextCodeUnit(']') {
					if inverted {
						set.complement()
					}
					return set, ch1MayContainStrings, nil
				}
				if !c.pattern.consumeNextCodeUnit('-') || !c.pattern.consumeNextCodeUnit('-') {
					return nil, false, newSyntaxError("class set: expected --")
				}
			}
		}

		// ClassUnion:
		// - ClassUnion allows ClassSetRange (or ClassSetOperand)
		// - ClassSetRange allows only ClassSetCharacter (not ClassSetOperand)
		if ch1IsClassSetCharacter && nextIsDash {
			ch2, err := c.parseClassSetCharacter()
			if err != nil {
				return nil, false, err
			}
			ch1 := set.chars[0].lo
			if ch1 > ch2 {
				return nil, false, newSyntaxError("class set: range out of order")
			}

			set = &charSet{chars: []charRange{{lo: ch1, hi: ch2}}}
			(*set) = set.maybeSimpleCaseFolding(c.flags)
		}
	}

	unionMayContainStrings := ch1MayContainStrings
	if inverted && unionMayContainStrings {
		return nil, false, newSyntaxError("negated character class may contain strings")
	}
	for {
		operand, mayContainStrings, isClassSetCharacter, foundEndOfClass, err := c.parseClassSetOperand()
		if err != nil {
			return nil, false, err
		}
		if foundEndOfClass {
			if inverted {
				set.complement()
			}
			return set, unionMayContainStrings, nil
		}
		if isClassSetCharacter {
			lo := operand.chars[0].lo
			if c.pattern.consumeNextCodeUnit('-') {
				hi, err := c.parseClassSetCharacter()
				if err != nil {
					return nil, false, err
				}
				if lo > hi {
					return nil, false, newSyntaxError("class set: range out of order")
				}
				operand = &charSet{chars: []charRange{{lo: lo, hi: hi}}}
			} else {
				operand = &charSet{chars: []charRange{{lo: lo, hi: lo}}}
			}
			(*operand) = operand.maybeSimpleCaseFolding(c.flags)
		} else {
			unionMayContainStrings = unionMayContainStrings || mayContainStrings
			if inverted && unionMayContainStrings {
				return nil, false, newSyntaxError("negated character class may contain strings")
			}
		}
		set.union(operand)
	}
}

var digitCharSet = &charSet{
	chars: []charRange{
		{lo: '0', hi: '9'},
	},
}
var asciiWordCharSet = &charSet{
	chars: []charRange{
		{lo: '0', hi: '9'},
		{lo: 'A', hi: 'Z'},
		{lo: '_', hi: '_'},
		{lo: 'a', hi: 'z'},
	},
}

// TODO(perf): maybe it worth using more efficient checks for class escapes
// outside of character class (i.e. /\d[]/). This way we can use more simple
// checkes (e.g. isDigitRune), instead of expensive *charSet.
// P.S. git-blame this comment to know the commit that removed efficient checks
func (c *compiler) parseCharacterClassEscape() (*charSet, error) {
	char, ended := c.pattern.nextCodeUnit()
	if ended {
		return nil, newSyntaxError("invalid escape")
	}
	inverted := false
	var set *charSet
	switch char {
	case 'D':
		inverted = true
		fallthrough
	case 'd':
		c.pattern.pos++
		set = digitCharSet.clone()
		if inverted {
			set.complement()
		}
		return set, nil
	case 'S':
		inverted = true
		fallthrough
	case 's':
		c.pattern.pos++
		set = ecmaWhiteSpaceOrLineTerminator.clone()
		if inverted {
			set.complement()
		}
		return set, nil
	case 'W':
		inverted = true
		fallthrough
	case 'w':
		c.pattern.pos++
		set = asciiWordCharSet.clone()
		if c.isUnicode() && c.flags&FlagIgnoreCase != 0 {
			set.union(ecmaExtraWordChars.clone())
		}
	case 'P':
		inverted = true
		fallthrough
	case 'p':
		c.pattern.pos++
		if c.flags&FlagAnnexB != 0 {
			ch := canonicalize(c.flags, rune(char))
			return &charSet{chars: []charRange{{lo: ch, hi: ch}}}, nil
		}
		if !c.isUnicode() {
			return nil, newSyntaxError(`\p is not allowed in non-Unicode mode`)
		}
		if !c.pattern.consumeNextCodeUnit('{') {
			return nil, newSyntaxError(`expected { after \p`)
		}

		nameOrValueStart := c.pattern.pos
		var nameOrValue string
		var value string
		for {
			ch, ended := c.pattern.nextCodeUnit()
			if ended {
				return nil, newSyntaxError("invalid property value")
			}
			if ch == '}' {
				nameOrValue = c.pattern.stringInRange(nameOrValueStart, c.pattern.pos)
				c.pattern.pos++
				break
			} else if ch == '=' {
				nameOrValue = c.pattern.stringInRange(nameOrValueStart, c.pattern.pos)
				c.pattern.pos++
				valueStart := c.pattern.pos
				for {
					ch, ended := c.pattern.nextCodeUnit()
					if ended {
						return nil, newSyntaxError("invalid property value")
					}
					if ch == '}' {
						value = c.pattern.stringInRange(valueStart, c.pattern.pos)
						c.pattern.pos++
						break
					} else if isASCIIWordChar(ch) {
						c.pattern.pos++
					} else if !c.pattern.consumeNextCodeUnit('}') {
						return nil, newSyntaxError("invalid property value")
					}
				}
				break
			}
			if isASCIIWordChar(ch) {
				c.pattern.pos++
			} else {
				return nil, newSyntaxError("invalid property name")
			}
		}

		var foundValue bool

		if value == "" {
			if !inverted {
				switch nameOrValue {
				case "Basic_Emoji":
					set = unicodeBasic_Emoji
				case "Emoji_Keycap_Sequence":
					set = unicodeEmoji_Keycap_Sequence
				case "RGI_Emoji_Modifier_Sequence":
					set = unicodeRGI_Emoji_Modifier_Sequence
				case "RGI_Emoji_Flag_Sequence":
					set = unicodeRGI_Emoji_Flag_Sequence
				case "RGI_Emoji_Tag_Sequence":
					set = unicodeRGI_Emoji_Tag_Sequence
				case "RGI_Emoji_ZWJ_Sequence":
					set = unicodeRGI_Emoji_ZWJ_Sequence
				case "RGI_Emoji":
					set = unicodeRGI_Emoji
				}
				if set != nil {
					if c.flags&FlagUnicodeSets == 0 {
						return nil, newSyntaxError("character class escape: properties of strings allowed only with 'v' flag")
					}
					set = set.clone()
					break
				}
			}

			set, foundValue = unicodePropertyAliases[nameOrValue]
			if !foundValue {
				set, foundValue = unicodePropertyValueAliases_General_Category[nameOrValue]
			}
			goto CheckProperty
		}

		switch nameOrValue {
		case "General_Category", "gc":
			set, foundValue = unicodePropertyValueAliases_General_Category[value]
		case "Script", "sc":
			set, foundValue = unicodePropertyValueAliases_Script[value]
		case "Script_Extensions", "scx":
			set, foundValue = unicodePropertyValueAliases_Script_Extensions[value]
		default:
			return nil, newSyntaxError("invalid property name")
		}
	CheckProperty:
		if !foundValue {
			return nil, newSyntaxError("invalid property value")
		}
		set = set.clone()
	default:
		return nil, nil
	}
	if c.flags&FlagUnicodeSets != 0 {
		(*set) = set.maybeSimpleCaseFolding(c.flags)
	}
	if inverted {
		set.complement()
	}
	if c.flags&FlagUnicodeSets == 0 {
		(*set) = set.canonicalize(c.flags)
	}
	return set, nil
}

// Returns address of the first matcher instruction
func (c *compiler) emitCharSetMatcher(s *charSet) {
	direction := c.direction
	// TODO(perf): right now we push backtracking frame for every possible string length.
	// But this means that for long strings, lot of instructions will be emitted.
	// Maybe we can add new stack for strings and point backtracking frame to
	// the same instruction.
	for strlen := s.strings.maxlen; strlen >= s.strings.minlen && len(s.strings.s) > 0; strlen-- {
		splitOffset := strlen - s.strings.minlen + 1
		if s.strings.minlen != 0 {
			splitOffset++
		}
		if strlen == 0 {
			c.emit(func(vm *machine) {
				// empty string always matches
				vm.pc++

				if s.chars == nil {
					return
				}
				vm.pushBacktrackingFrame(vm.pc)

				r, matched := vm.moveSP(direction)
				r = canonicalize(vm.flags, r)
				if matched && !s.containsRune(r) {
					vm.noMatch()
				}
			})
		} else {
			strlen := strlen
			c.emit(func(vm *machine) {
				vm.pushBacktrackingFrame(vm.pc + 1)
				vm.pc += splitOffset

				buf := make([]rune, strlen)
				for i := 0; i < strlen; i++ {
					j := i
					if direction == patternDirectionBackward {
						j = strlen - i - 1
					}
					var matched bool
					buf[j], matched = vm.moveSP(direction)
					if !matched {
						return
					}
					buf[j] = canonicalize(vm.flags, buf[j])
				}
				if _, ok := s.strings.s[string(buf)]; !ok {
					vm.noMatch()
				}
			})
		}
	}

	// if strings.minlen == 0, chars will be checked in the last instruction
	// emitted in the loop above
	if len(s.strings.s) == 0 || s.strings.minlen != 0 {
		c.emit(func(vm *machine) {
			vm.pc++

			r, matched := vm.moveSP(direction)
			r = canonicalize(vm.flags, r)
			if matched && !s.containsRune(r) {
				vm.noMatch()
			}
		})
	}
}

func (c *compiler) parseClassAtom() (rune, *charSet, bool, bool, error) {
	char, moved := c.pattern.move(patternDirectionForward, c.isUnicode())
	if !moved {
		return 0, nil, false, false, nil
	}
	if char == ']' {
		return 0, nil, true, false, nil
	}
	if char == '\\' {
		next, _ := c.pattern.nextCodeUnit()
		switch next {
		case '-':
			c.pattern.pos++
			return '-', nil, false, true, nil
		case 'b':
			c.pattern.pos++
			// backspace
			return '\u0008', nil, false, true, nil
		case 'c':
			if c.flags&FlagAnnexB != 0 {
				nextnext, _ := c.pattern.nextNthCodeUnit(1)
				if isDigit(nextnext) || nextnext == '_' {
					c.pattern.pos += 2
					return rune(nextnext) % 32, nil, false, true, nil
				}
			}
		}
		s, err := c.parseCharacterClassEscape()
		if err != nil {
			return 0, nil, false, false, err
		}
		if s != nil {
			return 0, s, false, true, nil
		}
		r, err := c.parseCharacterEscape()
		if err != nil {
			return 0, nil, false, false, err
		}
		return r, nil, false, true, nil
	}
	return char, nil, false, true, nil
}

func (c *compiler) compileAtom() error {
	// compileTerm won't be called at the end of the pattern
	char := c.pattern.nextNthCodeUnitUnsafe(0)

	direction := c.direction

	switch char {
	case '.':
		c.pattern.pos++
		c.emit(func(vm *machine) {
			vm.pc++

			src, matched := vm.moveSP(direction)
			if !matched {
				return
			}
			if !isEcmaLineTerminator(src) {
				return
			}
			if vm.flags&FlagDotAll == 0 {
				vm.noMatch()
			}
		})
		return nil
	case '[':
		c.pattern.pos++
		if c.flags&FlagUnicodeSets != 0 {
			s, _, err := c.compileClassSet()
			if err != nil {
				return err
			}
			c.emitCharSetMatcher(s)
			return nil
		}

		inverted := c.pattern.consumeNextCodeUnit('^')

		set := charSet{}

		for {
			leftR, leftS, foundEndOfClass, ok, err := c.parseClassAtom()
			if err != nil {
				return err
			}
			if !ok {
				if !foundEndOfClass {
					return newSyntaxError("character class: unexpected end of pattern")
				}
				break
			}

			if !c.pattern.consumeNextCodeUnit('-') {
				if leftS != nil {
					set.union(leftS)
				} else {
					set.unionChar(leftR)
				}
				continue
			}

			rightR, rightS, foundEndOfClass, ok, err := c.parseClassAtom()
			if err != nil {
				return err
			}
			if !ok {
				if !foundEndOfClass {
					return newSyntaxError("character class: unexpected end of pattern")
				}
				if leftS != nil {
					set.union(leftS)
				} else {
					set.unionChar(leftR)
				}
				set.unionChar('-')
				break
			}
			if leftS != nil || rightS != nil {
				if c.flags&FlagAnnexB == 0 {
					return newSyntaxError("character class: using character class in range is not allowed")
				}
				if leftS == nil {
					set.unionChar(leftR)
				} else {
					set.union(leftS)
				}
				if rightS == nil {
					set.unionChar(rightR)
				} else {
					set.union(rightS)
				}
				set.unionChar('-')
				continue
			}
			if leftR > rightR {
				return newSyntaxError("range out of order in character class")
			}
			set.union(&charSet{chars: []charRange{{lo: leftR, hi: rightR}}})
		}
		set = set.canonicalize(c.flags)

		c.emit(func(vm *machine) {
			vm.pc++

			src, matched := vm.moveSP(direction)
			if !matched {
				return
			}
			src = canonicalize(vm.flags, src)

			if len(set.chars) == 0 {
				if !inverted {
					vm.noMatch()
				}
				return
			}

			if set.containsRune(src) == inverted {
				vm.noMatch()
			}
		})
		return nil
	case '(':
		c.pattern.pos++

		questionMark := c.pattern.consumeNextCodeUnit('?')
		next, ended := c.pattern.nextCodeUnit()
		if ended {
			return newSyntaxError("unterminated group")
		}

		if questionMark && next != '<' {
			var add Flag
			var flags Flag
			foundDash := false

			for {
				next, ended = c.pattern.nextCodeUnit()
				if ended {
					return newSyntaxError("unterminated group")
				}
				c.pattern.pos++
				var f Flag
				switch next {
				case 'i':
					f = FlagIgnoreCase
				case 'm':
					f = FlagMultiline
				case 's':
					f = FlagDotAll
				case '-':
					if foundDash {
						return newSyntaxError("multiple dashes in flag group")
					}
					foundDash = true
					add = flags
				case ':':
					if foundDash {
						if flags == 0 {
							return newSyntaxError("invalid flag group")
						}
						flags ^= add
					} else {
						add = flags
						flags = 0
					}
					oldFlags := c.flags
					newFlags := (c.flags | add) & (^flags)
					c.flags = newFlags
					c.emit(func(vm *machine) {
						vm.pc++
						vm.flags = newFlags
					})
					if err := c.compileDisjunction(); err != nil {
						return err
					}
					c.flags = oldFlags
					if !c.pattern.consumeNextCodeUnit(')') {
						return newSyntaxError("unterminated group")
					}
					c.emit(func(vm *machine) {
						vm.pc++
						vm.flags = oldFlags
					})
					return nil
				default:
					return newSyntaxError("invalid group")
				}
				if flags&f != 0 {
					return newSyntaxError("repeated flag in flag group")
				}
				flags |= f
			}
		}

		captureIndex := c.capturesCount
		c.capturesCount++

		if questionMark {
			var groupName string
			if c.namedCapturesAhead != nil {
				if g, ok := c.namedCapturesAhead[c.pattern.pos]; ok {
					groupName = g.name
					c.pattern.pos = g.end
				}
			}
			if groupName == "" {
				var err error
				groupName, err = c.parseGroupName()
				if err != nil {
					return err
				}
			}
			if _, ok := c.namedCaptures[groupName]; ok {
				return newSyntaxError("duplicated group name: " + groupName)
			}
			c.namedCaptures[groupName] = []int{captureIndex}
			c.allNamedCaptures[groupName] = struct{}{}
		}

		startInstruction := func(vm *machine) {
			vm.pc++
			vm.startCapture(captureIndex)
		}
		endInstruction := func(vm *machine) {
			vm.pc++
			vm.endCapture(captureIndex)
		}

		if direction == patternDirectionBackward {
			startInstruction, endInstruction = endInstruction, startInstruction
		}
		c.emit(startInstruction)
		if err := c.compileDisjunction(); err != nil {
			return err
		}
		c.emit(endInstruction)
		if !c.pattern.consumeNextCodeUnit(')') {
			return newSyntaxError("unterminated group")
		}
		return nil
	case '\\':
		c.pattern.pos++
		char, ended := c.pattern.nextCodeUnit()
		if ended {
			return newSyntaxError("invalid escape")
		}
		if char != '0' {
			patternCopy := c.pattern
			num, ok := c.parseDecimalDigits()
			if ok {
				if num < c.getTotalCapturesCount() {
					c.emit(func(vm *machine) {
						vm.pc++
						if vm.matchesCapture(direction, num) == captureMatchKindFalse {
							vm.noMatch()
						}
					})
					return nil
				} else if c.flags&FlagAnnexB == 0 {
					return newSyntaxError("backreference to non-existent capturing group")
				}
				c.pattern = patternCopy
			}
		}

		var s *charSet
		var err error
		if char == 'k' {
			if c.flags&FlagAnnexB != 0 {
				c.getTotalCapturesCount()
				if len(c.allNamedCaptures) == 0 {
					goto ParseCharacterEscape
				}
			}
			c.pattern.pos++
			groupName, err := c.parseGroupName()
			if err != nil {
				return err
			}
			c.getTotalCapturesCount()
			if _, ok := c.allNamedCaptures[groupName]; !ok {
				return newSyntaxError("unknown group name")
			}
			c.emit(func(vm *machine) {
				vm.pc++
				for _, captureIndex := range vm.namedCaptures[groupName] {
					switch vm.matchesCapture(direction, captureIndex) {
					case captureMatchKindTrue:
						return
					case captureMatchKindFalse:
						vm.noMatch()
						return
					case captureMatchKindUnknown:
					}
				}
			})
			return nil
		}
		s, err = c.parseCharacterClassEscape()
		if err != nil {
			return err
		}
		if s != nil {
			c.emitCharSetMatcher(s)
			return nil
		}
	ParseCharacterEscape:
		r, err := c.parseCharacterEscape()
		if err != nil {
			return err
		}
		r = canonicalize(c.flags, r)
		c.emit(func(vm *machine) {
			vm.pc++
			src, matched := vm.moveSP(direction)
			if matched && canonicalize(vm.flags, src) != r {
				vm.noMatch()
			}
		})
		return nil
	case '{':
		if c.flags&FlagAnnexB == 0 {
			return newSyntaxError("nothing to repeat")
		}
		c.pattern.pos++
		patternCopy := c.pattern
		if _, ok := c.parseDecimalDigits(); ok {
			if c.pattern.consumeNextCodeUnit(',') {
				c.parseDecimalDigits()
			}
		}
		if c.pattern.consumeNextCodeUnit('}') {
			return newSyntaxError("nothing to repeat")
		}
		c.pattern = patternCopy
		c.emit(func(vm *machine) {
			vm.pc++
			src, matched := vm.moveSP(direction)
			if matched && src != '{' {
				vm.noMatch()
			}
		})
		return nil
	case '}':
		if c.flags&FlagAnnexB != 0 {
			c.pattern.pos++
			c.emit(func(vm *machine) {
				vm.pc++
				src, matched := vm.moveSP(direction)
				if matched && src != '}' {
					vm.noMatch()
				}
			})
			return nil
		}
		return newSyntaxError("invalid char }")
	case '*', '+', '?':
		return newSyntaxError("nothing to repeat")
	case ']':
		if c.flags&FlagAnnexB == 0 {
			return newSyntaxError("unmatched ']'")
		}
		c.pattern.pos++
		c.emit(func(vm *machine) {
			vm.pc++
			src, matched := vm.moveSP(direction)
			if matched && src != ']' {
				vm.noMatch()
			}
		})
		return nil
	default:
		expected, _ := c.pattern.move(patternDirectionForward, c.isUnicode())
		expected = canonicalize(c.flags, expected)
		c.emit(func(vm *machine) {
			vm.pc++

			src, matched := vm.moveSP(direction)
			src = canonicalize(vm.flags, src)
			if matched && expected != src {
				vm.noMatch()
			}
		})
		return nil
	}
}

type captureMatchKind uint8

const (
	captureMatchKindTrue captureMatchKind = iota
	captureMatchKindFalse
	captureMatchKindUnknown
)

func (vm *machine) matchesCapture(direction patternDirection, captureIndex int) captureMatchKind {
	capture := vm.captures[captureIndex]
	if capture.start == -1 || capture.end == -1 {
		return captureMatchKindUnknown
	}

	captureSource := vm.source.slice(capture.start, capture.end)

	if direction == patternDirectionBackward {
		if captureSource.isUtf16 {
			captureSource.pos = len(captureSource.utf16)
		} else {
			captureSource.pos = len(captureSource.utf8)
		}
	}

	for {
		expected, captureMoved := captureSource.move(direction, vm.isUnicode())
		if !captureMoved {
			break
		}

		actual, moved := vm.source.move(direction, vm.isUnicode())

		if moved && canonicalize(vm.flags, expected) == canonicalize(vm.flags, actual) {
			continue
		}

		return captureMatchKindFalse
	}
	return captureMatchKindTrue
}

// If number is valid, returns n, true
func (c *compiler) parseDecimalDigits() (int, bool) {
	char, ended := c.pattern.nextCodeUnit()
	if ended || !isDigit(char) {
		return 0, false
	}
	var n int64 = 0
	for ; !ended && isDigit(char); char, ended = c.pattern.nextCodeUnit() {
		c.pattern.pos++

		n = n*10 + int64(char-'0')
		if n >= math.MaxInt || n < 0 {
			n = math.MaxInt
		}
	}
	return int(n), true
}
func (c *compiler) compileTerm() error {
	atomStart := len(c.byteCode)
	// TODO(perf): assertions are always zero-width, so the quantifier loop exits
	// after the first iteration (no advancement). Capturing groups inside
	// assertions also don't need to be reset.
	capturesCountBeforeAtom := c.capturesCount
	ok, lookaheadAssertion, err := c.compileAssertion()
	if err != nil {
		return err
	}

	if c.flags&FlagAnnexB == 0 || !lookaheadAssertion {
		if ok {
			return nil
		}

		capturesCountBeforeAtom = c.capturesCount
		atomStart = len(c.byteCode)
		if err = c.compileAtom(); err != nil {
			return err
		}
	}

	char, ended := c.pattern.nextCodeUnit()
	if ended {
		return nil
	}
	var quantMin, quantMax int
	switch char {
	case '*':
		c.pattern.pos++
		quantMin = 0
		quantMax = math.MaxInt
	case '+':
		c.pattern.pos++
		quantMin = 1
		quantMax = math.MaxInt
	case '?':
		c.pattern.pos++
		quantMin = 0
		quantMax = 1
	case '{':
		patternCopy := c.pattern
		c.pattern.pos++
		n, ok := c.parseDecimalDigits()
		if !ok {
			if c.flags&FlagAnnexB == 0 {
				return newSyntaxError("invalid quantifier")
			}
			c.pattern = patternCopy
			return nil
		}
		quantMin = n

		if c.pattern.consumeNextCodeUnit(',') {
			n, ok = c.parseDecimalDigits()
			if !ok {
				n = math.MaxInt
			} else if quantMin > n {
				return newSyntaxError("invalid range in repetition")
			}
		}
		quantMax = n

		if !c.pattern.consumeNextCodeUnit('}') {
			if c.flags&FlagAnnexB == 0 {
				return newSyntaxError("invalid quantifier")
			}
			c.pattern = patternCopy
			return nil
		}
	default:
		return nil
	}

	greedy := !c.pattern.consumeNextCodeUnit('?')

	if quantMin == 1 && quantMax == 1 {
		return nil
	}

	// TODO(perf): inline repeated quantifiers (I guess few extra opcodes may be
	// faster than backtracking approach)

	// TODO(perf): for explicitly non-zero-width atoms, we can omit SP advance check

	if quantMin == 0 {
		if quantMax == 0 {
			c.byteCode = c.byteCode[:atomStart]
			return nil
		}
		capturesCountAfterAtom := c.capturesCount
		if capturesCountBeforeAtom != capturesCountAfterAtom {
			c.byteCode = slices.Insert(c.byteCode, atomStart, func(vm *machine) {
				vm.pc++
				for i := capturesCountBeforeAtom; i < capturesCountAfterAtom; i++ {
					vm.captures[i].start = -1
					vm.captures[i].end = -1
				}
			})
			atomStart++
		}
		if quantMax == 1 {
			splitOffset := len(c.byteCode) - atomStart + 2

			var fn func(*machine)
			if greedy {
				fn = func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc + splitOffset)
				}
			} else {
				fn = func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc)
					vm.pc += splitOffset
				}
			}

			c.byteCode = slices.Insert(c.byteCode, atomStart, fn, func(vm *machine) {
				vm.pc++
				vm.stack.push(vm.source.pos)
			})
			c.emit(func(vm *machine) {
				vm.pc++
				if vm.source.pos == vm.stack.pop() {
					vm.noMatch()
				}
			})
		} else if quantMax == math.MaxInt {
			splitOffset := len(c.byteCode) - atomStart + 2

			var splitFn func(*machine)
			if greedy {
				splitFn = func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc + splitOffset)
				}
			} else {
				splitFn = func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc)
					vm.pc += splitOffset
				}
			}

			c.byteCode = slices.Insert(c.byteCode, atomStart, splitFn, func(vm *machine) {
				vm.pc++
				vm.stack.push(vm.source.pos)
			})

			c.emit(func(vm *machine) {
				vm.pc++
				if vm.source.pos == vm.stack.pop() {
					vm.noMatch()
					return
				}
				vm.pc -= splitOffset + 1
			})
		} else {
			loopOffset := len(c.byteCode) - atomStart + 2

			var splitFn func(*machine)
			if greedy {
				splitFn = func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc + loopOffset)
				}
			} else {
				splitFn = func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc)
					vm.pc += loopOffset
				}
			}

			c.byteCode = slices.Insert(c.byteCode, atomStart, func(vm *machine) {
				vm.pc++
				vm.stack.push(quantMax)
			}, splitFn, func(vm *machine) {
				vm.pc++
				vm.stack.push(vm.source.pos)
			})

			c.emit(func(vm *machine) {
				vm.pc++

				if vm.source.pos == vm.stack.pop() {
					vm.noMatch()
					return
				}

				loopsLeft := vm.stack.peekPtr()
				(*loopsLeft)--

				if *loopsLeft != 0 {
					vm.pc -= loopOffset + 1
				}
			})
			c.emit(func(vm *machine) {
				vm.pc++
				vm.stack.pop()
			})
		}
	} else if quantMin == 1 {
		extraReps := quantMax - quantMin
		atomEnd := len(c.byteCode)
		loopOffset := atomEnd - atomStart + 2

		c.emit(func(vm *machine) {
			vm.pc++
			vm.stack.push(extraReps)
		})
		if greedy {
			c.emit(func(vm *machine) {
				vm.pc++
				vm.pushBacktrackingFrame(vm.pc + loopOffset)
			})
		} else {
			c.emit(func(vm *machine) {
				vm.pc++
				vm.pushBacktrackingFrame(vm.pc)
				vm.pc += loopOffset
			})
		}
		capturesCountAfterAtom := c.capturesCount
		c.emit(func(vm *machine) {
			vm.pc++
			vm.stack.push(vm.source.pos)
			for i := capturesCountBeforeAtom; i < capturesCountAfterAtom; i++ {
				vm.captures[i].start = -1
				vm.captures[i].end = -1
			}
		})

		c.byteCode = append(c.byteCode, c.byteCode[atomStart:atomEnd]...)

		c.emit(func(vm *machine) {
			vm.pc++

			if vm.source.pos == vm.stack.pop() {
				vm.noMatch()
				return
			}

			loopsLeft := vm.stack.peekPtr()
			(*loopsLeft)--

			if *loopsLeft != 0 {
				vm.pc -= loopOffset + 1
			}
		})
		c.emit(func(vm *machine) {
			vm.pc++
			vm.stack.pop()
		})
	} else {
		atomLen := len(c.byteCode) - atomStart
		loopOffset := atomLen + 2
		extraReps := quantMax - quantMin
		extraLoopOffset := loopOffset + 1

		capturesCountAfterAtom := c.capturesCount
		c.byteCode = slices.Insert(c.byteCode, atomStart, func(vm *machine) {
			vm.pc++
			vm.stack.push(quantMin)
		}, func(vm *machine) {
			vm.pc++
			for i := capturesCountBeforeAtom; i < capturesCountAfterAtom; i++ {
				vm.captures[i].start = -1
				vm.captures[i].end = -1
			}
		})

		atomStart++
		atomLen++

		c.emit(func(vm *machine) {
			vm.pc++

			loopsLeft := vm.stack.peekPtr()
			(*loopsLeft)--

			if *loopsLeft == 0 {
				vm.stack.pop()
				if extraReps > 0 {
					vm.stack.push(extraReps)
				}
			} else {
				vm.pc -= loopOffset
			}
		})

		if extraReps > 0 {
			if greedy {
				c.emit(func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc + extraLoopOffset)
				})
			} else {
				c.emit(func(vm *machine) {
					vm.pc++
					vm.pushBacktrackingFrame(vm.pc)
					vm.pc += extraLoopOffset
				})
			}
			c.emit(func(vm *machine) {
				vm.pc++
				vm.stack.push(vm.source.pos)
			})

			c.byteCode = append(c.byteCode, c.byteCode[atomStart:atomStart+atomLen]...)

			c.emit(func(vm *machine) {
				vm.pc++

				if vm.source.pos == vm.stack.pop() {
					vm.noMatch()
					return
				}

				loopsLeft := vm.stack.peekPtr()
				(*loopsLeft)--

				if *loopsLeft != 0 {
					vm.pc -= extraLoopOffset + 1
				}
			})
			c.emit(func(vm *machine) {
				vm.pc++
				vm.stack.pop()
			})
		}
	}
	return nil
}

type backtrackingFrame struct {
	pc                   int
	source               stringSource
	flags                Flag
	capStart, capLen     int
	stackStart, stackLen int
}

type stack[T any] []T

func (s *stack[T]) push(v T) { *s = append(*s, v) }

func (s *stack[T]) inc() { var z T; *s = append(*s, z) }

func (s *stack[T]) peekPtr() *T { return &(*s)[len(*s)-1] }

func (s *stack[T]) pop() T {
	i := len(*s) - 1
	v := (*s)[i]
	*s = (*s)[:i]
	return v
}

func (s *stack[T]) truncate(n int) { *s = (*s)[:n] }

type capture struct {
	start int
	end   int
}

type stringSource struct {
	utf8  []byte
	utf16 []uint16
	// bool check is faster than slice != nil
	isUtf16 bool
	pos     int
}

func (s *stringSource) stringInRange(start, end int) string {
	if s.isUtf16 {
		return string(utf16.Decode(s.utf16[start:end]))
	}
	return string(s.utf8[start:end])
}

func (s *stringSource) slice(start, end int) stringSource {
	if s.isUtf16 {
		return stringSource{
			utf16:   s.utf16[start:end],
			isUtf16: true,
		}
	}
	return stringSource{
		utf8: s.utf8[start:end],
	}
}

// TODO: ensure that stringSource methods are inlined - https://go-review.googlesource.com/c/go/+/57410

func (s *stringSource) atEnd() bool {
	return s.pos >= len(s.utf8) && s.pos >= len(s.utf16)
}
func (s *stringSource) atStart() bool {
	return s.pos == 0
}

// If source is ended, returns 0, true
func (s *stringSource) nextCodeUnit() (uint16, bool) {
	return s.nextNthCodeUnit(0)
}

// If source is ended, returns 0, true
func (s *stringSource) nextNthCodeUnit(n int) (uint16, bool) {
	pos := s.pos + n
	if s.isUtf16 {
		if pos >= len(s.utf16) {
			return 0, true
		}
		return s.utf16[pos], false
	}
	if pos >= len(s.utf8) {
		return 0, true
	}
	return uint16(s.utf8[pos]), false
}
func (s *stringSource) nextNthCodeUnitUnsafe(n int) uint16 {
	if s.isUtf16 {
		return s.utf16[s.pos+n]
	}
	return uint16(s.utf8[s.pos+n])
}

func (s *stringSource) consumeNextCodeUnit(expected uint16) bool {
	if char, ended := s.nextCodeUnit(); ended || char != expected {
		return false
	}
	s.pos++
	return true
}

func (s *stringSource) move(direction patternDirection, isUnicode bool) (rune, bool) {
	if s.isUtf16 {
		if direction == patternDirectionForward {
			if s.pos >= len(s.utf16) {
				return 0, false
			}
			r := rune(s.utf16[s.pos])
			s.pos++
			if !isUnicode || !isHighSurrogate(r) || s.pos == len(s.utf16) {
				return r, true
			}
			lo := rune(s.utf16[s.pos])
			if isLowSurrogate(lo) {
				r = utf16.DecodeRune(r, lo)
				s.pos++
			}
			return r, true
		}

		if s.pos == 0 {
			return 0, false
		}
		s.pos--
		r := rune(s.utf16[s.pos])
		if !isUnicode || !isLowSurrogate(r) || s.pos == 0 {
			return r, true
		}
		hi := rune(s.utf16[s.pos-1])
		if isHighSurrogate(hi) {
			r = utf16.DecodeRune(hi, r)
			s.pos--
		}
		return r, true
	}

	if direction == patternDirectionForward {
		if s.pos >= len(s.utf8) {
			return 0, false
		}
		r, size := utf8.DecodeRune(s.utf8[s.pos:])
		s.pos += size
		return r, true
	}
	if s.pos == 0 {
		return 0, false
	}
	r, size := utf8.DecodeLastRune(s.utf8[:s.pos])
	s.pos -= size
	return r, true
}

type machine struct {
	byteCode []func(vm *machine)
	flags    Flag

	// Program Counter. Index of current machine instruction
	pc     int
	source stringSource

	backtrackingStack stack[backtrackingFrame]
	capturesStack     []capture
	stacksStack       []int

	// TODO(perf): stack can be preallocated
	stack stack[int]

	captures      []capture
	namedCaptures map[string][]int

	notMatched bool
}

func (vm *machine) isUnicode() bool {
	return vm.flags&flagEitherUnicode != 0
}

func (vm *machine) startCapture(captureIndex int) {
	vm.captures[captureIndex].start = vm.source.pos
}
func (vm *machine) endCapture(captureIndex int) {
	vm.captures[captureIndex].end = vm.source.pos
}

func (vm *machine) moveSP(direction patternDirection) (rune, bool) {
	r, moved := vm.source.move(direction, vm.isUnicode())
	if !moved {
		vm.noMatch()
	}
	return r, moved
}

func (vm *machine) pushBacktrackingFrame(pc int) {
	vm.backtrackingStack.inc()
	frame := vm.backtrackingStack.peekPtr()
	frame.pc = pc
	frame.source = vm.source
	frame.capStart = len(vm.capturesStack)
	frame.capLen = len(vm.captures)
	vm.capturesStack = append(vm.capturesStack, vm.captures...)
	frame.stackStart = len(vm.stacksStack)
	frame.stackLen = len(vm.stack)
	vm.stacksStack = append(vm.stacksStack, vm.stack...)
	frame.flags = vm.flags
}

func (vm *machine) noMatch() {
	if len(vm.backtrackingStack) == 0 {
		vm.notMatched = true
		return
	}

	frame := vm.backtrackingStack.pop()
	vm.pc = frame.pc
	vm.source = frame.source
	copy(vm.captures, vm.capturesStack[frame.capStart:frame.capStart+frame.capLen])
	vm.capturesStack = vm.capturesStack[:frame.capStart]
	vm.stack = vm.stack[:frame.stackLen]
	copy(vm.stack, vm.stacksStack[frame.stackStart:frame.stackStart+frame.stackLen])
	vm.stacksStack = vm.stacksStack[:frame.stackStart]
	vm.flags = frame.flags
}

func (vm *machine) eval() {
	for vm.pc < len(vm.byteCode) && !vm.notMatched {
		vm.byteCode[vm.pc](vm)
	}
}

func compilePattern(pattern stringSource, flags Flag) (*compiler, error) {
	if flags&flagEitherUnicode != 0 {
		flags &= ^FlagAnnexB
	}
	c := compiler{
		pattern:            pattern,
		flags:              flags,
		direction:          patternDirectionForward,
		namedCaptures:      map[string][]int{},
		allNamedCaptures:   map[string]struct{}{},
		totalCapturesCount: -1,
	}
	if err := c.compile(); err != nil {
		return nil, err
	}
	return &c, nil
}

func newMachine(c *compiler, source stringSource, sticky bool) machine {
	vm := machine{
		byteCode:      c.byteCode,
		source:        source,
		flags:         c.flags,
		captures:      make([]capture, c.capturesCount),
		namedCaptures: c.namedCaptures,
	}
	if sticky {
		vm.flags |= FlagSticky
	}
	for i := range vm.captures {
		vm.captures[i].start = -1
		vm.captures[i].end = -1
	}

	return vm
}

// RegExp represents a compiled regular expression.
// It is safe for concurrent use by multiple goroutines.
// All methods on RegExp do not mutate internal state.
type RegExp struct {
	c *compiler
}

// RegExpUtf16 represents a compiled regular expression.
// It is safe for concurrent use by multiple goroutines.
// All methods on RegExpUtf16 do not mutate internal state.
type RegExpUtf16 struct {
	c *compiler
}

// Compile parses a regular expression pattern and returns a RegExp
// that can be applied against UTF-8 encoded input.
//
// The pattern must be a valid ECMAScript regular expression.
func Compile(pattern string, flags Flag) (*RegExp, error) {
	flags |= FlagUnicode
	c, err := compilePattern(stringSource{
		utf8: []byte(pattern),
	}, flags)
	if err != nil {
		return nil, err
	}
	return &RegExp{c: c}, nil
}

// MustCompile is like [Compile] but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables containing regular
// expressions.
func MustCompile(pattern string, flags Flag) *RegExp {
	re, err := Compile(pattern, flags)
	if err != nil {
		panic("regonaut: MustCompile: " + err.Error())
	}
	return re
}

// CompileUtf16 parses a regular expression pattern expressed as UTF-16 code
// units and returns a RegExpUtf16 that can be applied against UTF-16 encoded
// input.
//
// The pattern must be a valid ECMAScript regular expression.
func CompileUtf16(pattern []uint16, flags Flag) (*RegExpUtf16, error) {
	c, err := compilePattern(stringSource{
		utf16:   pattern,
		isUtf16: true,
	}, flags)
	if err != nil {
		return nil, err
	}
	return &RegExpUtf16{c: c}, nil
}

// MustCompileUtf16 is like [CompileUtf16] but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables containing regular
// expressions.
func MustCompileUtf16(pattern []uint16, flags Flag) *RegExpUtf16 {
	re, err := CompileUtf16(pattern, flags)
	if err != nil {
		panic("regonaut: MustCompileUtf16: " + err.Error())
	}
	return re
}

// Group represents a single captured substring from a regular expression match
// against UTF-8 encoded input.
// It is safe for concurrent use by multiple goroutines.
type Group struct {
	src []byte
	// Start is the inclusive start index of the captured substring,
	// or -1 if the group did not participate in the match.
	Start int
	// End is the exclusive end index of the captured substring,
	// or -1 if the group did not participate in the match.
	End int
	// Name is the group name if defined, otherwise empty.
	Name string
}

// Data returns the captured substring as a UTF-8 byte slice.
// If the group did not participate in the match (Start == -1), it returns nil.
func (g Group) Data() []byte {
	if g.Start == -1 {
		return nil
	}
	return g.src[g.Start:g.End]
}

// Match holds the result of a successful match against UTF-8 input.
// It is safe for concurrent use by multiple goroutines.
type Match struct {
	// Groups is the ordered list of captures.
	// Groups[0] is the full match; subsequent entries correspond to
	// the capturing groups in the pattern.
	Groups []Group
	// NamedGroups maps a group name to its captured group.
	NamedGroups map[string]Group
}

// GroupUtf16 represents a single captured substring from a regular expression
// match against UTF-16 encoded input.
// It is safe for concurrent use by multiple goroutines.
type GroupUtf16 struct {
	src []uint16
	// Start is the inclusive start index of the captured substring,
	// or -1 if the group did not participate in the match.
	Start int
	// End is the exclusive end index of the captured substring,
	// or -1 if the group did not participate in the match.
	End int
	// Name is the group name if defined, otherwise empty.
	Name string
}

// Data returns the captured substring as a UTF-16 code units slice.
// If the group did not participate in the match (Start == -1), it returns nil.
func (g GroupUtf16) Data() []uint16 {
	if g.Start == -1 {
		return nil
	}
	return g.src[g.Start:g.End]
}

// MatchUtf16 holds the result of a successful match against UTF-16 input.
// It is safe for concurrent use by multiple goroutines.
type MatchUtf16 struct {
	// Groups is the ordered list of captures.
	// Groups[0] is the full match; subsequent entries correspond to
	// the capturing groups in the pattern.
	Groups []GroupUtf16
	// NamedGroups maps a group name to its captured group.
	NamedGroups map[string]GroupUtf16
}

func findMatch(c *compiler, source []byte, startPos int, advanceOnce bool) *Match {
	if source == nil || startPos < 0 || startPos > len(source) {
		return nil
	}
	for i := 0; i < 3; i++ {
		pos := startPos - i
		if pos < 0 || pos >= len(source) {
			break
		}
		r, size := utf8.DecodeRune(source[pos:])
		if r == utf8.RuneError && size == 1 {
			if (source[pos] & 0b11000000) != 0b10000000 {
				break
			}
			continue
		}
		startPos = pos
		break
	}
	vm := newMachine(c, stringSource{utf8: source, pos: startPos}, false)
	if advanceOnce {
		vm.moveSP(patternDirectionForward)
	}
	vm.eval()

	if vm.notMatched {
		return nil
	}

	m := Match{
		Groups:      make([]Group, len(vm.captures)),
		NamedGroups: make(map[string]Group, len(vm.namedCaptures)),
	}

	for i, c := range vm.captures {
		m.Groups[i].Start = c.start
		m.Groups[i].End = c.end
		m.Groups[i].src = source
	}

NamedCaptures:
	for name, captures := range vm.namedCaptures {
		for _, i := range captures {
			if m.Groups[i].Start != -1 {
				m.Groups[i].Name = name
				m.NamedGroups[name] = m.Groups[i]
				continue NamedCaptures
			}
		}
		m.NamedGroups[name] = Group{
			Start: -1,
			End:   -1,
			Name:  name,
		}
	}

	return &m
}
func findMatchUtf16(c *compiler, source []uint16, startPos int, sticky, advanceOnce bool) *MatchUtf16 {
	if source == nil || startPos < 0 || startPos > len(source) {
		return nil
	}
	// https://github.com/tc39/ecma262/issues/128
	if c.flags&flagEitherUnicode != 0 && startPos > 0 && startPos < len(source) && isLowSurrogate(rune(source[startPos])) && isHighSurrogate(rune(source[startPos-1])) {
		startPos--
	}
	vm := newMachine(c, stringSource{utf16: source, isUtf16: true, pos: startPos}, sticky)
	if advanceOnce {
		vm.moveSP(patternDirectionForward)
	}
	vm.eval()

	if vm.notMatched {
		return nil
	}

	m := MatchUtf16{
		Groups:      make([]GroupUtf16, len(vm.captures)),
		NamedGroups: make(map[string]GroupUtf16, len(vm.namedCaptures)),
	}

	for i, c := range vm.captures {
		m.Groups[i].Start = c.start
		m.Groups[i].End = c.end
		m.Groups[i].src = source
	}

NamedCaptures:
	for name, captures := range vm.namedCaptures {
		for _, i := range captures {
			if m.Groups[i].Start != -1 {
				m.Groups[i].Name = name
				m.NamedGroups[name] = m.Groups[i]
				continue NamedCaptures
			}
		}
		m.NamedGroups[name] = GroupUtf16{
			Start: -1,
			End:   -1,
			Name:  name,
		}
	}

	return &m
}

// FindMatch applies r to a UTF-8 encoded byte slice and returns the first match.
// If no match is found, it returns nil.
func (r *RegExp) FindMatch(source []byte) *Match {
	return findMatch(r.c, source, 0, false)
}

// FindMatchStartingAt applies r to a UTF-8 encoded byte slice beginning the
// search at pos, where pos is a byte index into source. It returns the first
// match found at or after pos. If pos is out of range or no match is found,
// it returns nil.
func (r *RegExp) FindMatchStartingAt(source []byte, pos int) *Match {
	return findMatch(r.c, source, pos, false)
}

// FindNextMatch searches for the next match of r in the same UTF-8 encoded
// input as a previously returned match.
//
// The search begins at match.Groups[0].End. If the previous match was
// zero-length (Start == End), the search position is advanced by one input
// position before matching again to avoid returning the same empty match
// repeatedly.
//
// If match is nil, or if no further match is found, FindNextMatch returns nil.
func (r *RegExp) FindNextMatch(match *Match) *Match {
	if match == nil {
		return nil
	}
	return findMatch(r.c, match.Groups[0].src, match.Groups[0].End, match.Groups[0].Start == match.Groups[0].End)
}

// FindMatch applies r to a UTF-16 slice and returns the first match.
// If no match is found, it returns nil.
func (r *RegExpUtf16) FindMatch(source []uint16) *MatchUtf16 {
	return findMatchUtf16(r.c, source, 0, false, false)
}

// FindMatchStartingAt applies r to a UTF-16 slice beginning the search at pos,
// where pos is an index in UTF-16 code units. It returns the first match found
// at or after pos. If pos is out of range or no match is found, it returns nil.
func (r *RegExpUtf16) FindMatchStartingAt(source []uint16, pos int) *MatchUtf16 {
	return findMatchUtf16(r.c, source, pos, false, false)
}

// FindMatchStartingAtSticky applies r to a UTF-16 slice requiring the match to
// start exactly at pos (sticky behavior), where pos is an index in UTF-16 code
// units. If the input at pos does not begin a match, or if pos is out of range,
// it returns nil.
//
// This method is particularly useful for JavaScript engine implementers.
// The ECMAScript specification defines RegExp.prototype[Symbol.split] to create
// a new RegExp with the "y" (sticky) flag in order to constrain matching to the
// current position. By calling FindMatchStartingAtSticky instead, it is possible
// to avoid the overhead of allocating and compiling a new RegExp object, while
// still honoring the sticky semantics.
func (r *RegExpUtf16) FindMatchStartingAtSticky(source []uint16, pos int) *MatchUtf16 {
	return findMatchUtf16(r.c, source, pos, true, false)
}

// FindNextMatch searches for the next match of r in the same UTF-16 encoded
// input as a previously returned match.
//
// The search begins at match.Groups[0].End. If the previous match was
// zero-length (Start == End), the search position is advanced by one input
// position before matching again to avoid returning the same empty match
// repeatedly.
//
// If match is nil, or if no further match is found, FindNextMatch returns nil.
func (r *RegExpUtf16) FindNextMatch(match *MatchUtf16) *MatchUtf16 {
	if match == nil {
		return nil
	}
	return findMatchUtf16(r.c, match.Groups[0].src, match.Groups[0].End, false, match.Groups[0].Start == match.Groups[0].End)
}
