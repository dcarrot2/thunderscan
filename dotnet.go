package main

// Minimal, dependency-free reader for ECMA-335 (.NET) metadata.
// It extracts just what the rule engine needs: referenced types, referenced
// members ("Namespace.Type::Method"), P/Invoke imports, defined names and the
// string heaps. It never executes or loads the assembly.

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

type clrMeta struct {
	TypeRefs      []string
	MemberRefs    []string // "Namespace.Type::Member"
	PInvokes      []string // imported function names
	ModuleRefs    []string
	DefNames      []string // TypeDef / MethodDef / Field names
	StringHeap    []string
	UserStrings   []string
	ResourcesData []byte
	ILFacts       map[string]bool // facts from scanning method bodies, e.g. "GETFOLDERPATH_STARTUP"
	ParseErr      error           // table stream problem; heaps may still be populated
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func rvaToOffset(f *pe.File, rva uint32) (uint32, bool) {
	for _, s := range f.Sections {
		size := s.VirtualSize
		if s.Size > size {
			size = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return rva - s.VirtualAddress + s.Offset, true
		}
	}
	return 0, false
}

func clrDirectory(f *pe.File) (uint32, bool) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > 14 && oh.DataDirectory[14].VirtualAddress != 0 {
			return oh.DataDirectory[14].VirtualAddress, true
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > 14 && oh.DataDirectory[14].VirtualAddress != 0 {
			return oh.DataDirectory[14].VirtualAddress, true
		}
	}
	return 0, false
}

// parseCLR returns (nil, nil) for a native PE with no CLR header.
func parseCLR(f *pe.File, data []byte) (*clrMeta, error) {
	rva, ok := clrDirectory(f)
	if !ok {
		return nil, nil
	}
	off, ok := rvaToOffset(f, rva)
	if !ok || uint64(off)+72 > uint64(len(data)) {
		return &clrMeta{}, errors.New("CLR header out of bounds")
	}
	h := data[off:]
	mdRVA, mdSize := le32(h[8:]), le32(h[12:])
	resRVA, resSize := le32(h[24:]), le32(h[28:])

	m := &clrMeta{}
	if resRVA != 0 && resSize > 0 {
		if ro, ok := rvaToOffset(f, resRVA); ok && uint64(ro)+uint64(resSize) <= uint64(len(data)) {
			m.ResourcesData = data[ro : ro+resSize]
		}
	}

	mo, ok := rvaToOffset(f, mdRVA)
	if !ok || uint64(mo)+uint64(mdSize) > uint64(len(data)) {
		return m, errors.New("metadata out of bounds")
	}
	md := data[mo : mo+mdSize]
	if len(md) < 20 || le32(md) != 0x424A5342 { // "BSJB"
		return m, errors.New("bad metadata signature")
	}
	p := 16 + int(le32(md[12:]))
	if p+4 > len(md) || p < 16 {
		return m, errors.New("metadata header truncated")
	}
	nstreams := int(le16(md[p+2:]))
	p += 4

	streams := map[string][]byte{}
	for i := 0; i < nstreams; i++ {
		if p+8 > len(md) {
			return m, errors.New("stream headers truncated")
		}
		so, ss := le32(md[p:]), le32(md[p+4:])
		p += 8
		start := p
		for p < len(md) && md[p] != 0 {
			p++
		}
		if p >= len(md) {
			return m, errors.New("stream name truncated")
		}
		name := string(md[start:p])
		p = start + ((p - start + 1 + 3) &^ 3)
		if uint64(so)+uint64(ss) > uint64(len(md)) {
			continue
		}
		if _, dup := streams[name]; !dup {
			streams[name] = md[so : so+ss]
		}
	}

	strs := streams["#Strings"]
	m.StringHeap = splitNull(strs)
	m.UserStrings = parseUS(streams["#US"])

	tbl := streams["#~"]
	if tbl == nil {
		tbl = streams["#-"]
	}
	if tbl == nil {
		m.ParseErr = errors.New("no metadata table stream")
		return m, nil
	}
	at := func(rva uint32) []byte {
		o, ok := rvaToOffset(f, rva)
		if !ok || int(o) >= len(data) {
			return nil
		}
		return data[o:]
	}
	if err := parseTables(m, tbl, strs, at); err != nil {
		m.ParseErr = err
	}
	return m, nil
}

func splitNull(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

func compressedLen(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	switch {
	case c&0x80 == 0:
		return int(c), 1
	case c&0xC0 == 0x80:
		if len(b) < 2 {
			return 0, 0
		}
		return int(c&0x3F)<<8 | int(b[1]), 2
	case c&0xE0 == 0xC0:
		if len(b) < 4 {
			return 0, 0
		}
		return int(c&0x1F)<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]), 4
	}
	return 0, 0
}

func parseUS(b []byte) []string {
	var out []string
	i := 1
	for i < len(b) {
		n, hl := compressedLen(b[i:])
		if hl == 0 {
			break
		}
		i += hl
		if n == 0 {
			continue
		}
		if i+n > len(b) {
			break
		}
		ub := b[i : i+(n&^1)]
		u := make([]uint16, len(ub)/2)
		for k := range u {
			u[k] = le16(ub[2*k:])
		}
		out = append(out, string(utf16.Decode(u)))
		i += n
	}
	return out
}

// ---- table stream ----

const (
	cU16 = iota
	cU32
	cStr
	cGuid
	cBlob
	cTable
	cCoded
)

type col struct{ kind, arg int }

const (
	ckTypeDefOrRef = iota
	ckHasConstant
	ckHasCustomAttribute
	ckHasFieldMarshal
	ckHasDeclSecurity
	ckMemberRefParent
	ckHasSemantics
	ckMethodDefOrRef
	ckMemberForwarded
	ckCustomAttributeType
	ckResolutionScope
)

var codedKinds = [][]int{
	ckTypeDefOrRef:        {0x02, 0x01, 0x1B},
	ckHasConstant:         {0x04, 0x08, 0x17},
	ckHasCustomAttribute:  {0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B},
	ckHasFieldMarshal:     {0x04, 0x08},
	ckHasDeclSecurity:     {0x02, 0x06, 0x20},
	ckMemberRefParent:     {0x02, 0x01, 0x1A, 0x06, 0x1B},
	ckHasSemantics:        {0x14, 0x17},
	ckMethodDefOrRef:      {0x06, 0x0A},
	ckMemberForwarded:     {0x04, 0x06},
	ckCustomAttributeType: {-1, -1, 0x06, 0x0A, -1},
	ckResolutionScope:     {0x00, 0x1A, 0x23, 0x01},
}

var (
	u16  = col{cU16, 0}
	u32  = col{cU32, 0}
	str  = col{cStr, 0}
	guid = col{cGuid, 0}
	blob = col{cBlob, 0}
)

func tb(t int) col    { return col{cTable, t} }
func coded(k int) col { return col{cCoded, k} }

// Schema for tables 0x00..0x1C (enough to reach ImplMap; later tables are not needed).
var schema = [][]col{
	0x00: {u16, str, guid, guid, guid},                                      // Module
	0x01: {coded(ckResolutionScope), str, str},                              // TypeRef
	0x02: {u32, str, str, coded(ckTypeDefOrRef), tb(0x04), tb(0x06)},        // TypeDef
	0x03: {tb(0x04)},                                                        // FieldPtr
	0x04: {u16, str, blob},                                                  // Field
	0x05: {tb(0x06)},                                                        // MethodPtr
	0x06: {u32, u16, u16, str, blob, tb(0x08)},                              // MethodDef
	0x07: {tb(0x08)},                                                        // ParamPtr
	0x08: {u16, u16, str},                                                   // Param
	0x09: {tb(0x02), coded(ckTypeDefOrRef)},                                 // InterfaceImpl
	0x0A: {coded(ckMemberRefParent), str, blob},                             // MemberRef
	0x0B: {u16, coded(ckHasConstant), blob},                                 // Constant
	0x0C: {coded(ckHasCustomAttribute), coded(ckCustomAttributeType), blob}, // CustomAttribute
	0x0D: {coded(ckHasFieldMarshal), blob},                                  // FieldMarshal
	0x0E: {u16, coded(ckHasDeclSecurity), blob},                             // DeclSecurity
	0x0F: {u16, u32, tb(0x02)},                                              // ClassLayout
	0x10: {u32, tb(0x04)},                                                   // FieldLayout
	0x11: {blob},                                                            // StandAloneSig
	0x12: {tb(0x02), tb(0x14)},                                              // EventMap
	0x13: {tb(0x14)},                                                        // EventPtr
	0x14: {u16, str, coded(ckTypeDefOrRef)},                                 // Event
	0x15: {tb(0x02), tb(0x17)},                                              // PropertyMap
	0x16: {tb(0x17)},                                                        // PropertyPtr
	0x17: {u16, str, blob},                                                  // Property
	0x18: {u16, tb(0x06), coded(ckHasSemantics)},                            // MethodSemantics
	0x19: {tb(0x02), coded(ckMethodDefOrRef), coded(ckMethodDefOrRef)},      // MethodImpl
	0x1A: {str},                                                             // ModuleRef
	0x1B: {blob},                                                            // TypeSpec
	0x1C: {u16, coded(ckMemberForwarded), str, tb(0x1A)},                    // ImplMap
}

type table struct {
	data    []byte
	rows    int
	rowSize int
	offs    []int
	sizes   []int
}

func (t *table) get(row, c int) uint32 { // row is 0-based
	if t == nil || row < 0 || row >= t.rows {
		return 0
	}
	b := t.data[row*t.rowSize+t.offs[c]:]
	if t.sizes[c] == 2 {
		return uint32(le16(b))
	}
	return le32(b)
}

func bitsFor(n int) uint {
	b := uint(0)
	for (1 << b) < n {
		b++
	}
	return b
}

func parseTables(m *clrMeta, t []byte, strs []byte, at func(rva uint32) []byte) error {
	if len(t) < 24 {
		return errors.New("table stream truncated")
	}
	heap := t[6]
	valid := le64(t[8:])
	p := 24
	var rows [64]int
	for i := 0; i < 64; i++ {
		if valid>>uint(i)&1 == 1 {
			if p+4 > len(t) {
				return errors.New("row counts truncated")
			}
			rows[i] = int(le32(t[p:]))
			p += 4
		}
	}
	if heap&0x40 != 0 {
		p += 4
	}
	idx := func(flag byte) int {
		if heap&flag != 0 {
			return 4
		}
		return 2
	}
	strSize, guidSize, blobSize := idx(0x01), idx(0x02), idx(0x04)

	colSize := func(c col) int {
		switch c.kind {
		case cU16:
			return 2
		case cU32:
			return 4
		case cStr:
			return strSize
		case cGuid:
			return guidSize
		case cBlob:
			return blobSize
		case cTable:
			if rows[c.arg] < 1<<16 {
				return 2
			}
			return 4
		case cCoded:
			list := codedKinds[c.arg]
			maxRows := 0
			for _, ti := range list {
				if ti >= 0 && rows[ti] > maxRows {
					maxRows = rows[ti]
				}
			}
			if maxRows < 1<<(16-bitsFor(len(list))) {
				return 2
			}
			return 4
		}
		return 0
	}

	tables := make([]*table, len(schema))
	for ti, cols := range schema {
		if rows[ti] == 0 {
			continue
		}
		tt := &table{rows: rows[ti]}
		for _, c := range cols {
			tt.offs = append(tt.offs, tt.rowSize)
			s := colSize(c)
			tt.sizes = append(tt.sizes, s)
			tt.rowSize += s
		}
		total := tt.rowSize * tt.rows
		if total < 0 || p+total > len(t) {
			return fmt.Errorf("metadata table 0x%02X truncated", ti)
		}
		tt.data = t[p : p+total]
		p += total
		tables[ti] = tt
	}

	getStr := func(i uint32) string {
		if int(i) >= len(strs) {
			return ""
		}
		end := int(i)
		for end < len(strs) && strs[end] != 0 {
			end++
		}
		return string(strs[i:end])
	}
	join := func(ns, name string) string {
		if ns == "" {
			return name
		}
		return ns + "." + name
	}

	// TypeRefs (resolving nested types through their enclosing TypeRef).
	tr := tables[0x01]
	var typeRefName func(row, depth int) string
	typeRefName = func(row, depth int) string {
		if tr == nil || row < 0 || row >= tr.rows || depth > 8 {
			return "?"
		}
		scope := tr.get(row, 0)
		name := join(getStr(tr.get(row, 2)), getStr(tr.get(row, 1)))
		if scope&3 == 3 { // nested in another TypeRef
			return typeRefName(int(scope>>2)-1, depth+1) + "/" + name
		}
		return name
	}
	if tr != nil {
		for r := 0; r < tr.rows; r++ {
			m.TypeRefs = append(m.TypeRefs, typeRefName(r, 0))
		}
	}

	td := tables[0x02]
	typeDefName := func(row int) string {
		if td == nil || row < 0 || row >= td.rows {
			return "?"
		}
		return join(getStr(td.get(row, 2)), getStr(td.get(row, 1)))
	}
	if td != nil {
		for r := 0; r < td.rows; r++ {
			m.DefNames = append(m.DefNames, getStr(td.get(r, 1)))
		}
	}
	if f := tables[0x04]; f != nil {
		for r := 0; r < f.rows; r++ {
			m.DefNames = append(m.DefNames, getStr(f.get(r, 1)))
		}
	}
	md := tables[0x06]
	if md != nil {
		for r := 0; r < md.rows; r++ {
			m.DefNames = append(m.DefNames, getStr(md.get(r, 3)))
		}
	}

	if mrt := tables[0x0A]; mrt != nil {
		for r := 0; r < mrt.rows; r++ {
			par := mrt.get(r, 0)
			tag, ri := par&7, int(par>>3)-1
			owner := "?"
			switch tag {
			case 0:
				owner = typeDefName(ri)
			case 1:
				owner = typeRefName(ri, 0)
			}
			m.MemberRefs = append(m.MemberRefs, owner+"::"+getStr(mrt.get(r, 1)))
		}
	}

	// Method-body scan: which constants are passed to Environment.GetFolderPath?
	getFolder := map[uint32]bool{}
	for r, name := range m.MemberRefs {
		if name == "System.Environment::GetFolderPath" {
			getFolder[0x0A000000|uint32(r+1)] = true
		}
	}
	if len(getFolder) > 0 && md != nil && at != nil {
		for r := 0; r < md.rows; r++ {
			if code := methodCode(at(md.get(r, 0))); code != nil && callsWithStartupFolder(code, getFolder) {
				if m.ILFacts == nil {
					m.ILFacts = map[string]bool{}
				}
				m.ILFacts["GETFOLDERPATH_STARTUP"] = true
				break
			}
		}
	}

	if mod := tables[0x1A]; mod != nil {
		for r := 0; r < mod.rows; r++ {
			m.ModuleRefs = append(m.ModuleRefs, getStr(mod.get(r, 0)))
		}
	}
	if im := tables[0x1C]; im != nil {
		for r := 0; r < im.rows; r++ {
			m.PInvokes = append(m.PInvokes, getStr(im.get(r, 2)))
		}
	}
	return nil
}

// methodCode returns the IL bytes of a method body (tiny or fat header), or nil.
func methodCode(b []byte) []byte {
	if len(b) < 1 {
		return nil
	}
	switch b[0] & 3 {
	case 2: // tiny
		n := int(b[0] >> 2)
		if 1+n > len(b) {
			return nil
		}
		return b[1 : 1+n]
	case 3: // fat
		if len(b) < 12 {
			return nil
		}
		hdr := int(le16(b)>>12) * 4
		n := int(le32(b[4:]))
		if hdr < 12 || n < 0 || hdr+n > len(b) || n > 16<<20 {
			return nil
		}
		return b[hdr : hdr+n]
	}
	return nil
}

// ldcBefore reports the int constant loaded by an ldc.i4* instruction that
// ends exactly at code[end]. A byte-pattern heuristic: it does not decode the
// whole instruction stream, but it is only consulted right before a call to a
// specific method token, where a false match is very unlikely.
// Every plausible reading is returned, because without full decoding the
// byte before a call can be ambiguous.
type ldc struct{ val, size int }

func ldcBefore(code []byte, end int) []ldc {
	var out []ldc
	if end >= 2 && code[end-2] == 0x1F { // ldc.i4.s <int8>
		out = append(out, ldc{int(int8(code[end-1])), 2})
	}
	if end >= 5 && code[end-5] == 0x20 { // ldc.i4 <int32>
		out = append(out, ldc{int(int32(le32(code[end-4:]))), 5})
	}
	if end >= 1 && code[end-1] >= 0x15 && code[end-1] <= 0x1E { // ldc.i4.m1 .. ldc.i4.8
		out = append(out, ldc{int(code[end-1]) - 0x16, 1})
	}
	return out
}

// callsWithStartupFolder looks for GetFolderPath(SpecialFolder.Startup=7 or
// CommonStartup=24), for both the 1-argument and the (folder, option) overload.
func callsWithStartupFolder(code []byte, targets map[uint32]bool) bool {
	isStartup := func(v int) bool { return v == 7 || v == 24 }
	for i := 0; i+5 <= len(code); i++ {
		if code[i] != 0x28 || !targets[le32(code[i+1:])] { // call <token>
			continue
		}
		for _, a := range ldcBefore(code, i) {
			if isStartup(a.val) {
				return true
			}
			for _, b := range ldcBefore(code, i-a.size) { // (folder, option): folder is loaded first
				if isStartup(b.val) {
					return true
				}
			}
		}
	}
	return false
}
