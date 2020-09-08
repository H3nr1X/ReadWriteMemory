package ReadWriteMemory

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/Xustyx/w32"
	log "github.com/sirupsen/logrus"
	"math"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_NOACCESS 		   = 0x01
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32           			= syscall.NewLazyDLL("kernel32.dll")
	virtualQueryEx 	   			= kernel32.NewProc("VirtualQueryEx")
	virtualProtectEx   			= kernel32.NewProc("VirtualProtectEx")
)

type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type Process struct {
	Name    		string
	Handle			w32.HANDLE
	Pid     		uint32
	ModBaseAddr 	uintptr
	ModBaseSize		uint32
	Modules         map[string]Module
}

type Module struct {
	Name 			string
	ModBaseAddr		uintptr
	ModBaseSize		uint32
}

func init() {
	log.SetFormatter(
		&log.TextFormatter{
			PadLevelText:	 true,
			TimestampFormat: "15:04:05",
			ForceColors: 	 true,
		},
	)
}

func VirtualQueryEx(hProcess w32.HANDLE, lpAddress uintptr) (MemoryBasicInformation, error) {
	mbi := MemoryBasicInformation{}
	r, _, err := virtualQueryEx.Call(uintptr(hProcess), lpAddress, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if r == 0 {
		return mbi, err
	}
	return mbi, nil
}

func VirtualProtectEx(hProcess w32.HANDLE, lpAddress uintptr, dwSize uintptr, flNewProtect uint32) (lpflOldProtect uint32, err error) {
	r, _, lastErr := virtualProtectEx.Call(uintptr(hProcess), lpAddress, dwSize, uintptr(flNewProtect), uintptr(unsafe.Pointer(&lpflOldProtect)))
	if r == 0 {
		return 0, lastErr
	}
	return lpflOldProtect, nil
}

func setDebugPrivilege() bool {
	// Thanks to Xustyx' Goxymemory code for setting privileges and the w32 fork.
	pseudoHandle, err := w32.GetCurrentProcess()
	if err != nil {
		return false
	}

	hToken := w32.HANDLE(0)
	if !w32.OpenProcessToken(pseudoHandle, w32.TOKEN_ADJUST_PRIVILEGES|w32.TOKEN_QUERY, &hToken) {
		return false
	}

	return setPrivilege(hToken, w32.SE_DEBUG_NAME, true)
}

func setPrivilege(hToken w32.HANDLE, lpszPrivilege string, bEnablePrivilege bool) bool {
	tPrivs := w32.TOKEN_PRIVILEGES{}
	luid := w32.LUID{}

	if !w32.LookupPrivilegeValue("", lpszPrivilege, &luid) {
		return false
	}

	tPrivs.PrivilegeCount = 1
	tPrivs.Privileges[0].Luid = luid

	if bEnablePrivilege {
		tPrivs.Privileges[0].Attributes = w32.SE_PRIVILEGE_ENABLED
	} else {
		tPrivs.Privileges[0].Attributes = 0
	}

	return w32.AdjustTokenPrivileges(hToken, 0, &tPrivs, uint32(unsafe.Sizeof(tPrivs)), nil, nil)
}

func ProcessInfo(pid uint32) (Process, error) {
	snap := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE32 | w32.TH32CS_SNAPMODULE, pid)
	defer w32.CloseHandle(snap)

	var me w32.MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))

	if w32.Module32First(snap, &me) {
		proc := Process{
			Name:        w32.UTF16PtrToString(&me.SzModule[0]),
			Pid:         me.ProcessID,
			ModBaseAddr: uintptr(unsafe.Pointer(me.ModBaseAddr)),
			ModBaseSize: me.ModBaseSize,
			Modules:	 map[string]Module{},
		}

		for w32.Module32Next(snap, &me) {
			proc.Modules[w32.UTF16PtrToString(&me.SzModule[0])] = Module{
				Name:        w32.UTF16PtrToString(&me.SzModule[0]),
				ModBaseAddr: uintptr(unsafe.Pointer(me.ModBaseAddr)),
				ModBaseSize: me.ModBaseSize,
			}
		}

		return proc, nil
	}
	return Process{}, fmt.Errorf("ProcessInfo failed on %d", pid)
}

func ProcessByName(name string) (Process, error) {
	procs := make([]uint32, 1024)
	var read uint32

	if !strings.HasSuffix(name, ".exe") {
		name += ".exe"
	}

	if w32.EnumProcesses(procs, 1024, &read) {
		for _, pid := range procs[:read/4] {
			processInfo, err := ProcessInfo(pid)
			if err == nil && processInfo.Name == name {
				err = processInfo.open()
				if err != nil {
					return processInfo, err
				}
				return processInfo, nil
			}
		}
	}

	return Process{}, fmt.Errorf("process %s not found", name)
}

func ProcessByPid(pid uint32) (Process, error) {
	processInfo, err := ProcessInfo(pid)
	if err != nil {
		return Process{}, err
	}
	err = processInfo.open()
	if err != nil {
		return Process{}, err
	}
	return processInfo, nil
}

func (p *Process) open() error {
	setDebugPrivilege()
	handle, err := w32.OpenProcess(w32.PROCESS_ALL_ACCESS, false, p.Pid)
	if err != nil {
		return fmt.Errorf("can't open process: %s", err.Error())
	}
	p.Handle = handle
	return nil
}

func (p *Process) Read(address uintptr, dataType string) (data interface{}, err error){
	dataType = strings.ToLower(dataType)

	switch dataType {
	case "int":
		data, err = p.ReadInt(address)
	case "float64":
		data, err = p.ReadFloat64(address)
	case "float32":
		data, err = p.ReadFloat32(address)
	case "string":
		data, err = p.ReadString(address)
	default:
		err = fmt.Errorf("invalid data type")
	}

	if err != nil {
		return nil, err
	}
	return
}

func (p *Process) Write(address uintptr, dataType string, data interface{}) (err error){
	dataType = strings.ToLower(dataType)

	switch dataType {
	case "int":
		err = p.WriteInt(address, data.(int))
	case "float":
		err = p.WriteFloat(address, data.(float32))
	case "string":
		err = p.WriteString(address, data.(string))
	default:
		err = fmt.Errorf("invalid data type")
	}

	if err != nil {
		return err
	}
	return
}

func (p *Process) ReadBytes(address uintptr, size uint) ([]byte, error) {
	data, err := w32.ReadProcessMemory(p.Handle, uint32(address), size)
	if err != nil {
		return nil, fmt.Errorf("reading error. reason: %s", err.Error())
	}
	return data, nil
}

func (p *Process) ReadInt(address uintptr) (int, error) {
	data, err := p.ReadBytes(address, 4)
	if err != nil {
		return 0, err
	}
	return int(binary.LittleEndian.Uint32(data)), nil
}

func (p *Process) ReadInts(address uintptr, num int) ([]int, error) {
	dataArray := make([]int, 0)
	data, err := p.ReadBytes(address, uint(num * 4))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(data); i += 4 {
		dataArray = append(dataArray, int(binary.LittleEndian.Uint32(data[i:i+4])))
	}
	return dataArray, nil
}

func (p *Process) ReadIntPtr(address uintptr) (uintptr, error) {
	data, err := p.ReadBytes(address, 4)
	if err != nil {
		return 0, err
	}
	return uintptr(binary.LittleEndian.Uint32(data)), nil
}

func (p *Process) ReadFloat32(address uintptr) (float32, error) {
	data, err := p.ReadBytes(address, 4)
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil
}

func (p *Process) ReadFloats32(address uintptr, num int) ([]float32, error) {
	dataArray := make([]float32, 0)
	data, err := p.ReadBytes(address, uint(num * 4))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(data); i += 4 {
		dataArray = append(dataArray, math.Float32frombits(binary.LittleEndian.Uint32(data[i:i+4])))
	}
	return dataArray, nil
}

func (p *Process) ReadFloat64(address uintptr) (float64, error) {
	data, err := p.ReadFloat32(address)
	if err != nil {
		return 0, err
	}
	return float64(data), nil
}

func (p *Process) ReadFloats64(address uintptr, num int) ([]float64, error) {
	dataArray := make([]float64, 0)
	data, err := p.ReadBytes(address, uint(num * 4))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(data); i += 4 {
		dataArray = append(dataArray, float64(math.Float32frombits(binary.LittleEndian.Uint32(data[i:i+4]))))
	}
	return dataArray, nil
}

func (p *Process) ReadString(address uintptr) (string, error) {
	stringBytes := make([]byte, 0)

	for {
		d, err := p.ReadBytes(address, 1)
		if err != nil {
			return "", err
		}
		if d[0] == 0 {
			break
		} else {
			address++
			stringBytes = append(stringBytes, d[0])
		}
	}
	return string(stringBytes[:]), nil
}

func (p *Process) WriteBytes(address uintptr, data []byte) error {
	err := w32.WriteProcessMemory(p.Handle, uint32(address), data, uint(len(data)))
	if err != nil {
		return fmt.Errorf("writing error. reason: %s", err.Error())
	}
	return nil
}

func (p *Process) WriteString(address uintptr, str string) error {
	data := []byte(str)
	err := p.WriteBytes(address, data)
	if err != nil {
		return err
	}
	return nil
}

func (p *Process) WriteInt(address uintptr, i int) error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(i))
	err := p.WriteBytes(address, data)
	if err != nil {
		return err
	}
	return nil
}

func (p *Process) WriteInts(address uintptr, data []int) error {
	byteArray := make([]byte, 4*len(data))
	for i, in := range data {
		binary.LittleEndian.PutUint32(byteArray[i*4:], uint32(in))
	}
	err := p.WriteBytes(address, byteArray)
	if err != nil {
		return err
	}
	return nil
}

func (p *Process) WriteFloat(address uintptr, f float32) error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[:], math.Float32bits(f))
	err := p.WriteBytes(address, data)
	if err != nil {
		return err
	}
	return nil
}

func (p *Process) WriteFloats(address uintptr, data []float32) error {
	byteArray := make([]byte, 4*len(data))
	for i, f := range data {
		binary.LittleEndian.PutUint32(byteArray[i*4:], math.Float32bits(f))
	}
	err := p.WriteBytes(address, byteArray)
	if err != nil {
		return err
	}
	return nil
}

func (p *Process) AOBScan(mod Module, pattern string, dereference bool, offset int, extra int) (uintptr, error) {
	// Credits to Rake @ https://guidedhacking.com/threads/external-internal-pattern-scanning-guide.14112/

	repl := strings.NewReplacer("?", "..", "??", "..", "x", "..", "X", "..", "*", "..", "**", "..", " ", "")

	re, err := regexp.Compile(repl.Replace(strings.ToLower(pattern)))
	if err != nil {
		return uintptr(0), fmt.Errorf("can't compile pattern (%s)", pattern)
	}

	mbi, err := VirtualQueryEx(p.Handle, mod.ModBaseAddr)
	if err != nil {
		return uintptr(0), err
	}

	for curr := mod.ModBaseAddr; curr < mod.ModBaseAddr + uintptr(mod.ModBaseSize); curr += mbi.RegionSize {
		mbi, _ = VirtualQueryEx(p.Handle, curr)
		if mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS { continue }

		oldProt, err := VirtualProtectEx(p.Handle, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE)
		if err != nil { continue }

		read, err := p.ReadBytes(mbi.BaseAddress, uint(mbi.RegionSize))
		if err != nil { continue }
		log.Debugf("Scanning 0x%06X - 0x%06X", mbi.BaseAddress, mbi.BaseAddress + mbi.RegionSize)

		_, _ = VirtualProtectEx(p.Handle, mbi.BaseAddress, mbi.RegionSize, oldProt)

		if index := re.FindStringIndex(strings.ToLower(hex.EncodeToString(read))); len(index) > 0 {
			log.Debugf("Pattern hit at 0x%06X", uintptr(index[0] / 2) + curr)
			if dereference {
				scanPtr, err := p.ReadIntPtr(uintptr(index[0]/2) + curr + uintptr(offset))
				if err != nil {
					return uintptr(0), err
				}
				return scanPtr + uintptr(extra), nil
			}
			return uintptr(index[0]/2) + curr, nil
		}
	}

	return uintptr(0), fmt.Errorf("pattern not found")
}