package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Load required Windows DLLs and procedures
var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	ntdll             = syscall.NewLazyDLL("ntdll.dll")
	
	setConsoleCP      = kernel32.NewProc("SetConsoleOutputCP")
	openProcess       = kernel32.NewProc("OpenProcess")
	duplicateHandle   = kernel32.NewProc("DuplicateHandle")
	getCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	createToolhelp    = kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First    = kernel32.NewProc("Process32FirstW")
	process32Next     = kernel32.NewProc("Process32NextW")
	
	ntQueryObject     = ntdll.NewProc("NtQueryObject")
	ntQuerySystemInfo = ntdll.NewProc("NtQuerySystemInformation")
)

// Windows API constants
const (
	PROCESS_DUP_HANDLE        = 0x0040
	PROCESS_QUERY_INFORMATION = 0x0400
	DUPLICATE_CLOSE_SOURCE    = 0x00000001
	DUPLICATE_SAME_ACCESS     = 0x00000002
	TH32CS_SNAPPROCESS        = 0x00000002
	SystemHandleInformation   = 16
)

// ANSI color codes for terminal output
const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	grey   = "\033[90m"
	white  = "\033[97m"
)

// Roblox uses these named handles to prevent multiple instances from running.
// By closing them in the target process, we can bypass this restriction.
var targetHandles = []string{
	"ROBLOX_singletonEvent",
}
// PROCESSENTRY32 matches the Windows struct required for CreateToolhelp32Snapshot
type PROCESSENTRY32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// enableANSIColors enables VT100 escape sequences in the Windows console
// so our colored output renders correctly.
func enableANSIColors() {
	getStdHandle := kernel32.NewProc("GetStdHandle")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	
	outHandle, _, _ := getStdHandle.Call(uintptr(0xFFFFFFF4)) // STD_OUTPUT_HANDLE
	var mode uint32
	getConsoleMode.Call(outHandle, uintptr(unsafe.Pointer(&mode)))
	setConsoleMode.Call(outHandle, uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
}

// getRobloxPIDs scans running processes and returns a list of PIDs for RobloxPlayerBeta.exe
func getRobloxPIDs() []uint32 {
	snap, _, _ := createToolhelp.Call(TH32CS_SNAPPROCESS, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var pids []uint32
	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := process32First.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		if name == "RobloxPlayerBeta.exe" {
			pids = append(pids, pe.ProcessID)
		}
		ret, _, _ = process32Next.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return pids
}

// getSystemHandleBuffer queries the OS for all open handles.
// It dynamically resizes the buffer if the handle list is too large.
func getSystemHandleBuffer() []byte {
	var bufSize uint32 = 1024 * 1024 // Start with 1MB buffer
	for {
		buf := make([]byte, bufSize)
		status, _, _ := ntQuerySystemInfo.Call(
			SystemHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&bufSize)),
		)
		
		if status == 0 { // STATUS_SUCCESS
			return buf
		}
		
		bufSize *= 2
		if bufSize > 64*1024*1024 { // Cap at 64MB to prevent memory leaks
			return nil
		}
	}
}

// getHandleName duplicates a handle to our own process so we can query its name,
// then returns the string representation.
func getHandleName(hProcess uintptr, handleValue uint16) string {
	selfHandle, _, _ := getCurrentProcess.Call()

	var dupHandle uintptr
	ret, _, _ := duplicateHandle.Call(
		hProcess,
		uintptr(handleValue),
		selfHandle,
		uintptr(unsafe.Pointer(&dupHandle)),
		0, 0,
		DUPLICATE_SAME_ACCESS,
	)
	if ret == 0 {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(dupHandle))

	nameBuf := make([]byte, 1024)
	var retLen uint32
	ntQueryObject.Call(
		dupHandle,
		1, // ObjectNameInformation
		uintptr(unsafe.Pointer(&nameBuf[0])),
		uintptr(len(nameBuf)),
		uintptr(unsafe.Pointer(&retLen)),
	)

	// A valid name buffer must be at least 16 bytes (UNICODE_STRING struct size)
	if retLen < 16 {
		return ""
	}
	
	nameLen := *(*uint16)(unsafe.Pointer(&nameBuf[0]))
	if nameLen == 0 || int(nameLen) > 512 {
		return ""
	}
	
	return syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(&nameBuf[16]))[:nameLen/2])
}

// closeSingletonHandles looks for Roblox singleton mutexes/events in the target process
// and forces them closed. Returns the number of closed handles.
func closeSingletonHandles(pid uint32) int {
	hProcess, _, _ := openProcess.Call(
		PROCESS_DUP_HANDLE|PROCESS_QUERY_INFORMATION,
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	buf := getSystemHandleBuffer()
	if buf == nil {
		return 0
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	entrySize := uintptr(24) // SYSTEM_HANDLE_TABLE_ENTRY_INFO struct size
	base := uintptr(unsafe.Pointer(&buf[8]))

	closedCount := 0
	for i := uintptr(0); i < uintptr(count); i++ {
		ptr := base + i*entrySize
		ownerPID := *(*uint32)(unsafe.Pointer(ptr))
		
		// Only inspect handles belonging to our target Roblox process
		if ownerPID != pid {
			continue
		}
		
		handleValue := *(*uint16)(unsafe.Pointer(ptr + 6))
		name := getHandleName(hProcess, handleValue)
		if name == "" {
			continue
		}

		for _, target := range targetHandles {
			if strings.HasSuffix(name, target) {
				// We found the singleton handle. Duplicate it with DUPLICATE_CLOSE_SOURCE
				// and ignore the duplicated output. This closes the handle in the target process.
				duplicateHandle.Call(
					hProcess,
					uintptr(handleValue),
					0,
					0,
					0,
					0,
					DUPLICATE_CLOSE_SOURCE,
				)
				fmt.Printf("%s  [CLOSED] %s (handle=0x%x)%s\n", green, target, handleValue, reset)
				closedCount++
				break
			}
		}
	}
	return closedCount
}

func main() {
	// Lock main goroutine to current OS thread (required for some Windows API calls)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	enableANSIColors()
	setConsoleCP.Call(65001) // Set console output to UTF-8

	// Handle graceful shutdown on Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n%sExiting...%s\n", yellow, reset)
		os.Exit(0)
	}()

	fmt.Println()
	fmt.Printf("%s=========================================================%s\n", cyan, reset)
	fmt.Printf("%s                     Multi Instances                     %s\n", white, reset)
	fmt.Printf("%s=========================================================%s\n", cyan, reset)
	fmt.Println()
	fmt.Printf("%sTarget Handles:%s %s\n", white, reset, strings.Join(targetHandles, ", "))
	fmt.Printf("%sPress Ctrl+C to exit.%s\n", grey, reset)
	fmt.Println()

	processedPIDs := make(map[uint32]bool)
	unlockedTotal := 0

	// Main monitoring loop
	for {
		time.Sleep(50 * time.Millisecond)

		pids := getRobloxPIDs()

		// Cleanup dead processes from our tracking map to avoid memory bloat over time
		activePIDs := make(map[uint32]bool)
		for _, pid := range pids {
			activePIDs[pid] = true
		}
		for pid := range processedPIDs {
			if !activePIDs[pid] {
				delete(processedPIDs, pid)
			}
		}

		// Process new Roblox instances
		for _, pid := range pids {
			if processedPIDs[pid] {
				continue
			}
			
			now := time.Now().Format("15:04:05.000")
			fmt.Printf("%s[%s] New process detected PID=%d%s\n", cyan, now, pid, reset)

			// The target handles might not be created instantly when the process starts.
			// Retry fetching and closing them for up to ~5 seconds.
			handlesClosed := 0
			for attempt := 0; attempt < 100; attempt++ {
				handlesClosed = closeSingletonHandles(pid)
				if handlesClosed > 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}

			if handlesClosed > 0 {
				unlockedTotal++
				fmt.Printf("%s  -> Closed %d handle(s). Total instances unlocked: %d%s\n", green, handlesClosed, unlockedTotal, reset)
			} else {
				fmt.Printf("%s  -> Singleton handles not found after 5s timeout%s\n", yellow, reset)
			}
			
			// Mark as processed regardless of success to prevent infinite looping on a stubborn process
			processedPIDs[pid] = true
		}
	}
}
