//go:build windows

package capture

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

// A Job Object closes the whole tshark/dumpcap process tree even if Netwatch
// is force-stopped and cannot run LiveHandle.Close.
const jobObjectExtendedLimitInformation = 9
const jobObjectLimitKillOnJobClose = 0x2000
const processSetQuota = 0x0100
const processTerminate = 0x0001

type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                jobIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var createJobObject = kernel32.NewProc("CreateJobObjectW")
var setJobInformation = kernel32.NewProc("SetInformationJobObject")
var openProcess = kernel32.NewProc("OpenProcess")
var assignProcessToJob = kernel32.NewProc("AssignProcessToJobObject")
var closeHandle = kernel32.NewProc("CloseHandle")

func bindCaptureLifetime(cmd *exec.Cmd) (func(), error) {
	job, _, callErr := createJobObject.Call(0, 0)
	if job == 0 {
		return nil, fmt.Errorf("CreateJobObjectW: %w", callErr)
	}
	closeJob := func() { _, _, _ = closeHandle.Call(job) }
	info := jobExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if ok, _, err := setJobInformation.Call(job, jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); ok == 0 {
		closeJob()
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	process, _, err := openProcess.Call(processSetQuota|processTerminate, 0, uintptr(cmd.Process.Pid))
	if process == 0 {
		closeJob()
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer closeHandle.Call(process)
	if ok, _, err := assignProcessToJob.Call(job, process); ok == 0 {
		closeJob()
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return closeJob, nil
}
