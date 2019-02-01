package godivert

import (
	"errors"
	"syscall"
	"unsafe"
)

type TCPHelper struct {
	dllHandle        syscall.Handle
	getConnectionPID uintptr
}

func NewTCPHelper() (*TCPHelper, error) {
	dllHandle, err := syscall.LoadLibrary("tcphelper.dll")
	if err != nil {
		return nil, err
	}
	getConnectionPID, err := syscall.GetProcAddress(dllHandle, "GetConnectionPID")
	if err != nil {
		return nil, err
	}

	tcpHelper := &TCPHelper{
		dllHandle:        dllHandle,
		getConnectionPID: getConnectionPID,
	}
	return tcpHelper, nil
}

func (th *TCPHelper) Close() {
	if th.dllHandle != 0 {
		syscall.FreeLibrary(th.dllHandle)
	}
}

func (th *TCPHelper) GetConnectionPID(srcPort int, srcIP string, addressFamily int) (int, error) {
	if th.dllHandle == 0 || th.getConnectionPID == 0 {
		return 0, errors.New("TCPHelper is not initialized")
	}
	var nargs uintptr = 3
	ret, _, callErr := syscall.Syscall(th.getConnectionPID, nargs, uintptr(srcPort), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(srcIP))), uintptr(addressFamily))
	if callErr != 0 {
		return 0, callErr
	}
	return int(ret), nil
}
