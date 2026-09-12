// The amd64 guest init owns this port, outside the workload's runc namespace.
// Its paired Bochs handler terminates WASI directly with the workload status.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

const wasiExitPort = 0xf4

// Linux amd64 UAPI asm-generic/ioctls.h; syscall does not export TCSBRK.
const tcdrainIoctl = 0x5409

func guestExitStatus(err error) byte {
	if err == nil {
		return 0
	}
	var child *exec.ExitError
	if errors.As(err, &child) {
		if status, ok := child.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return byte(128 + status.Signal())
		}
		if code := child.ExitCode(); code >= 0 && code <= 255 {
			return byte(code)
		}
	}
	// Init/setup failures are distinct from successful workload completion.
	return 125
}

func drainGuestTerminal(fd uintptr) error {
	for {
		// Linux tcdrain: wait for queued terminal output, without sending break.
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, tcdrainIoctl, 1)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 && errno != syscall.ENOTTY {
			return errno
		}
		return nil
	}
}

func transmitGuestExit(status byte) error {
	port, err := os.OpenFile("/dev/port", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open guest exit-status port: %w", err)
	}
	defer port.Close()
	if _, err := port.Seek(wasiExitPort, io.SeekStart); err != nil {
		return err
	}
	var signature [1]byte
	if _, err := io.ReadFull(port, signature[:]); err != nil {
		return err
	}
	if signature[0] != 0x4f {
		return fmt.Errorf("guest exit-status port is not implemented by this emulator")
	}
	for _, stream := range []*os.File{os.Stdout, os.Stderr} {
		if err := drainGuestTerminal(stream.Fd()); err != nil {
			return fmt.Errorf("drain guest terminal before exit: %w", err)
		}
	}
	if _, err := port.Seek(wasiExitPort, io.SeekStart); err != nil {
		return err
	}
	if _, err := port.Write([]byte{status}); err != nil {
		return err
	}
	// A paired emulator exits during the outb instruction. Returning means the
	// channel failed; never fall back to a poweroff that reports false success.
	return fmt.Errorf("guest exit-status write returned without terminating WASI")
}

func finishWithWASIStatus(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if failure := transmitGuestExit(guestExitStatus(err)); failure != nil {
		panic(failure)
	}
}
