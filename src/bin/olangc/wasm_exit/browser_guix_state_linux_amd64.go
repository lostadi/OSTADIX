// Browser state is mounted by guest init, never by the OCI workload. The
// packaged /oci root remains the lower layer; only three Guix state paths
// receive persistent upper layers. Existing storage is never formatted here.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const guixStateProfilePath = "/oci/ostadix-guix-state.json"
const guixStateMarkerName = ".ostadix-guix-state.json"
const guixStateBytes = uint64(2147483648)
const guixStateCleanupBudget = 10 * time.Second
const blockGetSize64 = 0x80081272 // Linux amd64 BLKGETSIZE64.

var guixStatePin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$`)
var guixStateDiskName = regexp.MustCompile(`^sd[a-z]+$`)
var guixStateDiskAbsent = errors.New("no whole ext4 disk matches the Guix state UUID and size; existing storage is never formatted")

type guixStateProfile struct {
	Schema       string `json:"schema"`
	UUID         string `json:"uuid"`
	Bytes        uint64 `json:"bytes"`
	RuntimeImage string `json:"runtime_image"`
	Layout       uint32 `json:"layout"`
}

type guixStateLayout struct {
	name        string
	destination string
}

var guixStateLayouts = []guixStateLayout{
	{"store", "/gnu/store"},
	{"var-guix", "/var/guix"},
	{"root", "/root"},
}

type browserGuixState struct {
	private      string
	sysfs        string
	diskRoot     string
	sysfsMounted bool
	diskMounted  bool
	disk         *os.File
	filesystem   *os.File
	deviceNodes  []string
	directories  []string
	overlays     []string
}

func readGuixStateProfile(path string) (guixStateProfile, error) {
	var profile guixStateProfile
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return profile, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return profile, fmt.Errorf("Guix state profile must be a bounded regular file: %s", path)
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return profile, fmt.Errorf("invalid Guix state profile: %v", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return profile, fmt.Errorf("trailing data in Guix state profile")
	}
	if profile.Schema != "ostadix.guix-state/v1" || profile.Layout != 1 ||
		profile.Bytes != guixStateBytes || !guixStatePin.MatchString(profile.RuntimeImage) {
		return profile, fmt.Errorf("unsupported Guix state profile/schema/runtime image")
	}
	digest := sha256.Sum256([]byte(profile.RuntimeImage))
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(digest[:16])
	wantUUID := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	if profile.UUID != wantUUID {
		return profile, fmt.Errorf("Guix state UUID does not match its runtime image")
	}
	return profile, nil
}

func realGuixDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Guix state directory is not a real directory: %s", path)
	}
	return nil
}

func guixStatePathsOverlap(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	return left == right || left == "/" || right == "/" ||
		strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func (state *browserGuixState) privateDirectory(name string) (string, error) {
	path := filepath.Join(state.private, name)
	if err := os.Mkdir(path, 0700); err != nil {
		return "", err
	}
	state.directories = append(state.directories, path)
	return path, nil
}

func (state *browserGuixState) discoverDisk(profile guixStateProfile) error {
	entries, err := os.ReadDir(filepath.Join(state.sysfs, "class/block"))
	if err != nil {
		return err
	}
	wantUUID, err := hex.DecodeString(strings.ReplaceAll(profile.UUID, "-", ""))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !guixStateDiskName.MatchString(name) {
			continue // No optical devices, loop files, or partitions.
		}
		deviceText, err := os.ReadFile(filepath.Join(state.sysfs, "class/block", name, "dev"))
		if err != nil {
			return err
		}
		parts := strings.Split(strings.TrimSpace(string(deviceText)), ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid kernel block-device identity")
		}
		major, majorErr := strconv.ParseUint(parts[0], 10, 32)
		minor, minorErr := strconv.ParseUint(parts[1], 10, 32)
		if majorErr != nil || minorErr != nil {
			return fmt.Errorf("invalid kernel block-device numbers")
		}
		// Kernel sysfs determines the identity. Never expose this private device
		// node to the OCI workload or assume that USB port2 means /dev/sdb.
		node := filepath.Join(state.private, "device-"+name)
		if err := unix.Mknod(node, unix.S_IFBLK|0600, int(unix.Mkdev(uint32(major), uint32(minor)))); err != nil {
			return err
		}
		state.deviceNodes = append(state.deviceNodes, node)
		fd, err := unix.Open(node, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), node)
		var metadata unix.Stat_t
		if err := unix.Fstat(fd, &metadata); err != nil || metadata.Mode&unix.S_IFMT != unix.S_IFBLK ||
			unix.Major(uint64(metadata.Rdev)) != uint32(major) || unix.Minor(uint64(metadata.Rdev)) != uint32(minor) {
			file.Close()
			return fmt.Errorf("private Guix block-device identity mismatch")
		}
		var size uint64
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), blockGetSize64, uintptr(unsafe.Pointer(&size)))
		if errno != 0 {
			file.Close()
			return fmt.Errorf("read Guix block-device size: %v", errno)
		}
		var superblock [1024]byte
		if _, err := file.ReadAt(superblock[:], 1024); err != nil {
			file.Close()
			return fmt.Errorf("read Guix disk superblock: %v", err)
		}
		if binary.LittleEndian.Uint16(superblock[0x38:]) != 0xef53 || !bytes.Equal(superblock[0x68:0x78], wantUUID) {
			file.Close()
			continue
		}
		if state.disk != nil {
			file.Close()
			return fmt.Errorf("more than one disk has the expected Guix ext4 UUID")
		}
		if size != profile.Bytes {
			file.Close()
			return fmt.Errorf("Guix state disk size does not match its profile")
		}
		fsState := binary.LittleEndian.Uint16(superblock[0x3a:])
		incompat := binary.LittleEndian.Uint32(superblock[0x60:])
		if fsState&1 == 0 || fsState&2 != 0 || incompat&4 != 0 || binary.LittleEndian.Uint32(superblock[0xe8:]) != 0 {
			file.Close()
			return fmt.Errorf("Guix ext4 state is dirty or needs recovery; automatic recovery/formatting is disabled")
		}
		logBlockSize := binary.LittleEndian.Uint32(superblock[0x18:])
		blocks := uint64(binary.LittleEndian.Uint32(superblock[4:]))
		if incompat&0x80 != 0 {
			blocks |= uint64(binary.LittleEndian.Uint32(superblock[0x150:])) << 32
		}
		if logBlockSize > 6 || blocks != profile.Bytes/(uint64(1024)<<logBlockSize) {
			file.Close()
			return fmt.Errorf("Guix ext4 geometry does not match the fixed whole-disk profile")
		}
		state.disk = file
	}
	if state.disk == nil {
		return guixStateDiskAbsent
	}
	return nil
}

func (state *browserGuixState) waitForDisk(profile guixStateProfile) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := state.discoverDisk(profile)
		if !errors.Is(err, guixStateDiskAbsent) || !time.Now().Before(deadline) {
			return err
		}
		// USB disk discovery can finish after the root CDROM became ready.
		// Retry only an absent UUID; malformed or ambiguous disks fail at once.
		for _, node := range state.deviceNodes {
			if err := os.Remove(node); err != nil {
				return err
			}
		}
		state.deviceNodes = nil
		time.Sleep(100 * time.Millisecond)
	}
}

func prepareBrowserGuixState(spec *runtimespec.Spec, lowerRoot string) (prepared *browserGuixState, result error) {
	profile, err := readGuixStateProfile(guixStateProfilePath)
	if os.IsNotExist(err) {
		return nil, nil // Original sealed profile: no disk, mounts, or finalization tag.
	}
	if err != nil {
		return nil, err
	}
	if lowerRoot != "/oci/rootfs" || spec.Root == nil || spec.Root.Path != "/run/rootfs" || spec.Process == nil {
		return nil, fmt.Errorf("browser Guix state requires the fixed embedded OCI root")
	}
	var inheritedMounts []runtimespec.Mount
	for _, mount := range spec.Mounts {
		// c2w exposes ordinary WASI preopens to OCI automatically. The raw
		// disk is an emulator transport, not an additional workload mount.
		if filepath.Clean(mount.Destination) == "/browser-state" &&
			mount.Type == "bind" && filepath.Clean(mount.Source) == "/mnt/wasi0/browser-state" {
			continue
		}
		if guixStatePathsOverlap(mount.Destination, "/browser-state") ||
			(filepath.IsAbs(mount.Source) && guixStatePathsOverlap(mount.Source, "/mnt/wasi0/browser-state")) {
			return nil, fmt.Errorf("OCI mount would expose the raw Guix state transport")
		}
		if guixStatePathsOverlap(mount.Destination, "/ostadix") || guixStatePathsOverlap(mount.Destination, "/oci") {
			return nil, fmt.Errorf("OCI mount would replace the packaged program or immutable image")
		}
		for _, layout := range guixStateLayouts {
			if guixStatePathsOverlap(mount.Destination, layout.destination) {
				return nil, fmt.Errorf("OCI mount conflicts with Guix state destination: %s", mount.Destination)
			}
		}
		inheritedMounts = append(inheritedMounts, mount)
	}
	for _, path := range []string{"/oci", lowerRoot, lowerRoot + "/gnu", lowerRoot + "/gnu/store", lowerRoot + "/var", lowerRoot + "/var/guix", lowerRoot + "/root"} {
		if err := realGuixDirectory(path, false); err != nil {
			return nil, err
		}
	}
	private, err := os.MkdirTemp("/run", "ostadix-guix-state-")
	if err != nil {
		return nil, err
	}
	state := &browserGuixState{private: private}
	defer func() {
		if result != nil {
			if cleanupErr := state.finalizeWithinBudget(false); cleanupErr != nil {
				result = fmt.Errorf("Guix state admission failed: %v; rollback failed: %v", result, cleanupErr)
			}
		}
	}()
	state.sysfs, err = state.privateDirectory("sysfs")
	if err != nil {
		return nil, err
	}
	if err := unix.Mount("sysfs", state.sysfs, "sysfs", unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil {
		return nil, fmt.Errorf("mount private kernel device inventory: %v", err)
	}
	state.sysfsMounted = true
	if err := state.waitForDisk(profile); err != nil {
		return nil, err
	}
	if err := unix.Unmount(state.sysfs, 0); err != nil {
		return nil, err
	}
	state.sysfsMounted = false
	state.diskRoot, err = state.privateDirectory("filesystem")
	if err != nil {
		return nil, err
	}
	device := fmt.Sprintf("/proc/self/fd/%d", state.disk.Fd())
	if err := unix.Mount(device, state.diskRoot, "ext4", unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID, "noload"); err != nil {
		return nil, fmt.Errorf("read-only Guix state admission mount: %v", err)
	}
	state.diskMounted = true
	marker, err := readGuixStateProfile(filepath.Join(state.diskRoot, guixStateMarkerName))
	if err != nil || marker != profile {
		return nil, fmt.Errorf("Guix disk marker/runtime profile mismatch: %v", err)
	}
	if err := unix.Unmount(state.diskRoot, 0); err != nil {
		return nil, err
	}
	state.diskMounted = false
	if err := unix.Mount(device, state.diskRoot, "ext4", unix.MS_NODEV|unix.MS_NOSUID, "errors=remount-ro"); err != nil {
		return nil, fmt.Errorf("writable Guix state mount: %v", err)
	}
	state.diskMounted = true
	fd, err := unix.Open(state.diskRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	state.filesystem = os.NewFile(uintptr(fd), state.diskRoot)
	var mounts []runtimespec.Mount
	for _, layout := range guixStateLayouts {
		base := filepath.Join(state.diskRoot, layout.name)
		upper, work := filepath.Join(base, "upper"), filepath.Join(base, "work")
		for _, directory := range []string{base, upper, work} {
			// All layout directories come from the admitted initial image.
			// Missing persistent structure is corruption, not a fresh store.
			if err := realGuixDirectory(directory, false); err != nil {
				return nil, err
			}
		}
		merged, err := state.privateDirectory("merged-" + layout.name)
		if err != nil {
			return nil, err
		}
		options := "lowerdir=" + lowerRoot + layout.destination + ",upperdir=" + upper + ",workdir=" + work + ",index=off"
		if err := unix.Mount("overlay", merged, "overlay", unix.MS_NODEV|unix.MS_NOSUID, options); err != nil {
			return nil, fmt.Errorf("mount Guix state overlay %s: %v", layout.destination, err)
		}
		state.overlays = append(state.overlays, merged)
		mounts = append(mounts, runtimespec.Mount{
			Destination: layout.destination, Type: "bind", Source: merged,
			Options: []string{"rbind", "rw", "nodev", "nosuid", "rprivate"},
		})
	}
	spec.Mounts = append(inheritedMounts, mounts...)
	// These markers are safety opt-ins, not authentication. They are supplied
	// here only after the compile-time browser profile and disk were admitted.
	var environment []string
	for _, entry := range spec.Process.Env {
		if !strings.HasPrefix(entry, "OSTADIX_GUIX_BROWSER_STATE=") && !strings.HasPrefix(entry, "OSTADIX_GUIX_SESSION_GUEST=") {
			environment = append(environment, entry)
		}
	}
	spec.Process.Env = append(environment, "OSTADIX_GUIX_BROWSER_STATE=1", "OSTADIX_GUIX_SESSION_GUEST=1")
	return state, nil
}

type guixStateCommandOutput struct{ buffer bytes.Buffer }

func (output *guixStateCommandOutput) Bytes() []byte { return output.buffer.Bytes() }
func (output *guixStateCommandOutput) String() string { return output.buffer.String() }

func (output *guixStateCommandOutput) Write(data []byte) (int, error) {
	if output.buffer.Len()+len(data) > 65536 {
		return 0, fmt.Errorf("owned runc cleanup output exceeded its bound")
	}
	return output.buffer.Write(data)
}

func guixStateRunc(ctx context.Context, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/sbin/runc", arguments...)
	command.Env = []string{"PATH=/bin:/sbin:/usr/bin:/usr/sbin"}
	var output, diagnostic guixStateCommandOutput
	command.Stdout, command.Stderr = &output, &diagnostic
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("owned runc cleanup command failed: %v: %s", err, diagnostic.String())
	}
	return output.Bytes(), nil
}

func stopOwnedGuixContainer(ctx context.Context) error {
	listing, err := guixStateRunc(ctx, "list", "--format", "json")
	if err != nil {
		return err
	}
	var containers []struct{ ID string `json:"id"` }
	if err := json.Unmarshal(listing, &containers); err != nil {
		return fmt.Errorf("read owned runc container inventory: %v", err)
	}
	for _, container := range containers {
		if container.ID == "foo" { // Exact ID fixed by pinned create-spec.
			// A worker may have called setsid: runc/PID namespace ownership,
			// rather than the O backend's process group, is the boundary here.
			_, _ = guixStateRunc(ctx, "kill", "--all", "foo", "KILL")
			if _, err := guixStateRunc(ctx, "delete", "--force", "foo"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (state *browserGuixState) cleanup(ctx context.Context, stopContainer bool) error {
	if stopContainer {
		if err := stopOwnedGuixContainer(ctx); err != nil {
			return err
		}
	}
	for index := len(state.overlays) - 1; index >= 0; index-- {
		if err := unix.Unmount(state.overlays[index], 0); err != nil {
			return fmt.Errorf("unmount Guix state overlay: %v", err)
		}
	}
	if state.filesystem != nil {
		if err := unix.Syncfs(int(state.filesystem.Fd())); err != nil {
			return fmt.Errorf("sync Guix ext4 state: %v", err)
		}
		if err := state.filesystem.Close(); err != nil {
			return err
		}
		state.filesystem = nil
		unix.Sync()
	}
	if state.diskMounted {
		if err := unix.Unmount(state.diskRoot, 0); err != nil {
			return fmt.Errorf("unmount Guix ext4 state: %v", err)
		}
	}
	if state.sysfsMounted {
		if err := unix.Unmount(state.sysfs, 0); err != nil {
			return err
		}
	}
	if state.disk != nil {
		if err := state.disk.Close(); err != nil {
			return err
		}
	}
	for _, node := range state.deviceNodes {
		if err := os.Remove(node); err != nil {
			return err
		}
	}
	for index := len(state.directories) - 1; index >= 0; index-- {
		if err := os.Remove(state.directories[index]); err != nil {
			return err
		}
	}
	return os.Remove(state.private) // Never remove a persistent state directory.
}

func (state *browserGuixState) finalizeWithinBudget(stopContainer bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), guixStateCleanupBudget)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- state.cleanup(ctx, stopContainer) }()
	select {
	case err := <-finished:
		if ctx.Err() != nil {
			return fmt.Errorf("Guix state cleanup deadline expired; disk remains dirty")
		}
		return err
	case <-ctx.Done():
		// A blocked kernel sync/unmount is not cancellable. Never acknowledge
		// it later: only this caller can set stateFinalized, and the failure
		// now returns to the existing guest exit path for whole-VM teardown.
		return fmt.Errorf("Guix state cleanup deadline expired; disk remains dirty")
	}
}

func (state *browserGuixState) finish() error {
	stateFinalized = false
	if err := state.finalizeWithinBudget(true); err != nil {
		return err
	}
	stateFinalized = true
	return nil
}
