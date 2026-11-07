//go:build windows

/*
===============================================================================
         FILE: main.go (win-eventstats)
        USAGE: Read Windows event channel statistics on the local endpoint
  DESCRIPTION: Reports Windows event log statistics to support Wazuh SIEM storage planning.
 REQUIREMENTS: Windows; administrative access for complete channel coverage
        NOTES: Copyright (c) 2026. Licensed under Custom License
               - See LICENSE.md for details
               - Provided WITHOUT WARRANTY
               - Test before production use
               - Use at your own risk
               - No support or guarantee provided
               - No Backup, no remorse
       AUTHOR: Stephan H. Wenderlich <stephan.wenderlich@gray-hat-it-security-consulting.de>
 ORGANIZATION: Gray-Hat IT-Security Consulting Stephan H. Wenderlich
               Web: https://gray-hat-it-security-consulting.de
      CREATED: 06/11/2026
     REVISION: 2
===============================================================================
LEGAL DISCLAIMER:
This independent community-developed utility has no affiliation with,
endorsement by, or sponsorship from Wazuh Inc. It is not an official Wazuh
product and does not require or inspect a Wazuh agent.

TRADEMARK NOTICE:
"Wazuh" is a trademark of Wazuh Inc. Its mention identifies the third party
covered by this disclaimer. No rights to third-party branding are granted.
===============================================================================
*/

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	sysmonChannel       = "Microsoft-Windows-Sysmon/Operational"
	evtOpenChannelPath  = 1
	evtQueryReverse     = 0x200
	evtLogFileSize      = 3
	evtLogRecordCount   = 5
	errorNoMoreItems    = syscall.Errno(259)
	errorSmallBuffer    = syscall.Errno(122)
	errorChannelMissing = syscall.Errno(15007)
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

type evtVariant struct {
	Value uint64
	Count uint32
	Type  uint32
}

type eventAPI struct {
	openEnum *syscall.LazyProc
	nextPath *syscall.LazyProc
	openLog  *syscall.LazyProc
	getInfo  *syscall.LazyProc
	query    *syscall.LazyProc
	next     *syscall.LazyProc
	context  *syscall.LazyProc
	render   *syscall.LazyProc
	close    *syscall.LazyProc
}

type channelStats struct {
	Name       string
	Events     uint64
	Bytes      uint64
	HaveEvents bool
	HaveBytes  bool
}

type summary struct {
	Name     string
	Channels uint64
	Events   uint64
	Bytes    uint64
}

type cell struct {
	Text  string
	Right bool
}

type eventError struct {
	Operation string
	Code      syscall.Errno
}

func (err eventError) Error() string {
	return fmt.Sprintf("%s failed (Windows error %d)", err.Operation, uint32(err.Code))
}

func (err eventError) Unwrap() error {
	return err.Code
}

var sysmonNames = map[uint16]string{
	1:   "ProcessCreate",
	2:   "FileCreateTime",
	3:   "NetworkConnect",
	4:   "ServiceStateChange",
	5:   "ProcessTerminate",
	6:   "DriverLoad",
	7:   "ImageLoad",
	8:   "CreateRemoteThread",
	9:   "RawAccessRead",
	10:  "ProcessAccess",
	11:  "FileCreate",
	12:  "RegistryEvent: Create/Delete",
	13:  "RegistryEvent: Value Set",
	14:  "RegistryEvent: Rename",
	15:  "FileCreateStreamHash",
	16:  "ServiceConfigurationChange",
	17:  "PipeEvent: Created",
	18:  "PipeEvent: Connected",
	19:  "WmiEvent: Filter",
	20:  "WmiEvent: Consumer",
	21:  "WmiEvent: ConsumerToFilter",
	22:  "DnsQuery",
	23:  "FileDelete: Archived",
	24:  "ClipboardChange",
	25:  "ProcessTampering",
	26:  "FileDeleteDetected",
	27:  "FileBlockExecutable",
	28:  "FileBlockShredding",
	29:  "FileExecutableDetected",
	255: "Error",
}

func run(ctx context.Context) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Legal Disclaimer in stdout
	fmt.Println("[!] DISCLAIMER: This is an independent community-developed utility and is not")
	fmt.Println("    affiliated with, endorsed by, or sponsored by Wazuh.")
	host, err := os.Hostname()
	if err != nil {
		host = "Unknown"
	}
	fmt.Printf("\nComputer: %s\n", host)

	api, err := loadEventAPI()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return 1
	}
	names, err := api.channels()
	if err != nil {
		fmt.Printf("ERROR: Could not enumerate event channels: %v\n", err)
		return 1
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})

	var channels []channelStats
	sysmonFound := false
	for _, name := range names {
		if ctx.Err() != nil {
			fmt.Println("WARNING: Scan canceled.")
			return 130
		}
		if strings.EqualFold(name, sysmonChannel) {
			sysmonFound = true
		}
		stats, _ := api.stats(name)
		if stats.HaveEvents || stats.HaveBytes {
			channels = append(channels, stats)
		}
	}

	printChannels(channels)
	header("SYSMON")
	code := 0
	if sysmonFound {
		counts, total, err := api.sysmonCounts(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				fmt.Println("WARNING: Sysmon scan canceled; no complete ID breakdown available.")
				code = 130
			} else {
				fmt.Printf("WARNING: Sysmon ID scan failed after %s events: %v\n", formatCount(total), err)
				code = 1
			}
		} else {
			printSysmon(counts, total)
		}
	} else {
		fmt.Println("No Sysmon Operational channel found.")
	}

	printSummary(channels)
	return code
}

func loadEventAPI() (*eventAPI, error) {
	getDirectory := kernel32.NewProc("GetSystemDirectoryW")
	if err := getDirectory.Find(); err != nil {
		return nil, fmt.Errorf("GetSystemDirectoryW is unavailable")
	}
	buffer := make([]uint16, 32768)
	n, _, callErr := getDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 {
		return nil, nativeError("GetSystemDirectoryW", callErr)
	}
	if n >= uintptr(len(buffer)) {
		return nil, fmt.Errorf("Windows system directory exceeds buffer size")
	}
	dll := syscall.NewLazyDLL(filepath.Join(syscall.UTF16ToString(buffer[:n]), "wevtapi.dll"))
	api := &eventAPI{
		openEnum: dll.NewProc("EvtOpenChannelEnum"), nextPath: dll.NewProc("EvtNextChannelPath"),
		openLog: dll.NewProc("EvtOpenLog"), getInfo: dll.NewProc("EvtGetLogInfo"),
		query: dll.NewProc("EvtQuery"), next: dll.NewProc("EvtNext"),
		context: dll.NewProc("EvtCreateRenderContext"), render: dll.NewProc("EvtRender"),
		close: dll.NewProc("EvtClose"),
	}
	for _, proc := range []*syscall.LazyProc{
		api.openEnum, api.nextPath, api.openLog, api.getInfo, api.query,
		api.next, api.context, api.render, api.close,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("Windows Event Log API function %s is unavailable", proc.Name)
		}
	}
	return api, nil
}

func nativeError(operation string, err error) error {
	var number syscall.Errno
	if errors.As(err, &number) && number != 0 {
		return eventError{Operation: operation, Code: number}
	}
	return fmt.Errorf("%s failed without a Windows error code", operation)
}

func missingLog(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) || errors.Is(err, errorChannelMissing)
}

func (api *eventAPI) closeHandle(handle uintptr) {
	if handle != 0 {
		_, _, _ = api.close.Call(handle)
	}
}

func (api *eventAPI) channels() ([]string, error) {
	handle, _, err := api.openEnum.Call(0, 0)
	if handle == 0 {
		return nil, nativeError("EvtOpenChannelEnum", err)
	}
	defer api.closeHandle(handle)
	buffer := make([]uint16, 256)
	var names []string
	seen := make(map[string]bool)
	for {
		var used uint32
		ok, _, err := api.nextPath.Call(handle, uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)))
		if ok == 0 {
			if errors.Is(err, errorNoMoreItems) {
				return names, nil
			}
			if errors.Is(err, errorSmallBuffer) && used > uint32(len(buffer)) {
				buffer = make([]uint16, used)
				continue
			}
			return nil, nativeError("EvtNextChannelPath", err)
		}
		name := syscall.UTF16ToString(buffer)
		key := strings.ToLower(name)
		if !seen[key] {
			seen[key] = true
			names = append(names, name)
		}
	}
}

func (api *eventAPI) stats(name string) (channelStats, error) {
	stats := channelStats{Name: name}
	path, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return stats, err
	}
	handle, _, callErr := api.openLog.Call(0, uintptr(unsafe.Pointer(path)), evtOpenChannelPath)
	if handle == 0 {
		readErr := nativeError("EvtOpenLog", callErr)
		if missingLog(readErr) {
			return stats, nil
		}
		return stats, readErr
	}
	defer api.closeHandle(handle)
	var countErr, sizeErr error
	stats.Events, countErr = api.logValue(handle, evtLogRecordCount)
	stats.HaveEvents = countErr == nil
	stats.Bytes, sizeErr = api.logValue(handle, evtLogFileSize)
	stats.HaveBytes = sizeErr == nil
	return stats, errors.Join(countErr, sizeErr)
}

func (api *eventAPI) logValue(handle uintptr, property uintptr) (uint64, error) {
	var value evtVariant
	var used uint32
	ok, _, err := api.getInfo.Call(handle, property, uintptr(unsafe.Sizeof(value)),
		uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&used)))
	if ok == 0 {
		return 0, nativeError("EvtGetLogInfo", err)
	}
	if used < uint32(unsafe.Sizeof(value)) || value.Type != 10 {
		return 0, fmt.Errorf("EvtGetLogInfo returned an unavailable or unexpected numeric value")
	}
	return value.Value, nil
}

func (api *eventAPI) sysmonCounts(ctx context.Context) (map[uint16]uint64, uint64, error) {
	path, _ := syscall.UTF16PtrFromString(sysmonChannel)
	query, _, err := api.query.Call(0, uintptr(unsafe.Pointer(path)), 0, evtOpenChannelPath|evtQueryReverse)
	if query == 0 {
		return nil, 0, nativeError("EvtQuery", err)
	}
	defer api.closeHandle(query)
	valuePath, _ := syscall.UTF16PtrFromString("Event/System/EventID")
	paths := [1]*uint16{valuePath}
	renderContext, _, err := api.context.Call(1, uintptr(unsafe.Pointer(&paths[0])), 0)
	runtime.KeepAlive(paths)
	if renderContext == 0 {
		return nil, 0, nativeError("EvtCreateRenderContext", err)
	}
	defer api.closeHandle(renderContext)

	counts := make(map[uint16]uint64)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return counts, total, err
		}
		var event uintptr
		var returned uint32
		ok, _, err := api.next.Call(query, 1, uintptr(unsafe.Pointer(&event)), 5000, 0,
			uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			api.closeHandle(event)
			if errors.Is(err, errorNoMoreItems) {
				return counts, total, nil
			}
			return counts, total, nativeError("EvtNext", err)
		}
		if returned != 1 || event == 0 {
			api.closeHandle(event)
			return counts, total, fmt.Errorf("EvtNext returned an unexpected event count")
		}
		id, readErr := api.eventID(renderContext, event)
		api.closeHandle(event)
		if readErr != nil {
			return counts, total, readErr
		}
		counts[id]++
		total++
	}
}

func (api *eventAPI) eventID(renderContext, event uintptr) (uint16, error) {
	var value evtVariant
	var used, count uint32
	ok, _, err := api.render.Call(renderContext, event, 0, uintptr(unsafe.Sizeof(value)),
		uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return 0, nativeError("EvtRender(EventID)", err)
	}
	if count != 1 || used < uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("EvtRender returned no unique Event ID")
	}
	var id uint64
	switch value.Type {
	case 4:
		id = uint64(uint8(value.Value))
	case 6:
		id = uint64(uint16(value.Value))
	case 8:
		id = uint64(uint32(value.Value))
	case 10:
		id = value.Value
	default:
		return 0, fmt.Errorf("EvtRender returned an unsupported Event ID type (%d)", value.Type)
	}
	if id > 65535 {
		return 0, fmt.Errorf("Event ID exceeds the Windows Event ID range")
	}
	return uint16(id), nil
}

func isSysmon(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "microsoft-windows-sysmon/")
}

func printChannels(channels []channelStats) {
	header("WINDOWS EVENT CHANNELS")
	var visible []channelStats
	for _, channel := range channels {
		if !isSysmon(channel.Name) && channel.HaveEvents && channel.Events > 0 {
			visible = append(visible, channel)
		}
	}
	if len(visible) == 0 {
		fmt.Println("No channels with stored events found.")
		return
	}
	sort.SliceStable(visible, func(i, j int) bool {
		return visible[i].Events > visible[j].Events
	})
	total := summaries(channels)[0].Events
	rows := [][]cell{{{Text: "Event Channel"}, {Text: "Total Events", Right: true},
		{Text: "Share (%)", Right: true}}}
	for _, channel := range visible {
		rows = append(rows, []cell{{Text: channel.Name}, {Text: formatCount(channel.Events), Right: true},
			{Text: fmt.Sprintf("%.2f", 100*float64(channel.Events)/float64(total)), Right: true}})
	}
	printTable(rows)
}

func printSysmon(counts map[uint16]uint64, total uint64) {
	ids := make([]int, 0, len(sysmonNames)+len(counts))
	for id := range sysmonNames {
		ids = append(ids, int(id))
	}
	for id := range counts {
		if _, known := sysmonNames[id]; !known {
			ids = append(ids, int(id))
		}
	}
	sort.Ints(ids)
	rows := [][]cell{{{Text: "Event Name"}, {Text: "Event ID", Right: true},
		{Text: "Total Events", Right: true}, {Text: "Share (%)", Right: true}}}
	for _, id := range ids {
		name := sysmonNames[uint16(id)]
		if name == "" {
			name = "Unknown Event ID"
		}
		count := counts[uint16(id)]
		share := 0.0
		if total > 0 {
			share = 100 * float64(count) / float64(total)
		}
		rows = append(rows, []cell{{Text: name}, {Text: strconv.Itoa(id), Right: true},
			{Text: formatCount(count), Right: true},
			{Text: fmt.Sprintf("%.2f", share), Right: true}})
	}
	printTable(rows)
}

func summaries(channels []channelStats) []summary {
	result := []summary{{Name: "Windows"}, {Name: "Sysmon"}, {Name: "TOTAL"}}
	for _, channel := range channels {
		group := 0
		if isSysmon(channel.Name) {
			group = 1
		}
		for _, index := range []int{group, 2} {
			if channel.HaveEvents {
				result[index].Events += channel.Events
				if channel.Events > 0 {
					result[index].Channels++
				}
			}
			if channel.HaveBytes {
				result[index].Bytes += channel.Bytes
			}
		}
	}
	return result
}

func printSummary(channels []channelStats) {
	header("SUMMARY")
	rows := [][]cell{{{Text: "Category"}, {Text: "Channels with Events", Right: true},
		{Text: "Total Events", Right: true}, {Text: "File Size (MiB)", Right: true}}}
	for _, total := range summaries(channels) {
		rows = append(rows, []cell{{Text: total.Name}, {Text: formatCount(total.Channels), Right: true},
			{Text: formatCount(total.Events), Right: true}, {Text: "~" + formatMiB(total.Bytes), Right: true}})
	}
	printTable(rows)
	fmt.Println()
}

func printTable(rows [][]cell) {
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for column, value := range row {
			widths[column] = max(widths[column], len([]rune(value.Text)))
		}
	}
	for index, row := range rows {
		for column, value := range row {
			padding := strings.Repeat(" ", widths[column]-len([]rune(value.Text)))
			if column > 0 {
				fmt.Print("  ")
			}
			if value.Right {
				fmt.Print(padding, value.Text)
			} else {
				fmt.Print(value.Text)
				if column < len(row)-1 {
					fmt.Print(padding)
				}
			}
		}
		fmt.Println()
		if index == 0 {
			for column, width := range widths {
				if column > 0 {
					fmt.Print("  ")
				}
				fmt.Print(strings.Repeat("-", width))
			}
			fmt.Println()
		}
	}
}

func formatCount(number uint64) string {
	text := strconv.FormatUint(number, 10)
	for position := len(text) - 3; position > 0; position -= 3 {
		text = text[:position] + "," + text[position:]
	}
	return text
}

func formatMiB(bytes uint64) string {
	text := fmt.Sprintf("%.2f", float64(bytes)/(1024*1024))
	parts := strings.SplitN(text, ".", 2)
	whole, _ := strconv.ParseUint(parts[0], 10, 64)
	return formatCount(whole) + "." + parts[1]
}

func header(title string) {
	fmt.Printf("\n=== %s ===\n\n", title)
}

func ownConsole() bool {
	input, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	var mode uint32
	if err != nil || syscall.GetConsoleMode(input, &mode) != nil {
		return false
	}
	proc := kernel32.NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var processes [2]uint32
	count, _, _ := proc.Call(uintptr(unsafe.Pointer(&processes[0])), uintptr(len(processes)))
	return count == 1
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx)
	stop()
	if code != 130 && ownConsole() {
		fmt.Print("\nPress Enter to exit...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}
