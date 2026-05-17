/*
===============================================================================

         FILE: main.go (win-agent-logtailer)
        USAGE: Executed on Windows endpoints to monitor agent logs
  DESCRIPTION: Live-Monitoring of ossec.log with ANSI color highlighting.
               Compatible with Wazuh agent logs.
 REQUIREMENTS: Windows Server/OS, Go (latest version recommended; backwards
               compatibility with older Go versions not tested)
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
      CREATED: 17/05/2026
     REVISION: 2

===============================================================================
LEGAL DISCLAIMER:
This is an independent community-developed utility and is not affiliated with,
endorsed by, or sponsored by Wazuh. It is described as "compatible with Wazuh
agent logs" and is not an official Wazuh product.

TRADEMARK NOTICE:
"Wazuh" is a trademark of Wazuh, Inc. The name is used solely to describe
compatibility with Wazuh agent logs. No right to use any third-party logo,
branding, service mark, or trade name is granted by this software or license.
===============================================================================
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

// ANSI Color Codes
const (
	ColorReset    = "\033[0m"
	ColorAlarmRed = "\033[91m" // CRITICAL
	ColorRed      = "\033[31m" // ERROR
	ColorCyan     = "\033[36m" // INFO
	ColorOrange   = "\033[33m" // WARNING
	ColorGray     = "\033[90m" // DEBUG
)

// init() forces Windows Server to render ANSI colors
func init() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	// --- 1. OUTPUT: Enable ANSI Colors ---
	outHandle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err == nil {
		var outMode uint32
		if err := syscall.GetConsoleMode(outHandle, &outMode); err == nil {
			// 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
			outMode |= 0x0004
			_, _, _ = setConsoleMode.Call(uintptr(outHandle), uintptr(outMode))
		}
	}
}

func main() {
	filePath := `C:\Program Files (x86)\ossec-agent\ossec.log`

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("%sCritical Error: Could not open %s.%s\n", ColorRed, filePath, ColorReset)
		time.Sleep(5 * time.Second)
		return
	}

	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("%sWarning closing the file: %v%s\n", ColorOrange, err, ColorReset)
		}
	}()

	// Seek to the end of the file
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Printf("%sCritical Error seeking to end of file: %v%s\n", ColorRed, err, ColorReset)
		time.Sleep(5 * time.Second)
		return
	}

	// Set window title natively via ANSI escape sequence
	fmt.Print("\033]0;win-agent-logtailer | Pause & Copy: Select Text | Resume: Enter or Right-Click\007")

	// Legal Disclaimer in stdout
	fmt.Printf("%s[!] DISCLAIMER: This is an independent community-developed utility and is not%s\n", ColorOrange, ColorReset)
	fmt.Printf("%s    affiliated with, endorsed by, or sponsored by Wazuh.%s\n", ColorOrange, ColorReset)

	fmt.Printf("%s[+] win-agent-logtailer started... Waiting for new events...%s\n", ColorCyan, ColorReset)
	fmt.Printf("---------------------------------------------------------------------\n")

	// 64 KB Buffer
	buf := make([]byte, 64*1024)
	var remainder []byte

	for {
		n, err := file.Read(buf)
		if n > 0 {
			chunk := append(remainder, buf[:n]...)

			for {
				idx := bytes.IndexByte(chunk, '\n')
				if idx == -1 {
					remainder = make([]byte, len(chunk))
					copy(remainder, chunk)
					break
				}

				lineBytes := chunk[:idx]

				if len(lineBytes) > 0 && lineBytes[len(lineBytes)-1] == '\r' {
					lineBytes = lineBytes[:len(lineBytes)-1]
				}

				line := string(lineBytes)

				color := ColorReset
				if strings.Contains(line, " CRITICAL: ") {
					color = ColorAlarmRed
				} else if strings.Contains(line, " ERROR: ") {
					color = ColorRed
				} else if strings.Contains(line, " WARNING: ") {
					color = ColorOrange
				} else if strings.Contains(line, " INFO: ") {
					color = ColorCyan
				} else if strings.Contains(line, " DEBUG: ") {
					color = ColorGray
				}

				fmt.Printf("%s%s%s\n", color, line, ColorReset)

				chunk = chunk[idx+1:]
			}
		} else if err == io.EOF {
			time.Sleep(500 * time.Millisecond)
		} else if err != nil {
			fmt.Printf("%sRead Error: %v%s\n", ColorRed, err, ColorReset)
			time.Sleep(1 * time.Second)
		}
	}
}
