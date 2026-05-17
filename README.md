# win-agent-logtailer

> **LEGAL DISCLAIMER:**  
> This is an independent community-developed utility and is not affiliated with, endorsed by, or sponsored by Wazuh. It is described as "compatible with Wazuh agent logs" and is not an official Wazuh product.  
> "Wazuh" is a trademark of Wazuh, Inc. The name is used solely to describe compatibility with Wazuh agent logs.

## Description

`win-agent-logtailer` is a lightweight, Go-based command-line utility designed to monitor local agent logs (`ossec.log`) in real-time on Windows systems. It acts as a native Windows equivalent to the Linux `tail -f` command and is intended for troubleshooting and monitoring Wazuh agent activity.

## Features

- **Real-Time Monitoring:** Continuously reads new entries appended to the `ossec.log` file.
- **Color-Coded Output:** Automatically parses log severity and applies ANSI color highlighting for better readability:
    - `CRITICAL`: Alarm red
    - `ERROR`: Red
    - `WARNING`: Orange
    - `INFO`: Cyan
    - `DEBUG`: Gray
- **Native Windows Support:** Enables ANSI color rendering in standard Windows consoles such as `cmd.exe` and PowerShell.
- **Zero Dependencies:** Distributed as a standalone, statically compiled `.exe` binary.

## Prerequisites

- Windows Operating System (Windows Server / Windows 10 / Windows 11)
- Installed Wazuh Agent (default path: `C:\Program Files (x86)\ossec-agent\`)
- **Execution Rights:** Administrative privileges may be required to access `ossec.log`, depending on the local file permissions.
- **Downloaded File Handling:** Windows may mark the downloaded executable as blocked or display a Microsoft Defender SmartScreen warning before first execution.

## Usage

1. Download the compiled `win-agent-logtailer.exe`.
2. Verify the published SHA256 checksum before executing the file.
3. If Windows marks the file as blocked, right-click the file, open **Properties**, and enable **Unblock** on the **General** tab.
4. If access to `ossec.log` is denied, start the tool from an elevated Command Prompt or elevated PowerShell session.
5. Execute the binary:
   ```cmd
   .\win-agent-logtailer.exe
   ```

**UI Controls:**
- **Pause Output:** Select any text inside the console window.
- **Resume Output:** Press `Enter` or right-click inside the console window.
- **Exit:** Press `Ctrl + C`.

## Windows execution notes

- **Administrative privileges may be required:**  
  If the process cannot access `C:\Program Files (x86)\ossec-agent\ossec.log`, start the tool from an elevated shell.
- **Unblock downloaded binaries if required:**  
  On some systems, Windows attaches a download origin marker to internet-downloaded files. If the executable is blocked, open the file properties and enable **Unblock** before starting it.
- **Microsoft Defender SmartScreen:**  
  Because this is an independently distributed utility, Windows may display a warning for an unrecognized app. Verify the SHA256 checksum from the official download page before deciding whether to run it.

## Building from Source

If you prefer to compile the binary yourself, ensure that Go is installed.

1. Clone the repository.
2. Open a terminal in the project root.
3. Run:
   ```cmd
   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/win-agent-logtailer.exe ./cmd/win-agent-logtailer
   ```

## License & Copyright

**Copyright (c) 2026 Stephan H. Wenderlich**  
**Gray-Hat IT-Security Consulting Stephan H. Wenderlich**  
**Web:** [https://gray-hat-it-security-consulting.de](https://gray-hat-it-security-consulting.de)

This project is licensed under a Custom License. See the [LICENSE.md](LICENSE.md) file for the full terms and conditions.

- This software is provided "AS IS" without warranty of any kind.
- Commercial use is restricted as defined in the license terms.
- Redistribution requires attribution and retention of the license text.