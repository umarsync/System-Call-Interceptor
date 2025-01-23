# System Call Interceptor Kernel Module

This kernel module intercepts and logs specific system calls (`open`, `read`, `write`) in the Linux kernel. It is designed for educational purposes and advanced debugging. The module dynamically hooks into the system call table, logs the intercepted calls, and restores the original behavior upon unloading.


## Features

- **Intercepts System Calls:** Hooks into the `open`, `read`, and `write` system calls.
- **Logs System Call Activity:** Logs intercepted system calls to the kernel log buffer (viewable using `dmesg`).
- **Dynamic Loading:** Can be loaded and unloaded dynamically using `insmod` and `rmmod`.
- **Educational Tool:** Demonstrates kernel hooking, system call table manipulation, and kernel module development.

## Prerequisites

- **Linux Kernel Development Environment:**
  - GCC compiler
  - Linux kernel headers
  - `make` utility
- **Root Access:** Required to load and unload kernel modules.

## Installation

### 1. Clone the Repository
Clone the repository to your local machine:
```bash
git clone https://github.com/umarsync/system-call-interceptor.git
cd system-call-interceptor
```

### 2. Compile the Kernel Module
Use the provided `Makefile` to compile the module:
```bash
make
```
This will generate a kernel object file named `syscall_interceptor.ko`.

### 3. Load the Module
Load the module into the kernel using `insmod`:
```bash
sudo insmod syscall_interceptor.ko
```

### 4. View Logs
Use `dmesg` to view the intercepted system call logs:
```bash
dmesg
```

### 5. Unload the Module
Unload the module when done:
```bash
sudo rmmod syscall_interceptor
```

## Usage

### Example Output
When the module is loaded, it logs intercepted system calls to the kernel log buffer. For example:
```bash
[  123.456789] syscall_interceptor: open("/etc/passwd", 0, 0)
[  123.567890] syscall_interceptor: read(3, 0x7ffd12345678, 1024)
[  123.678901] syscall_interceptor: write(1, 0x7ffd12345678, 512)
```

### Supported System Calls
- **`open`:** Logs the file path, flags, and mode.
- **`read`:** Logs the file descriptor, buffer address, and byte count.
- **`write`:** Logs the file descriptor, buffer address, and byte count.

## Advanced Configuration

### Filtering by Process ID (PID)
To log system calls only for specific processes, modify the `new_open`, `new_read`, and `new_write` functions to check the current process ID (`current->pid`).

### Logging to a File
Instead of logging to the kernel log buffer, you can write logs to a file in `/var/log`. Use `filp_open`, `vfs_write`, and `filp_close` to implement file-based logging.

### Rate Limiting
To avoid flooding the log buffer, implement rate limiting using a timer or a counter.

## Warning

- **System Stability:** Modifying the system call table can lead to system instability or kernel panics. Use this module in a controlled environment.
- **Security Risks:** This module can be used for malicious purposes. Ensure you have proper authorization before using it on any system.
- **Kernel Version Compatibility:** This module is tested on Linux kernels 5.x. It may require adjustments for other versions.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

### Steps to Contribute:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

## Acknowledgments

- Inspired by Linux kernel development tutorials and system call interception techniques.
- Special thanks to the Linux kernel community for their extensive documentation.

## References

- [Linux Kernel Module Programming Guide](https://tldp.org/LDP/lkmpg/2.6/html/)
- [Linux System Call Table](https://filippo.io/linux-syscall-table/)
- [Kernel Hooking Techniques](https://www.apriorit.com/dev-blog/544-linux-kernel-hooking)
