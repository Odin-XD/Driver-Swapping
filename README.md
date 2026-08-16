# Sign Bypass - Windows Driver Signature Bypass Framework

A Windows kernel driver signature bypass implementation that demonstrates advanced techniques for circumventing Windows driver signature enforcement. This project showcases the manipulation of kernel structures and memory to replace unsigned drivers with signed alternatives in system memory.

## 🔒 Core Mechanism

### Driver Signature Bypass Process

The signature bypass works by performing an in-memory driver swap after the Windows kernel has already loaded and verified a legitimate signed driver:

1. **Legitimate Driver Loading**: Windows loads a properly signed driver (the "host" driver)
2. **Memory Mapping**: Create memory mappings to the loaded driver's memory space
3. **Content Replacement**: Replace the legitimate driver's code with our unsigned driver code
4. **Certificate Preservation**: Keep the original driver's signature information intact
5. **Execution**: The unsigned code runs with the signed driver's identity

### Technical Implementation

#### Memory Manipulation (`write_to_read_only_memory`)
```cpp
DWORD write_to_read_only_memory(void* address, void* buffer, size_t size)
{
    // Uses Memory Descriptor Lists (MDL) to safely modify read-only kernel memory
    PMDL Mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(Mdl);
    
    // Map the memory with write access in kernel mode
    PVOID MappedAddress = MmMapLockedPagesSpecifyCache(
        Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        
    // Perform the memory replacement
    RtlCopyMemory(MappedAddress, buffer, size);
}
```

#### PE Header Management
- **Original Headers Backup**: Saves the legitimate driver's PE headers
- **Size Calculation**: Determines the exact memory regions to replace
- **Section Mapping**: Identifies and preserves critical sections (.text, .data, .rdata)

## 📁 Project Structure

```
Sign Bypass/
├── 📄 ZwSwapCert.cpp          # Main signature bypass implementation
├── 📄 ZwSwapCert.hpp          # Structure definitions and headers
├── 📄 RawDriver.hpp           # Embedded signed driver binary
├── 📄 ZwSwapCert.sln          # Visual Studio solution
├── 📄 ZwSwapCert.vcxproj      # Project configuration
└── 📁 x64/                   # Build artifacts
```

### Supported Platforms
- Windows 10 (1903+)
- Windows 11 (all versions)
- x64 architecture

## ⚙️ How It Works

### 1. Driver Host Selection
The framework requires a legitimate signed driver as a "host":
- Uses embedded signed driver binary (`RawDriver.hpp`)
- Driver must be loaded and running in kernel space
- Signature and certificate chains remain valid

### 2. Memory Layout Analysis
```cpp
// Analyze loaded driver structure
PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)driverStartSaved;
PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)driverStartSaved + dosHeaders->e_lfanew);

// Calculate memory regions
int headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
PVOID textSection = (PVOID)((ULONG_PTR)driverStartSaved + textSectionRVA);
```

### 3. In-Memory Replacement
- **Backup Original**: Save the legitimate driver's code sections
- **Calculate Sizes**: Determine exact memory ranges for replacement
- **Atomic Swap**: Replace code sections while preserving driver identity
- **Maintain Integrity**: Keep PE structure and signature metadata intact

### 4. Signature Preservation
The bypass maintains the appearance of a legitimate signed driver:
- **Certificate Chain**: Original signing certificates remain valid
- **PE Authenticode**: Signature verification still passes
- **System Trust**: Windows continues to trust the driver identity

## 🔍 Key Components

### Core Variables
```cpp
UNICODE_STRING DriverPath;              // Path to legitimate signed driver
PVOID FileCopy;                         // Copy of original driver file
PIMAGE_DOS_HEADER originalHeaders;      // Backup of PE headers
PVOID originalTextSection;              // Backup of original code
SIZE_T textSize;                        // Size of code section to replace
```

### Embedded Driver Binary
The `RawDriver.hpp` contains a legitimate signed driver binary:
- **Size**: 42,880 bytes on disk, 0x1D000 bytes in memory
- **Format**: Embedded as byte array in source code
- **Purpose**: Serves as the "host" driver for signature spoofing

## 🛡️ Detection Evasion

### Techniques Used
1. **Memory-Only Operation**: No unsigned files written to disk
2. **Legitimate Driver Host**: Uses real signed driver as cover
3. **Atomic Replacement**: Minimizes detection windows during swap
4. **Signature Preservation**: Maintains valid certificate chains

## ⚠️ Legal Notice

**This project is for educational and security research purposes only.**


### Windows Internals
- [Windows Driver Security Model](https://docs.microsoft.com/en-us/windows-hardware/drivers/driversecurity/)
- [Code Integrity and Driver Signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity)
- [Memory Descriptor Lists (MDL)](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)

### PE Format Documentation  
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Authenticode Signature Format](https://docs.microsoft.com/en-us/windows/win32/seccrypto/authenticode)

### Security Research
- Driver signature enforcement bypass techniques
- Kernel memory manipulation methods
- Windows security model analysis

---

**⚡ Advanced kernel-level signature bypass for security research**

*This implementation demonstrates sophisticated Windows internals manipulation - use only for legitimate security research and education.*