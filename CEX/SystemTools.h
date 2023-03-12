// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_SYSUTILS_H
#define CEX_SYSUTILS_H

#include "CexDomain.h"
#include "ArrayTools.h"
#include "CpuDetect.h"
#include <chrono>
#include <string>

#if defined(CEX_OS_WINDOWS)
#define _WINSOCKAPI_
#	include <Windows.h>
#	pragma comment(lib, "IPHLPAPI.lib")
#	include <iphlpapi.h>
#	include <intrin.h>  
#	include <Sddl.h>
#	include <tlhelp32.h>
#	if defined(CEX_COMPILER_MSC)
#		include <VersionHelpers.h>
#	endif
#elif defined(CEX_OS_UNIX)
#	include <time.h>
#	include <unistd.h>
#elif defined(CEX_OS_APPLE)
#	include <mach/mach.h>
#	include <mach/mach_time.h>
#	include <time.h>
#endif
#if defined(CEX_OS_POSIX)
#	include <dirent.h>
#	include <fstream>
#	include <ios>
#	include <iostream>
#	include <limits.h>
#	include <pwd.h>
#	include <stdio.h>
#	include <stdlib.h>
#	include <sys/resource.h>
#	include <sys/statvfs.h>
#	include <sys/sysctl.h>
#	include <sys/sysinfo.h>
#	include <sys/time.h>
#	include <sys/types.h>
#	include <unistd.h>
#endif

NAMESPACE_TOOLS

/// <summary>
/// System utilities class.
/// <para>Various functions used by the Entropy Collection Provider (ECP) as sources of entropy input.
/// Note* This class has only been tested in Windows, other operating systems currently may have limited support.</para>
/// </summary>
class SystemTools
{
private:

	// library version info
	static const int32_t CEX_VERSION_MAJOR = 1;
	static const int32_t CEX_VERSION_MINOR = 0;
	static const int32_t CEX_VERSION_PATCH = 0;
	static const int32_t CEX_VERSION_RELEASE = 4;

	static bool HAS_RDRAND;
	static bool TMR_RDTSC;

public:

	/// <summary>
	/// Return the computer name
	/// </summary>
	/// 
	/// <returns>A char vector</returns>
	static std::string ComputerName();

	/// <summary>
	/// Return an array of free space, total bytes, and available bytes for a drive
	/// </summary>
	/// 
	/// <param name="Drive">The drive to poll</param>
	///
	/// <returns>A vector of 64bit uint32_t sizes</returns>
	static std::vector<uint64_t> DriveSpace(const std::string &Drive);

	/// <summary>
	/// Return the intel RDRAND instructions
	/// </summary>
	/// 
	/// <returns>Returns the availability of the RDRAND instructions on this system</returns>
	static bool HasRdRand();

	/// <summary>
	/// Return the RDTSC frequency
	/// </summary>
	/// 
	/// <returns>The 64bit frequency size</returns>
	static uint64_t GetRdtscFrequency();

	/// <summary>
	/// Return availability of RDTSCP timer
	/// </summary>
	/// 
	/// <returns>True if available</returns>
	static bool HasRdtsc();

	/// <summary>
	/// Return the total physical memory size in bytes
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t MemoryPhysicalTotal();

	/// <summary>
	/// Return the used physical memory size in bytes
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t MemoryPhysicalUsed();

	/// <summary>
	/// Return the used virtual memory size in bytes
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t MemoryVirtualTotal();

	/// <summary>
	/// Return the used virtual memory size in bytes
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t MemoryVirtualUsed();

	/// <summary>
	/// Return the operating system name string
	/// </summary>
	/// 
	/// <returns>The name string</returns>
	static std::string OsName();

	/// <summary>
	/// Return the current process id
	/// </summary>
	/// 
	/// <returns>The 32bit process id</returns>
	static uint32_t ProcessId();

	/// <summary>
	/// Return the logged-in user name
	/// </summary>
	/// 
	/// <returns>A char vector</returns>
	static std::string UserName();

	/// <summary>
	/// Return the current time in nanoseconds
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t TimeCurrentNS();

	/// <summary>
	/// Return the system tick count
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t TimeStamp(bool HasRdtsc = false);

	/// <summary>
	/// Return the time in milliseconds since the system was booted
	/// </summary>
	/// 
	/// <returns>The 64bit uint32_t size</returns>
	static uint64_t TimeSinceBoot();

	/// <summary>
	/// Return the CEX library version string
	/// </summary>
	/// 
	/// <returns>The version string</returns>
	static std::string Version();

#if defined(CEX_OS_WINDOWS)

	/// <summary>
	/// Return an array ip adapter info structures
	/// </summary>
	/// 
	/// <returns>A vector of PIP_ADAPTER_INFO structures</returns>
	static std::vector<PIP_ADAPTER_INFO> AdaptersInfo();

	/// <summary>
	/// Return the current thread id
	/// </summary>
	/// 
	/// <returns>The 32bit uint32_t id</returns>
	static uint32_t CurrentThreadId();

	/// <summary>
	/// Return the current caret position
	/// </summary>
	/// 
	/// <returns>A POINT structure</returns>
	static POINT CursorPosition();

	/// <summary>
	/// Return the handle to the current module
	/// </summary>
	/// 
	/// <returns>An HMODULE handle</returns>
	static HMODULE GetCurrentModule();

	/// <summary>
	/// Return an array of heap entry structures for all running processes
	/// </summary>
	/// 
	/// <returns>A vector of HEAPENTRY32 structures</returns>
	static std::vector<HEAPENTRY32> HeapList();

	/// <summary>
	/// Return a string array of drive letters
	/// </summary>
	/// 
	/// <returns>A vector of path strings</returns>
	static std::vector<std::string> LogicalDrives();

	/// <summary>
	/// Return memory status information
	/// </summary>
	/// 
	/// <returns>A MEMORYSTATUSEX structure</returns>
	static MEMORYSTATUSEX MemoryStatus();

	/// <summary>
	/// Return an array of module entry structures for all running processes
	/// </summary>
	/// 
	/// <returns>A vector of MODULEENTRY32 structures</returns>
	static std::vector<MODULEENTRY32> ModuleEntries();

	/// <summary>
	/// Return the operating system version string.
	/// <para>Note: application must have manifest in Windows 10, or function will return Windows 8 or Server 2012</para>
	/// </summary>
	/// 
	/// <returns>The version string</returns>
	static std::string OsVersion();

	/// <summary>
	/// Return an array of process entry structures for all running processes
	/// </summary>
	/// 
	/// <returns>A vector of PROCESSENTRY32 structures</returns>
	static std::vector<PROCESSENTRY32> ProcessEntries();

	/// <summary>
	/// Guard a region of protected memory
	/// </summary>
	///
	/// <param name="Pointer">The pointer to the region of memory</param>
	/// <param name="Length">The amount of memory to protect</param>
	/// 
	/// <returns>Returns true for a successful operation</returns>
	static bool ProtectPages(void* Pointer, size_t Length);

	/// <summary>
	/// Release page guard on a memory region
	/// </summary>
	///
	/// <param name="Pointer">The pointer to the region of memory</param>
	/// <param name="Length">The amount of memory to protect</param>
	/// 
	/// <returns>Returns true for a successful operation</returns>
	static bool ReleaseProtectedPages(void* Pointer, size_t Length);

	/// <summary>
	/// Return a partial array of pre-formatted system CLSID strings
	/// <para>This function is used only for entropy collection, and returns only CLSIDS that contain no zeroes.</para>
	/// </summary>
	/// 
	/// <returns>A vector of CLSID strings</returns>
	static std::vector<std::string> SystemIds();

	/// <summary>
	/// Return system status information
	/// </summary>
	/// 
	/// <returns>A SYSTEM_INFO structure</returns>
	static SYSTEM_INFO SystemInfo();

	/// <summary>
	/// Return tcp transmission status information
	/// </summary>
	/// 
	/// <returns>A MIB_TCPSTATS structure</returns>
	static MIB_TCPSTATS TcpStatistics();

	/// <summary>
	/// Return an array of thread entry structures for all running processes
	/// </summary>
	/// 
	/// <returns>A vector of THREADENTRY32 structures</returns>
	static std::vector<THREADENTRY32> ThreadEntries();

	/// <summary>
	/// Return the logged-in users SID
	/// </summary>
	/// 
	/// <returns>The SID string</returns>
	static std::string UserId();

	/// <summary>
	/// Return the logged-in users info structure
	/// </summary>
	/// 
	/// <returns>A PTOKEN_USER structure</returns>
	static std::vector<uint8_t> UserToken();

#elif defined(CEX_OS_POSIX)

	/// <summary>
	/// The available free space on the primary hard drive
	/// </summary>
	/// 
	/// <returns>The available free space</returns>
	static uint64_t AvailableFreeSpace();

	/// <summary>
	/// Get a list of directories in the path
	/// </summary>
	///
	/// <param name="Path"></param>
	/// 
	/// <returns>A list of directory names in the path</returns>
	static std::vector<std::string> GetDirectories(std::string &Path);

	/// <summary>
	/// Get the file names in a directory
	/// </summary>
	/// 
	/// <returns>A list of file names in the directory</returns>
	static std::vector<std::string> GetFiles(std::string &Path);

	/// <summary>
	/// Get the path of the users home directory
	/// </summary>
	/// 
	/// <returns>The name of the users home directory</returns>
	static std::string GetHomeDirectory();

	/// <summary>
	/// Get the memory usage statistics
	/// </summary>
	/// 
	/// <returns>A binary dump of the memory statistics</returns>
	static std::string MemoryStatistics();

	/// <summary>
	/// Get the memory usage statistics
	/// </summary>
	/// 
	/// <returns>A binary dump of the network statistics</returns>
	static std::string NetworkStatistics();

	/// <summary>
	/// Return an array of process related values
	/// </summary>
	/// 
	/// <returns>A vector of process information</returns>
	static std::vector<uint32_t> ProcessEntries();

	/// <summary>
	/// Return an rusage struct with system usage information
	/// </summary>
	/// 
	/// <returns>An rusage struct</returns>
	static struct ::rusage SystemInfo();

	/// <summary>
	/// Return the user id string
	/// </summary>
	/// 
	/// <returns>A string containing the user id</returns>
	static std::string UserId();

#endif
};

NAMESPACE_TOOLSEND
#endif
