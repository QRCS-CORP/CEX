#include "SystemTools.h"

NAMESPACE_UTILITY

bool SystemTools::TMR_RDTSC = false;

std::string SystemTools::ComputerName()
{
	std::string ret("");

#if defined(CEX_OS_WINDOWS)
	try
	{
		TCHAR buffer[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD buffLen = sizeof(buffer) / sizeof(TCHAR);
		GetComputerName(buffer, &buffLen);

#if defined(UNICODE)
		std::wstring cpy((wchar_t*)buffer, buffLen);
		ret.assign(cpy.begin(), cpy.end());
#else
		ret.assign((char*)buffer, buffLen);
#endif
	}
	catch (std::exception&) 
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		char buffer[HOST_NAME_MAX];
		gethostname(buffer, HOST_NAME_MAX);

#if defined(UNICODE)
		std::wstring cpy((wchar_t*)buffer, buffLen);
		ret.assign(cpy.begin(), cpy.end());
#else
		ret.assign((char*)buffer, buffLen);
#endif
	}
	catch (std::exception&) 
	{
	}

#endif
	
	return ret;
}

std::vector<ulong> SystemTools::DriveSpace(const std::string &Drive)
{
#if defined(CEX_OS_WINDOWS)

	std::vector<ulong> retSizes(0);
	ULARGE_INTEGER freeBytes;
	ULARGE_INTEGER totalBytes;
	ULARGE_INTEGER availBytes;
	std::wstring ws;

	try
	{
		ws.assign(Drive.begin(), Drive.end());
		UINT drvType = GetDriveType(ws.c_str());

		if (drvType == 3 || drvType == 6)
		{
			if (GetDiskFreeSpaceEx(ws.c_str(), &freeBytes, &totalBytes, &availBytes))
			{
				retSizes.push_back(static_cast<ulong>(freeBytes.QuadPart));
				retSizes.push_back(static_cast<ulong>(totalBytes.QuadPart));
				retSizes.push_back(static_cast<ulong>(availBytes.QuadPart));
			}
		}
	}
	catch (std::exception&) 
	{
	}

	return retSizes;

#elif defined(CEX_OS_POSIX)

	std::vector<ulong> retSizes(0);

	try
	{
		struct statvfs fsinfo;
		statvfs("/", &fsinfo);

		retSizes.push_back(static_cast<ulong>(fsinfo.f_frsize * fsinfo.f_blocks));
		retSizes.push_back(static_cast<ulong>(fsinfo.f_bsize * fsinfo.f_bfree));
	}
	catch (std::exception&) 
	{
	}

	return retSizes;

#else
	return 0;
#endif
}

ulong SystemTools::GetRdtscFrequency()
{
	if (HasRdtsc())
	{
		ulong first = __rdtsc();
		Sleep(10);
		ulong second = __rdtsc();

		return (second - first) * 100;
	}
	else
	{
		return 0;
	}
}

bool SystemTools::HasRdRand()
{
	CpuDetect detect;

 	return detect.RDRAND();
}

bool SystemTools::HasRdtsc()
{
	if (!TMR_RDTSC)
	{
		CpuDetect detect;
		TMR_RDTSC = detect.RDTSCP();
	}

	return TMR_RDTSC;
}

ulong SystemTools::MemoryPhysicalTotal()
{
#if defined(CEX_OS_WINDOWS)

	// http://stackoverflow.com/questions/63166/how-to-determine-cpu-and-memory-consumption-from-inside-a-process
	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);
	}
	catch (std::exception&) 
	{
	}

	return static_cast<ulong>(memInfo.ullTotalPhys);

#elif defined(CEX_OS_POSIX)

	long long totalPhysMem = 0;

	try
	{
		struct sysinfo memInfo;
		sysinfo(&memInfo);
		totalPhysMem = memInfo.totalram;
		totalPhysMem *= memInfo.mem_unit;

		return static_cast<ulong>(totalPhysMem);
	}
	catch (std::exception&) 
	{
		return 0;
	}

#else
	return 0;
#endif
}

ulong SystemTools::MemoryPhysicalUsed()
{
#if defined(CEX_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);

		return static_cast<ulong>(memInfo.ullTotalPhys - memInfo.ullAvailPhys);
	}
	catch (std::exception&) 
	{
		return 0;
	}

#elif defined(CEX_OS_POSIX)

	long long physMemUsed = 0;

	try
	{
		struct sysinfo memInfo;
		sysinfo(&memInfo);
		physMemUsed = memInfo.totalram - memInfo.freeram;
		physMemUsed *= memInfo.mem_unit;
	}
	catch (std::exception&) 
	{
	}

	return static_cast<ulong>(physMemUsed);

#else
	return 0;
#endif
}

ulong SystemTools::MemoryVirtualTotal()
{
#if defined(CEX_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);

		return static_cast<ulong>(memInfo.ullTotalPageFile);
	}
	catch (std::exception&) 
	{
		return 0;
	}

#elif defined(CEX_OS_POSIX)

	struct sysinfo memInfo;
	long long totalVirtualMem = 0;

	try
	{
		sysinfo(&memInfo);
		totalVirtualMem = memInfo.totalram;
		totalVirtualMem += memInfo.totalswap;
		totalVirtualMem *= memInfo.mem_unit;
	}
	catch (std::exception&) 
	{
	}

	return static_cast<ulong>(totalVirtualMem);

#else
	return 0;
#endif
}

ulong SystemTools::MemoryVirtualUsed()
{
#if defined(CEX_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);

		return static_cast<ulong>(memInfo.ullTotalPageFile - memInfo.ullAvailPageFile);
	}
	catch (std::exception&) 
	{
		return 0;
	}

#elif defined(CEX_OS_POSIX)

	long long virtualMemUsed = 0;

	try
	{
		struct sysinfo memInfo;
		sysinfo(&memInfo);
		virtualMemUsed = memInfo.totalram - memInfo.freeram;
		virtualMemUsed += memInfo.totalswap - memInfo.freeswap;
		virtualMemUsed *= memInfo.mem_unit;
	}
	catch (std::exception&)
	{
	}

	return static_cast<ulong>(virtualMemUsed);

#else
	return 0;
#endif
}

std::string SystemTools::OsName()
{
#ifdef _WIN32
	return "Windows 32-bit";
#elif _WIN64
	return "Windows 64-bit";
#elif __unix || __unix__
	return "Unix";
#elif __APPLE__ || __MACH__
	return "Mac OSX";
#elif __linux__
	return "Linux";
#elif __FreeBSD__
	return "FreeBSD";
#else
	return "Other";
#endif
}

uint SystemTools::ProcessId()
{
#if defined(CEX_OS_WINDOWS)
	try 
	{
		return static_cast<uint>(GetCurrentProcessId());
	}
	catch (std::exception&)
	{
		return 0;
	}
#else
	try
	{
		return static_cast<uint>(::getpid());
	}
	catch (std::exception&)
	{
		return 0;
	}
#endif
}

ulong SystemTools::TimeCurrentNS()
{
	return static_cast<ulong>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
}

ulong SystemTools::TimeStamp(bool HasRdtsc)
{
	ulong tmeStamp = 0;

	// http://nadeausoftware.com/articles/2012/04/c_c_tip_how_measure_elapsed_real_time_benchmarking
#if defined(CEX_OS_WINDOWS)
	try
	{
		if (HasRdtsc)
		{
			// use tsc if available
			tmeStamp = static_cast<ulong>(__rdtsc());
		}
		else
		{
			int64_t ctr1 = 0;
			int64_t freq = 0;

			if (QueryPerformanceCounter((LARGE_INTEGER *)&ctr1) != 0)
			{
				QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
				// return microseconds to milliseconds
				if (freq > 0)
				{
					tmeStamp = static_cast<ulong>(ctr1 * 1000.0 / freq);
				}
			}
			else
			{
				FILETIME ft;
				LARGE_INTEGER li;
				// Get the amount of 100 nano seconds intervals elapsed since January 1, 1601 (UTC) and copy it to a LARGE_INTEGER structure
				GetSystemTimeAsFileTime(&ft);
				li.LowPart = ft.dwLowDateTime;
				li.HighPart = ft.dwHighDateTime;
				tmeStamp = static_cast<ulong>(li.QuadPart);
				// Convert from file time to UNIX epoch time.
				tmeStamp -= 116444736000000000LL; 
				// From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals
				tmeStamp /= 10000;
			}
		}
	}
	catch (std::exception&) 
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		tmeStamp = static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif (defined(CEX_OS_HPUX) || defined(CEX_OS_SUNUX)) && (defined(__SVR4) || defined(__svr4__))

	// HP-UX, Solaris
	try
	{
		tmeStamp = static_cast<ulong>(gethrtime());
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		tmeStamp = static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif defined(CEX_OS_APPLE)
	// OSX
	try
	{
		static double timeConvert = 0.0;
		mach_timebase_info_data_t timeBase;
		(void)mach_timebase_info(&timeBase);
		timeConvert = timeBase.numer / timeBase.denom;
		tmeStamp = static_cast<ulong>(mach_absolute_time() * timeConvert);
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		tmeStamp = static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif defined(CEX_OS_POSIX)

	// POSIX
#	if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0)
	{
		struct timespec ts;
#		if defined(CLOCK_MONOTONIC_PRECISE)
			// BSD
			const clockid_t id = CLOCK_MONOTONIC_PRECISE;
#		elif defined(CLOCK_MONOTONIC_RAW)
			// Linux
			const clockid_t id = CLOCK_MONOTONIC_RAW;
#		elif defined(CLOCK_HIGHRES)
			// Solaris
			const clockid_t id = CLOCK_HIGHRES;
#		elif defined(CLOCK_MONOTONIC)
			// AIX, BSD, Linux, POSIX, Solaris
			const clockid_t id = CLOCK_MONOTONIC;
#		elif defined(CLOCK_REALTIME)
			// AIX, BSD, HP-UX, Linux, POSIX
			const clockid_t id = CLOCK_REALTIME;
#		else
			// Unknown
			const clockid_t id = (clockid_t)-1;
#		endif
		try
		{
			if (id != (clockid_t)-1 && clock_gettime(id, &ts) != -1)
			{
				tmeStamp = static_cast<ulong>(ts.tv_sec + ts.tv_nsec);
			}
		}
		catch (std::exception&)
		{
			std::chrono::high_resolution_clock::time_point epoch;
			auto now = std::chrono::high_resolution_clock::now();
			auto elapsed = now - epoch;

			tmeStamp = static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
		}
	}

#endif

	// AIX, BSD, Cygwin, HP-UX, Linux, OSX, POSIX, Solaris
	try
	{
		struct timeval tm;
		gettimeofday(&tm, NULL);

		tmeStamp = static_cast<ulong>(tm.tv_sec + tm.tv_usec);
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;

		tmeStamp = static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#else
	std::chrono::high_resolution_clock::time_point epoch;
	auto now = std::chrono::high_resolution_clock::now();
	auto elapsed = now - epoch;

	tmeStamp = static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
#endif

	return tmeStamp;
}

ulong SystemTools::TimeSinceBoot()
{
	// http://stackoverflow.com/questions/30095439/how-do-i-get-system-up-time-in-milliseconds-in-c
#if defined(CEX_OS_WINDOWS)

	try
	{
		return std::chrono::milliseconds(GetTickCount64()).count();
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;

		return static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		std::chrono::milliseconds uptime(0U);
		struct timespec ts;
		if (clock_gettime(CLOCK_UPTIME_PRECISE, &ts) == 0)
		{
			uptime = std::chrono::milliseconds(static_cast<ulong>(ts.tv_sec) * 1000ULL + static_cast<ulong>(ts.tv_nsec) / 1000000ULL);
			return return static_cast<ulong>(uptime);
		}
		else
		{
			std::chrono::high_resolution_clock::time_point epoch;
			auto now = std::chrono::high_resolution_clock::now();
			auto elapsed = now - epoch;
			return static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
		}
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		return static_cast<ulong>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#else
	return 0;
#endif
}

std::string SystemTools::UserName()
{
	std::string ret("");

#if defined(CEX_OS_WINDOWS)

	try
	{
		TCHAR buffer[UNLEN + 1];
		DWORD buffLen = sizeof(buffer) / sizeof(TCHAR);
		GetUserName(buffer, &buffLen);
#if defined(UNICODE)
		std::wstring cpy((wchar_t*)buffer, buffLen);
		ret.assign(cpy.begin(), cpy.end());
#else
		ret.assign((char*)buffer, buffLen);
#endif
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		char buffer[LOGIN_NAME_MAX];
		getlogin_r(buffer, LOGIN_NAME_MAX);
		size_t buffLen = sizeof(buffer) / sizeof(char);
#if defined(UNICODE)
		std::wstring cpy((wchar_t*)buffer, buffLen);
		ret.assign(cpy.begin(), cpy.end());
#else
		ret.assign((char*)buffer, buffLen);
#endif
	}
	catch (std::exception&) 
	{
	}

#endif

	return ret;
}

std::string SystemTools::Version()
{
	return std::to_string(CEX_VERSION_MAJOR) + "." +
		std::to_string(CEX_VERSION_MINOR) + "." +
		std::to_string(CEX_VERSION_RELEASE) + "." +
		std::to_string(CEX_VERSION_PATCH);
}

#if defined(CEX_OS_WINDOWS)

	std::vector<PIP_ADAPTER_INFO> SystemTools::AdaptersInfo()
	{
		std::vector<PIP_ADAPTER_INFO> serInf(0);

		try
		{
			PIP_ADAPTER_INFO pAdapterInfo;
			PIP_ADAPTER_INFO pAdapter = NULL;
			ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

			pAdapterInfo = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO));

			if (pAdapterInfo == NULL)
			{
				return serInf;
			}

			if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
			{
				HeapFree(GetProcessHeap(), 0, pAdapterInfo);
				pAdapterInfo = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, ulOutBufLen);
				if (pAdapterInfo == NULL)
				{
					return serInf;
				}
			}

			if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
			{
				pAdapter = pAdapterInfo;

				while (pAdapter)
				{
					serInf.push_back(pAdapter);
					pAdapter = pAdapter->Next;
				}
			}

			if (pAdapterInfo)
			{
				HeapFree(GetProcessHeap(), 0, pAdapterInfo);
			}
		}
		catch (std::exception&) 
		{
		}

		return serInf;
	}

	uint SystemTools::CurrentThreadId()
	{
		try
		{
			return GetCurrentThreadId();
		}
		catch (std::exception&) 
		{
			return 0;
		}
	}

	POINT SystemTools::CursorPosition()
	{
		POINT pnt;

		try
		{ 
			GetCursorPos(&pnt);
		}
		catch (std::exception&)
		{
		}

		return pnt;
	}

	std::vector<HEAPENTRY32> SystemTools::HeapList()
	{
		std::vector<HEAPENTRY32> serInf(0);

		try
		{
			const size_t HEAP_LISTS_MAX = 32;
			const size_t HEAP_OBJS_PER_LIST = 128;
			HEAPLIST32 heapList;
			heapList.dwSize = sizeof(HEAPLIST32);

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, 0);

			if (Heap32ListFirst(snapshot, &heapList))
			{
				size_t heapCount = 0;

				do
				{
					if (++heapCount > HEAP_LISTS_MAX)
					{
						break;
					}

					HEAPENTRY32 heapEntry;
					heapEntry.dwSize = sizeof(HEAPENTRY32);

					if (Heap32First(&heapEntry, heapList.th32ProcessID, heapList.th32HeapID))
					{
						size_t heapObjs = 0;

						do
						{
							if (heapObjs++ > HEAP_OBJS_PER_LIST)
							{
								break;
							}

							serInf.push_back(heapEntry);
						} 
						while (Heap32Next(&heapEntry));
					}
				} 
				while (Heap32ListNext(snapshot, &heapList));
			}
		}
		catch (std::exception&) 
		{
		}

		return serInf;
	}

	std::vector<std::string> SystemTools::LogicalDrives()
	{
		std::vector<std::string> strBuf(0);

		try
		{
			TCHAR buffer[(4 * 26) + 1] = { 0 };
			GetLogicalDriveStrings(sizeof(buffer) / sizeof(TCHAR), buffer);

			for (LPTSTR lpDrive = buffer; *lpDrive != 0; lpDrive += 4)
			{
				std::wstring ws = lpDrive;
				strBuf.push_back(std::string(ws.begin(), ws.end()));
			}
		}
		catch (std::exception&)
		{
		}

		return strBuf;
	}

	MEMORYSTATUSEX SystemTools::MemoryStatus()
	{
		MEMORYSTATUSEX memInfo;

		try
		{
			memInfo.dwLength = sizeof(memInfo);
			GlobalMemoryStatusEx(&memInfo);
		}
		catch (std::exception&)
		{
		}

		return memInfo;
	}

	std::vector<MODULEENTRY32> SystemTools::ModuleEntries()
	{
		std::vector<MODULEENTRY32> serInf(0);

		try
		{
			MODULEENTRY32 info;
			info.dwSize = sizeof(MODULEENTRY32);
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

			if (Module32First(snapshot, &info))
			{
				do
				{
					serInf.push_back(info);
				} 
				while (Module32Next(snapshot, &info));
			}
		}
		catch (std::exception&)
		{
		}

		return serInf;
	}

	HMODULE SystemTools::GetCurrentModule()
	{
		HMODULE hMod = NULL;
		::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)GetCurrentModule, &hMod);

		return hMod;
	}

	std::string SystemTools::OsVersion()
	{
		// note: application must have manifest in Win10, or will return Win8 or Server2012:
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms725492(v=vs.85).aspx
	#if defined(CEX_COMPILER_MSC)
		try
		{
			if (IsWindowsServer())
			{
				if (IsWindowsVersionOrGreater(10, 0, 0))
				{
					return "Windows Server 2016";
				}
				else if (IsWindowsVersionOrGreater(6, 3, 0))
				{
					return "Windows Server 2012 R2";
				}
				else if (IsWindowsVersionOrGreater(6, 2, 0))
				{
					return "Windows Server 2012";
				}
				else if (IsWindowsVersionOrGreater(6, 1, 0))
				{
					return "Windows Server 2008 R2";
				}
				else if (IsWindowsVersionOrGreater(6, 0, 0))
				{
					return "Windows Server 2008";
				}
				else if (IsWindowsVersionOrGreater(5, 2, 0))
				{
					return "Windows Server 2003";
				}
				else if (IsWindowsVersionOrGreater(5, 0, 0))
				{
					return "Windows 2000";
				}
				else
				{
					return "Unknown";
				}
			}
			else
			{
				if (IsWindowsVersionOrGreater(10, 0, 0))
				{
					return "Windows 10";
				}
				else if (IsWindowsVersionOrGreater(6, 3, 0))
				{
					return "Windows 8.1";
				}
				else if (IsWindowsVersionOrGreater(6, 2, 0))
				{
					return "Windows 8";
				}
				else if (IsWindowsVersionOrGreater(6, 1, 0))
				{
					return "Windows 7";
				}
				else if (IsWindowsVersionOrGreater(6, 0, 0))
				{
					return "Windows Vista";
				}
				else if (IsWindowsVersionOrGreater(5, 2, 0))
				{
					return "Windows XP Professional x64 Edition";
				}
				else if (IsWindowsVersionOrGreater(5, 1, 0))
				{
					return "Windows XP";
				}
				else
				{
					return "Unknown";
				}
			}
		}
		catch (std::exception&) 
		{
			return "Windows Unknown";
		}
	#else
		return "Windows Unknown"; // only msvc supports VersionHelpers.h?
	#endif
	}

	std::vector<PROCESSENTRY32> SystemTools::ProcessEntries()
	{
		std::vector<PROCESSENTRY32> serInf(0);

		try
		{
			PROCESSENTRY32 prcInf;
			prcInf.dwSize = sizeof(PROCESSENTRY32);
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (Process32First(snapshot, &prcInf))
			{
				do
				{
					serInf.push_back(prcInf);
				} 
				while (Process32Next(snapshot, &prcInf));
			}
		}
		catch (std::exception&)
		{
		}

		return serInf;
	}

	bool SystemTools::ProtectPages(void* Pointer, size_t Length)
	{
		HANDLE hProcess = ::GetCurrentProcess();
		MEMORY_BASIC_INFORMATION mbi;
		BOOL ret;
		ULONG paold;

		if (ret = (VirtualQueryEx(hProcess, Pointer, &mbi, sizeof(mbi)) == sizeof(mbi)))
		{
			if (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				ret = VirtualProtectEx(hProcess, Pointer, Length, PAGE_GUARD | mbi.Protect, &paold);
			}
		}

		return static_cast<bool>(ret);
	}

	bool SystemTools::ReleaseProtectedPages(void* Pointer, size_t Length)
	{
		HANDLE hProcess = ::GetCurrentProcess();
		MEMORY_BASIC_INFORMATION mbi;
		BOOL ret;
		ULONG paold;

		if (ret = (VirtualQueryEx(hProcess, Pointer, &mbi, sizeof(mbi)) == sizeof(mbi)))
		{
			if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				ret = VirtualProtectEx(hProcess, Pointer, Length, PAGE_EXECUTE_READWRITE, &paold);
			}
		}

		return static_cast<bool>(ret);
	}

	std::vector<std::string> SystemTools::SystemIds()
	{
		std::vector<std::string> retArr(0);

		try
		{
			HKEY hKey;
			LSTATUS ret = 0;
			DWORD lpcchName = 0;
			TCHAR achKey[255];
			const size_t CLDLEN = 38;

			if (RegOpenKeyEx(HKEY_CLASSES_ROOT, TEXT("CLSID"), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
			{
				DWORD dwIndex = 0;
				const std::string FLT1 = "0";
				const char FLT2[] = "{}-";

				do
				{
					lpcchName = 1024;
					ret = RegEnumKeyEx(hKey, dwIndex, achKey, &lpcchName, NULL, NULL, NULL, NULL);

					if (ret == ERROR_SUCCESS)
					{
						if (lpcchName == CLDLEN)
						{
							std::wstring tmp(&achKey[0]);
							std::string cid(tmp.begin(), tmp.end());

							// filter ids with zero, done to reduce overall processing time
							// func is used only for entropy collection, rem this if you need the actual clsids
							if (cid.find(FLT1) == std::string::npos)
							{
								for (unsigned int i = 0; i < strlen(FLT2); ++i)
								{
									tmp.erase(std::remove(tmp.begin(), tmp.end(), FLT2[i]), tmp.end());
								}

								retArr.push_back(cid);
							}
						}
					}

					++dwIndex;
				} 
				while (ret == 0);

				if (hKey != NULL)
				{
					RegCloseKey(hKey);
				}
			}
		}
		catch (std::exception&) 
		{
		}

		return retArr;
	}

	SYSTEM_INFO SystemTools::SystemInfo()
	{
		SYSTEM_INFO sysInfo;

		try
		{
			GetSystemInfo(&sysInfo);
		}
		catch (std::exception&) 
		{
		}

		return sysInfo;
	}

	MIB_TCPSTATS SystemTools::TcpStatistics()
	{
		MIB_TCPSTATS tcpStats;

		try
		{
			GetTcpStatistics(&tcpStats);
		}
		catch (std::exception&) 
		{
		}

		return tcpStats;
	}

	std::vector<THREADENTRY32> SystemTools::ThreadEntries()
	{
		std::vector<THREADENTRY32> serInf(0);

		try
		{
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			THREADENTRY32 thdInf;
			thdInf.dwSize = sizeof(THREADENTRY32);

			if (Thread32First(snapshot, &thdInf))
			{
				do
				{
					serInf.push_back(thdInf);
				} 
				while (Thread32Next(snapshot, &thdInf));
			}
		}
		catch (std::exception&) 
		{
		}

		return serInf;
	}

	std::string SystemTools::UserId()
	{
		std::string sidStr = "";

		try
		{
			HANDLE hToken = NULL;

			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				// Get the size of the memory buffer needed for the SID
				DWORD dwBufferSize = 0;
				if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
				{
					// Allocate buffer for user token data
					std::vector<BYTE> buffer;
					buffer.resize(dwBufferSize);
					PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

					// Retrieve the token information in a TOKEN_USER structure
					if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize))
					{
						if (IsValidSid(pTokenUser->User.Sid))
						{
							LPTSTR pszSID = NULL;
							if (ConvertSidToStringSid(pTokenUser->User.Sid, &pszSID))
							{
								std::wstring ws((wchar_t*)pszSID);
								sidStr = std::string(ws.begin(), ws.end());
								LocalFree(pszSID);
								pszSID = NULL;
							}
						}
					}
				}
			}

			if (hToken)
			{
				CloseHandle(hToken);
				hToken = NULL;
			}
		}
		catch (std::exception&) 
		{
		}

		return sidStr;
	}

	std::vector<byte> SystemTools::UserToken()
	{
		std::vector<byte> buffer(0);

		try
		{
			HANDLE hToken = NULL;

			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				// get the size of the memory buffer needed for the SID
				DWORD dwBufferSize = 0;
				if (GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
				{
					// allocate buffer for user token data
					buffer.resize(dwBufferSize);
					// retrieve the token information in a TOKEN_USER structure
					GetTokenInformation(hToken, TokenUser, reinterpret_cast<PTOKEN_USER>(&buffer[0]), dwBufferSize, &dwBufferSize);
				}
			}

			if (hToken)
			{
				CloseHandle(hToken);
				hToken = NULL;
			}

		}
		catch (std::exception&) 
		{
		}

		return buffer;
	}

#elif defined(CEX_OS_POSIX)

	ulong SystemTools::AvailableFreeSpace()
	{
		struct statvfs stat;
		ulong ret;

		ret = 0;

		try
		{
			struct passwd *pw = getpwuid(getuid());

			if (NULL != pw && 0 == statvfs(pw->pw_dir, &stat))
			{
				ret = (uint64_t)stat.f_bavail * stat.f_frsize;
			}
		}
		catch (std::exception&)
		{
		}

		return ret;
	}

	std::string SystemTools::DeviceStatistics()
	{
		// TODO: refine this to specific statistics
		std::string stats;

		stats = std::string("");

		try
		{
			std::ifstream is("/proc/net/dev", std::ifstream::binary);
			if (is)
			{
				is.seekg(0, is.end);
				int length = is.tellg();
				is.seekg(0, is.beg);

				char* buffer = new char[length];
				is.read(buffer, length);
				is.close();

				stats = std::string(buffer);
				delete[] buffer;
			}

		}
		catch (std::exception&)
		{
		}

		return stats;
	}

	std::vector<std::string> SystemTools::GetDirectories(std::string &Path)
	{
		DIR * d = opendir(Path.c_str());
		std::vector<std::string> ret(0);

		try
		{
			if (d != NULL)
			{
				struct dirent * dir;

				while ((dir = readdir(d)) != NULL) 
				{
					if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
					{
						ret.push_back(std::string(dir->d_name));
						char dpath[255];
						GetDirectories(dpath);
					}
				}
				closedir(d);
			}
		}
		catch (std::exception&)
		{
		}

		return ret;
	}

	std::vector<std::string> SystemTools::GetFiles(std::string &Path)
	{
		std::vector<std::string> ret(0);

		try
		{
			struct dirent *entry;
			DIR *dir = opendir(Path.c_str());

			if (dir != NULL)
			{

				while ((entry = readdir(dir)) != NULL)
				{
					ret.push_back(std::string(entry->d_name));
				}

				closedir(dir);
			}

		}
		catch (std::exception&)
		{
		}

		return ret;
	}

	std::string SystemTools::GetHomeDirectory()
	{
		struct passwd pwd;
		struct passwd* result;
		const char* homedir;
		char* buf;
		size_t bufsize;
		int s;

		try
		{
			if ((homedir = getenv("HOME")) == NULL)
			{
				homedir = getpwuid(getuid())->pw_dir;
			}

			bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
			if (bufsize == -1)
			{
				bufsize = 0x4000;
			}

			buf = malloc(bufsize);
			if (buf != NULL)
			{
				s = getpwuid_r(getuid(), &pwd, buf, bufsize, &result);
			}

			char *homedir = result.pw_dir;
		}
		catch (std::exception&)
		{
		}

		return std::string(homedir);
	}

	std::string SystemTools::MemoryStatistics()
	{
		// TODO: refine this to specific statistics
		std::string stats;

		stats = std::string("");

		try
		{
			std::ifstream is("/proc/self/stat", std::ifstream::binary);

			if (is)
			{
				is.seekg(0, is.end);
				int length = is.tellg();
				is.seekg(0, is.beg);

				char* buffer = new char[length];
				is.read(buffer, length);
				is.close();

				stats = std::string(buffer);
				delete[] buffer;
			}

		}
		catch (std::exception&)
		{
		}

		return stats;
	}

	std::string SystemTools::NetworkStatistics()
	{
		// TODO: refine this to specific statistics
		std::string stats;

		stats = std::string("");

		try
		{
			std::ifstream is("/proc/net/netstat", std::ifstream::binary);
			if (is) 
			{
				is.seekg(0, is.end);
				int length = is.tellg();
				is.seekg(0, is.beg);

				char* buffer = new char[length];
				is.read(buffer, length);
				is.close();

				stats = std::string(buffer);
				delete[] buffer;
			}

		}
		catch (std::exception&)
		{
		}

		return stats;
	}

	std::vector<uint> SystemTools::ProcessEntries()
	{
		std::vector<uint> ret(0);

		try
		{
			ret.push_back(static_cast<uint>(::getpid()));
			ret.push_back(static_cast<uint>(::getppid()));
			ret.push_back(static_cast<uint>(::getuid()));
			ret.push_back(static_cast<uint>(::getgid()));
			ret.push_back(static_cast<uint>(::getpgrp()));
		}
		catch (std::exception&)
		{
		}

		return ret;
	}

	std::vector<byte> SystemTools::SystemInfo()
	{
		struct ::rusage suse;
		std::vector<byte> ret;

		try
		{
			::getrusage(RUSAGE_SELF, &suse);
			ret.resize(sizeof(suse));
			std::memcpy(ret.data(), &suse, ret.size());
		}
		catch (std::exception&)
		{
		}

		return ret;
	}

	std::string SystemTools::UserId()
	{
		std::string ret;

		ret = std::string("");

		try
		{
			ret = std::string(static_cast<uint>(::getuid()));
		}
		catch (std::exception&) 
		{
		}

		return ret;
	}

#endif

NAMESPACE_UTILITYEND