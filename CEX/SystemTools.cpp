#include "SystemTools.h"

NAMESPACE_TOOLS

bool SystemTools::TMR_RDTSC = false;
bool SystemTools::HAS_RDRAND = false;

std::string SystemTools::ComputerName()
{
	std::string res("");

#if defined(CEX_OS_WINDOWS)
	try
	{
		TCHAR buf[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD buffLen = sizeof(buf) / sizeof(TCHAR);
		GetComputerName(buf, &buffLen);

#if defined(UNICODE)
		std::wstring cpy(reinterpret_cast<wchar_t*>(buf), buffLen);
		res.assign(cpy.begin(), cpy.end());
#else
		res.assign((char*)buf, buffLen);
#endif
	}
	catch (std::exception&) 
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		char buf[HOST_NAME_MAX];
		gethostname(buf, HOST_NAME_MAX);

#if defined(UNICODE)
		std::wstring cpy((wchar_t*)buf, buffLen);
		res.assign(cpy.begin(), cpy.end());
#else
		res.assign((char*)buf, buffLen);
#endif
	}
	catch (std::exception&) 
	{
	}

#endif
	
	return res;
}

std::vector<uint64_t> SystemTools::DriveSpace(const std::string &Drive)
{
#if defined(CEX_OS_WINDOWS)

	std::vector<uint64_t> rlen(0);
	ULARGE_INTEGER freebt;
	ULARGE_INTEGER totalbt;
	ULARGE_INTEGER availbt;
	std::wstring ws;

	try
	{
		ws.assign(Drive.begin(), Drive.end());
		UINT drvType = GetDriveType(ws.c_str());

		if (drvType == 3 || drvType == 6)
		{
			if (GetDiskFreeSpaceEx(ws.c_str(), &freebt, &totalbt, &availbt))
			{
				rlen.push_back(static_cast<uint64_t>(freebt.QuadPart));
				rlen.push_back(static_cast<uint64_t>(totalbt.QuadPart));
				rlen.push_back(static_cast<uint64_t>(availbt.QuadPart));
			}
		}
	}
	catch (std::exception&) 
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		struct statvfs fsinfo;
		statvfs("/", &fsinfo);

		rlen.push_back(static_cast<uint64_t>(fsinfo.f_frsize * fsinfo.f_blocks));
		rlen.push_back(static_cast<uint64_t>(fsinfo.f_bsize * fsinfo.f_bfree));
	}
	catch (std::exception&) 
	{
	}

#endif

	return rlen;
}

uint64_t SystemTools::GetRdtscFrequency()
{
	uint64_t res;

	if (HasRdtsc())
	{
		uint64_t first = __rdtsc();
		Sleep(10);
		uint64_t second = __rdtsc();

		res = (second - first) * 100;
	}
	else
	{
		res = 0;
	}

	return res;
}

bool SystemTools::HasRdRand()
{
	if (!HAS_RDRAND)
	{
#if defined(CEX_HAS_AVX)
		CpuDetect dtc;
		HAS_RDRAND = dtc.RDRAND();
#else
		HAS_RDRAND = false;
#endif
	}

	return HAS_RDRAND;
}

bool SystemTools::HasRdtsc()
{
	if (!TMR_RDTSC)
	{
#if defined(CEX_HAS_AVX)
		CpuDetect dtc;
		TMR_RDTSC = dtc.RDTSCP();
#else
		TMR_RDTSC = false;
#endif
	}

	return TMR_RDTSC;
}

uint64_t SystemTools::MemoryPhysicalTotal()
{
	uint64_t res;

	res = 0;

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

	res = static_cast<uint64_t>(memInfo.ullTotalPhys);

#elif defined(CEX_OS_POSIX)

	int64_t int64_t totalPhysMem = 0;

	try
	{
		struct sysinfo memInfo;
		sysinfo(&memInfo);
		totalPhysMem = memInfo.totalram;
		totalPhysMem *= memInfo.mem_unit;

		res = static_cast<uint64_t>(totalPhysMem);
	}
	catch (std::exception&) 
	{
	}
#endif

	return res;
}

uint64_t SystemTools::MemoryPhysicalUsed()
{
	uint64_t res;

	res = 0;

#if defined(CEX_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);

		res = static_cast<uint64_t>(memInfo.ullTotalPhys - memInfo.ullAvailPhys);
	}
	catch (std::exception&) 
	{
	}

#elif defined(CEX_OS_POSIX)

	int64_t int64_t physMemUsed = 0;

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

	res = static_cast<uint64_t>(physMemUsed);

#endif

	return res;
}

uint64_t SystemTools::MemoryVirtualTotal()
{
	uint64_t res;

	res = 0;

#if defined(CEX_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);

		res = static_cast<uint64_t>(memInfo.ullTotalPageFile);
	}
	catch (std::exception&) 
	{
	}

#elif defined(CEX_OS_POSIX)

	struct sysinfo memInfo;
	int64_t int64_t totalVirtualMem = 0;

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

	res = static_cast<uint64_t>(totalVirtualMem);

#endif

	return res;
}

uint64_t SystemTools::MemoryVirtualUsed()
{
	uint64_t res;

	res = 0;

#if defined(CEX_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	try
	{
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);

		res = static_cast<uint64_t>(memInfo.ullTotalPageFile - memInfo.ullAvailPageFile);
	}
	catch (std::exception&) 
	{
	}

#elif defined(CEX_OS_POSIX)

	int64_t int64_t vused;

	vused = 0;

	try
	{
		struct sysinfo memInfo;
		sysinfo(&memInfo);
		vused = memInfo.totalram - memInfo.freeram;
		vused += memInfo.totalswap - memInfo.freeswap;
		vused *= memInfo.mem_unit;
	}
	catch (std::exception&)
	{
	}

	res = static_cast<uint64_t>(vused);

#endif

	return res;
}

std::string SystemTools::OsName()
{
	std::string res("");

#ifdef _WIN32
	res = "Windows 32-bit";
#elif _WIN64
	res = "Windows 64-bit";
#elif __unix || __unix__
	res = "Unix";
#elif __APPLE__ || __MACH__
	res = "Mac OSX";
#elif __linux__
	res = "Linux";
#elif __FreeBSD__
	res = "FreeBSD";
#else
	res = "Other";
#endif

	return res;
}

uint32_t SystemTools::ProcessId()
{
	uint32_t res;

	res = 0;

#if defined(CEX_OS_WINDOWS)
	try 
	{
		res = static_cast<uint32_t>(GetCurrentProcessId());
	}
	catch (std::exception&)
	{
	}
#else
	try
	{
		res = static_cast<uint32_t>(::getpid());
	}
	catch (std::exception&)
	{
	}
#endif

	return res;
}

uint64_t SystemTools::TimeCurrentNS()
{
	return static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
}

uint64_t SystemTools::TimeStamp(bool HasRdtsc)
{
	uint64_t rtme;

	rtme = 0;

	// http://nadeausoftware.com/articles/2012/04/c_c_tip_how_measure_elapsed_real_time_benchmarking
#if defined(CEX_OS_WINDOWS)
	try
	{
		if (HasRdtsc)
		{
			// use tsc if available
			rtme = static_cast<uint64_t>(__rdtsc());
		}
		else
		{
			int64_t ctr1 = 0;
			int64_t freq = 0;

			if (QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&ctr1)) != 0)
			{
				QueryPerformanceFrequency(reinterpret_cast<LARGE_INTEGER*>(&freq));
				// return microseconds to milliseconds
				if (freq > 0)
				{
					rtme = static_cast<uint64_t>(ctr1 * 1000ULL / freq);
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
				rtme = static_cast<uint64_t>(li.QuadPart);
				// Convert from file time to UNIX epoch time.
				rtme -= 116444736000000000LL; 
				// From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals
				rtme /= 10000;
			}
		}
	}
	catch (std::exception&) 
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		rtme = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif (defined(CEX_OS_HPUX) || defined(CEX_OS_SUNUX)) && (defined(__SVR4) || defined(__svr4__))

	// HP-UX, Solaris
	try
	{
		rtme = static_cast<uint64_t>(gethrtime());
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		rtme = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif defined(CEX_OS_APPLE)
	// OSX
	try
	{
		static double timeConvert = 0.0;
		mach_timebase_info_data_t timeBase;
		(void)mach_timebase_info(&timeBase);
		timeConvert = timeBase.numer / timeBase.denom;
		rtme = static_cast<uint64_t>(mach_absolute_time() * timeConvert);
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		rtme = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
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
				rtme = static_cast<uint64_t>(ts.tv_sec + ts.tv_nsec);
			}
		}
		catch (std::exception&)
		{
			std::chrono::high_resolution_clock::time_point epoch;
			auto now = std::chrono::high_resolution_clock::now();
			auto elapsed = now - epoch;

			rtme = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
		}
	}

#endif

	// AIX, BSD, Cygwin, HP-UX, Linux, OSX, POSIX, Solaris
	try
	{
		struct timeval tm;
		gettimeofday(&tm, NULL);

		rtme = static_cast<uint64_t>(tm.tv_sec + tm.tv_usec);
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;

		rtme = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#else
	std::chrono::high_resolution_clock::time_point epoch;
	auto now = std::chrono::high_resolution_clock::now();
	auto elapsed = now - epoch;

	rtme = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
#endif

	return rtme;
}

uint64_t SystemTools::TimeSinceBoot()
{
	uint64_t res;

	res = 0;

	// http://stackoverflow.com/questions/30095439/how-do-i-get-system-up-time-in-milliseconds-in-c
#if defined(CEX_OS_WINDOWS)

	try
	{
		res = std::chrono::milliseconds(GetTickCount64()).count();
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;

		res = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		std::chrono::milliseconds uptime(0U);
		struct timespec ts;
		if (clock_gettime(CLOCK_UPTIME_PRECISE, &ts) == 0)
		{
			uptime = std::chrono::milliseconds(static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL);
			res = return static_cast<uint64_t>(uptime);
		}
		else
		{
			std::chrono::high_resolution_clock::time_point epoch;
			auto now = std::chrono::high_resolution_clock::now();
			auto elapsed = now - epoch;
			res = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
		}
	}
	catch (std::exception&)
	{
		std::chrono::high_resolution_clock::time_point epoch;
		auto now = std::chrono::high_resolution_clock::now();
		auto elapsed = now - epoch;
		res = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
	}
#endif

	return res;
}

std::string SystemTools::UserName()
{
	std::string res("");

#if defined(CEX_OS_WINDOWS)

	try
	{
		TCHAR buf[UNLEN + 1];
		DWORD buffLen = sizeof(buf) / sizeof(TCHAR);
		GetUserName(buf, &buffLen);
#if defined(UNICODE)
		std::wstring cpy(reinterpret_cast<wchar_t*>(buf), buffLen);
		res.assign(cpy.begin(), cpy.end());
#else
		res.assign((char*)buf, buffLen);
#endif
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		char buf[LOGIN_NAME_MAX];
		getlogin_r(buf, LOGIN_NAME_MAX);
		size_t buffLen = sizeof(buf) / sizeof(char);
#if defined(UNICODE)
		std::wstring cpy((wchar_t*)buf, buffLen);
		res.assign(cpy.begin(), cpy.end());
#else
		res.assign((char*)buf, buffLen);
#endif
	}
	catch (std::exception&) 
	{
	}

#endif

	return res;
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
		std::vector<PIP_ADAPTER_INFO> sinfo(0);

		try
		{
			PIP_ADAPTER_INFO pAdapterInfo;
			PIP_ADAPTER_INFO pAdapter = NULL;
			ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

			pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO)));

			if (pAdapterInfo != NULL)
			{
				if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
				{
					HeapFree(GetProcessHeap(), 0, pAdapterInfo);
					pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(HeapAlloc(GetProcessHeap(), 0, ulOutBufLen));
				}

				if (pAdapterInfo == NULL)
				{
					if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
					{
						pAdapter = pAdapterInfo;

						while (pAdapter)
						{
							sinfo.push_back(pAdapter);
							pAdapter = pAdapter->Next;
						}
					}

					if (pAdapterInfo)
					{
						HeapFree(GetProcessHeap(), 0, pAdapterInfo);
					}
				}
			}
		}
		catch (std::exception&) 
		{
		}

		return sinfo;
	}

	uint32_t SystemTools::CurrentThreadId()
	{
		uint32_t res;

		res = 0;

		try
		{
			res = GetCurrentThreadId();
		}
		catch (std::exception&) 
		{
		}

		return res;
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
		std::vector<HEAPENTRY32> sinfo(0);

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

							sinfo.push_back(heapEntry);
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

		return sinfo;
	}

	std::vector<std::string> SystemTools::LogicalDrives()
	{
		std::vector<std::string> strBuf(0);

		try
		{
			TCHAR buf[(4 * 26) + 1] = { 0 };
			GetLogicalDriveStrings(sizeof(buf) / sizeof(TCHAR), buf);

			for (LPTSTR lpDrive = buf; *lpDrive != 0; lpDrive += 4)
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
		std::vector<MODULEENTRY32> sinfo(0);

		try
		{
			MODULEENTRY32 info;
			info.dwSize = sizeof(MODULEENTRY32);
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

			if (Module32First(snapshot, &info))
			{
				do
				{
					sinfo.push_back(info);
				} 
				while (Module32Next(snapshot, &info));
			}
		}
		catch (std::exception&)
		{
		}

		return sinfo;
	}

	HMODULE SystemTools::GetCurrentModule()
	{
		HMODULE hMod = NULL;
		::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCTSTR>(GetCurrentModule), &hMod);

		return hMod;
	}

	std::string SystemTools::OsVersion()
	{
		std::string res("");

		// note: application must have manifest in Win10, or will return Win8 or Server2012:
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms725492(v=vs.85).aspx
	#if defined(CEX_COMPILER_MSC)
		try
		{
			if (IsWindowsServer())
			{
				if (IsWindowsVersionOrGreater(10, 0, 0))
				{
					res = "Windows Server 2016";
				}
				else if (IsWindowsVersionOrGreater(6, 3, 0))
				{
					res = "Windows Server 2012 R2";
				}
				else if (IsWindowsVersionOrGreater(6, 2, 0))
				{
					res = "Windows Server 2012";
				}
				else if (IsWindowsVersionOrGreater(6, 1, 0))
				{
					res = "Windows Server 2008 R2";
				}
				else if (IsWindowsVersionOrGreater(6, 0, 0))
				{
					res = "Windows Server 2008";
				}
				else if (IsWindowsVersionOrGreater(5, 2, 0))
				{
					res = "Windows Server 2003";
				}
				else if (IsWindowsVersionOrGreater(5, 0, 0))
				{
					res = "Windows 2000";
				}
				else
				{
					res = "Unknown";
				}
			}
			else
			{
				if (IsWindowsVersionOrGreater(10, 0, 0))
				{
					res = "Windows 10";
				}
				else if (IsWindowsVersionOrGreater(6, 3, 0))
				{
					res = "Windows 8.1";
				}
				else if (IsWindowsVersionOrGreater(6, 2, 0))
				{
					res = "Windows 8";
				}
				else if (IsWindowsVersionOrGreater(6, 1, 0))
				{
					res = "Windows 7";
				}
				else if (IsWindowsVersionOrGreater(6, 0, 0))
				{
					res = "Windows Vista";
				}
				else if (IsWindowsVersionOrGreater(5, 2, 0))
				{
					res = "Windows XP Professional x64 Edition";
				}
				else if (IsWindowsVersionOrGreater(5, 1, 0))
				{
					res = "Windows XP";
				}
				else
				{
					res = "Unknown";
				}
			}
		}
		catch (std::exception&) 
		{
			res = "Windows Unknown";
		}
	#else
		res = "Windows Unknown"; // only msvc supports VersionHelpers.h?
	#endif

		return res;
	}

	std::vector<PROCESSENTRY32> SystemTools::ProcessEntries()
	{
		std::vector<PROCESSENTRY32> sinfo(0);

		try
		{
			PROCESSENTRY32 prcInf;
			prcInf.dwSize = sizeof(PROCESSENTRY32);
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (Process32First(snapshot, &prcInf))
			{
				do
				{
					sinfo.push_back(prcInf);
				} 
				while (Process32Next(snapshot, &prcInf));
			}
		}
		catch (std::exception&)
		{
		}

		return sinfo;
	}

	bool SystemTools::ProtectPages(void* Pointer, size_t Length)
	{
		HANDLE hproc;
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T res;
		ULONG paold;

		hproc = ::GetCurrentProcess();
		res = VirtualQueryEx(hproc, Pointer, &mbi, sizeof(mbi));

		if (res == sizeof(mbi))
		{
			if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0)
			{
				res = VirtualProtectEx(hproc, Pointer, Length, PAGE_GUARD | mbi.Protect, &paold);
			}
		}

		return static_cast<bool>(res);
	}

	bool SystemTools::ReleaseProtectedPages(void* Pointer, size_t Length)
	{
		HANDLE hproc;
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T res;
		ULONG paold;

		hproc = ::GetCurrentProcess();
		res = VirtualQueryEx(hproc, Pointer, &mbi, sizeof(mbi));

		if (res == sizeof(mbi))
		{
			if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				res = VirtualProtectEx(hproc, Pointer, Length, PAGE_EXECUTE_READWRITE, &paold);
			}
		}

		return static_cast<bool>(res);
	}

	std::vector<std::string> SystemTools::SystemIds()
	{
		std::vector<std::string> rids(0);

		try
		{
			const size_t CLDLEN = 38;
			HKEY hKey;
			LSTATUS res = 0;
			DWORD lpcchName = 0;
			TCHAR achKey[255];
			size_t i;

			if (RegOpenKeyEx(HKEY_CLASSES_ROOT, TEXT("CLSID"), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
			{
				DWORD dwIndex = 0;
				const std::string FLT1 = "0";
				const char FLT2[] = "{}-";
				const size_t SLEN = 3;

				do
				{
					lpcchName = 1024;
					res = RegEnumKeyEx(hKey, dwIndex, achKey, &lpcchName, NULL, NULL, NULL, NULL);

					if (res == ERROR_SUCCESS)
					{
						if (lpcchName == CLDLEN)
						{
							std::wstring tmp(&achKey[0]);
							std::string cid(tmp.begin(), tmp.end());

							// filter ids with zero, done to reduce overall processing time
							// func is used only for entropy collection, rem this if you need the actual clsids
							if (cid.find(FLT1) == std::string::npos)
							{
								for (i = 0; i < SLEN; ++i)
								{
									tmp.erase(std::remove(tmp.begin(), tmp.end(), FLT2[i]), tmp.end());
								}

								rids.push_back(cid);
							}
						}
					}

					++dwIndex;
				} 
				while (res == 0);

				if (hKey != NULL)
				{
					RegCloseKey(hKey);
				}
			}
		}
		catch (std::exception&) 
		{
		}

		return rids;
	}

	SYSTEM_INFO SystemTools::SystemInfo()
	{
		SYSTEM_INFO sinfo;

		try
		{
			GetSystemInfo(&sinfo);
		}
		catch (std::exception&) 
		{
		}

		return sinfo;
	}

	MIB_TCPSTATS SystemTools::TcpStatistics()
	{
		MIB_TCPSTATS tcpstats;

		try
		{
			GetTcpStatistics(&tcpstats);
		}
		catch (std::exception&) 
		{
		}

		return tcpstats;
	}

	std::vector<THREADENTRY32> SystemTools::ThreadEntries()
	{
		std::vector<THREADENTRY32> sinfo(0);

		try
		{
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			THREADENTRY32 thdinf;
			thdinf.dwSize = sizeof(THREADENTRY32);

			if (Thread32First(snapshot, &thdinf))
			{
				do
				{
					sinfo.push_back(thdinf);
				} 
				while (Thread32Next(snapshot, &thdinf));
			}
		}
		catch (std::exception&) 
		{
		}

		return sinfo;
	}

	std::string SystemTools::UserId()
	{
		std::string sids("");

		try
		{
			HANDLE hToken = NULL;

			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				// Get the size of the memory buf needed for the SID
				DWORD dwBufferSize = 0;
				if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
				{
					// Allocate buf for user token data
					std::vector<BYTE> buf;
					buf.resize(dwBufferSize);
					PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buf[0]);

					// Retrieve the token information in a TOKEN_USER structure
					if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize))
					{
						if (IsValidSid(pTokenUser->User.Sid))
						{
							LPTSTR pszSID = NULL;
							if (ConvertSidToStringSid(pTokenUser->User.Sid, &pszSID))
							{
								std::wstring ws(reinterpret_cast<wchar_t*>(pszSID));
								sids = std::string(ws.begin(), ws.end());
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

		return sids;
	}

	std::vector<uint8_t> SystemTools::UserToken()
	{
		std::vector<uint8_t> buf(0);

		try
		{
			HANDLE hToken = NULL;

			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				// get the size of the memory buf needed for the SID
				DWORD dwBufferSize = 0;
				if (GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
				{
					// allocate buf for user token data
					buf.resize(dwBufferSize);
					// retrieve the token information in a TOKEN_USER structure
					GetTokenInformation(hToken, TokenUser, reinterpret_cast<PTOKEN_USER>(&buf[0]), dwBufferSize, &dwBufferSize);
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

		return buf;
	}

#elif defined(CEX_OS_POSIX)

	uint64_t SystemTools::AvailableFreeSpace()
	{
		struct statvfs stat;
		uint64_t res;

		res = 0;

		try
		{
			struct passwd *pw = getpwuid(getuid());

			if (NULL != pw && 0 == statvfs(pw->pw_dir, &stat))
			{
				res = (uint64_t)stat.f_bavail * stat.f_frsize;
			}
		}
		catch (std::exception&)
		{
		}

		return res;
	}

	std::string SystemTools::DeviceStatistics()
	{
		// TODO: refine this to specific statistics
		std::string stats("");

		try
		{
			std::ifstream is("/proc/net/dev", std::ifstream::binary);
			if (is)
			{
				is.seekg(0, is.end);
				int32_t length = is.tellg();
				is.seekg(0, is.beg);

				char* buf = new char[length];
				is.read(buf, length);
				is.close();

				stats = std::string(buf);
				delete[] buf;
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
		std::vector<std::string> res(0);

		try
		{
			if (d != NULL)
			{
				struct dirent * dir;

				while ((dir = readdir(d)) != NULL) 
				{
					if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
					{
						res.push_back(std::string(dir->d_name));
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

		return res;
	}

	std::vector<std::string> SystemTools::GetFiles(std::string &Path)
	{
		std::vector<std::string> res(0);

		try
		{
			struct dirent *entry;
			DIR *dir = opendir(Path.c_str());

			if (dir != NULL)
			{

				while ((entry = readdir(dir)) != NULL)
				{
					res.push_back(std::string(entry->d_name));
				}

				closedir(dir);
			}

		}
		catch (std::exception&)
		{
		}

		return res;
	}

	std::string SystemTools::GetHomeDirectory()
	{
		struct passwd pwd;
		struct passwd* result;
		const char* homedir;
		char* buf;
		size_t buflen;
		int32_t s;

		try
		{
			if ((homedir = getenv("HOME")) == NULL)
			{
				homedir = getpwuid(getuid())->pw_dir;
			}

			buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
			if (buflen == -1)
			{
				buflen = 0x4000;
			}

			buf = malloc(buflen);
			if (buf != NULL)
			{
				s = getpwuid_r(getuid(), &pwd, buf, buflen, &result);
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
		std::string stats("");

		try
		{
			std::ifstream is("/proc/self/stat", std::ifstream::binary);

			if (is)
			{
				is.seekg(0, is.end);
				int32_t length = is.tellg();
				is.seekg(0, is.beg);

				char* buf = new char[length];
				is.read(buf, length);
				is.close();

				stats = std::string(buf);
				delete[] buf;
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
		std::string stats("");

		try
		{
			std::ifstream is("/proc/net/netstat", std::ifstream::binary);
			if (is) 
			{
				is.seekg(0, is.end);
				int32_t length = is.tellg();
				is.seekg(0, is.beg);

				char* buf = new char[length];
				is.read(buf, length);
				is.close();

				stats = std::string(buf);
				delete[] buf;
			}

		}
		catch (std::exception&)
		{
		}

		return stats;
	}

	std::vector<uint32_t> SystemTools::ProcessEntries()
	{
		std::vector<uint32_t> res(0);

		try
		{
			res.push_back(static_cast<uint32_t>(::getpid()));
			res.push_back(static_cast<uint32_t>(::getppid()));
			res.push_back(static_cast<uint32_t>(::getuid()));
			res.push_back(static_cast<uint32_t>(::getgid()));
			res.push_back(static_cast<uint32_t>(::getpgrp()));
		}
		catch (std::exception&)
		{
		}

		return res;
	}

	std::vector<uint8_t> SystemTools::SystemInfo()
	{
		struct ::rusage suse;
		std::vector<uint8_t> res;

		try
		{
			::getrusage(RUSAGE_SELF, &suse);
			res.resize(sizeof(suse));
			std::memcpy(res.data(), &suse, res.size());
		}
		catch (std::exception&)
		{
		}

		return res;
	}

	std::string SystemTools::UserId()
	{
		std::string res("");

		try
		{
			res = std::string(static_cast<uint32_t>(::getuid()));
		}
		catch (std::exception&) 
		{
		}

		return res;
	}

#endif

NAMESPACE_TOOLSEND
