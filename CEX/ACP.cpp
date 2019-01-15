#include "ACP.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CJP.h"
#include "CSP.h"
#include "RDP.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Utility::ArrayTools;
using Enumeration::ErrorCodes;

const std::string ACP::CLASS_NAME("ACP");

//~~~Constructor~~~//

ACP::ACP()
	:
	m_kdfGenerator(new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512)),
	m_hasRdrand(false),
	m_hasTsc(false),
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_POSIX)
	m_isAvailable(true)
#else
	m_isAvailable(false)
#endif
{
	if (!m_isAvailable)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("The provider is not supported on this system!"), ErrorCodes::NotFound);
	}

	Scope();
	Reset();
}

ACP::~ACP()
{
	m_hasTsc = false;
	m_hasRdrand = false;
	m_isAvailable = false;

	if (m_kdfGenerator != nullptr)
	{
		m_kdfGenerator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const Enumeration::Providers ACP::Enumeral()
{
	return Enumeration::Providers::ACP;
}

const bool ACP::IsAvailable()
{
	return m_isAvailable;
}

const std::string ACP::Name()
{
	return CLASS_NAME;
}

//~~~Public Functions~~~//

void ACP::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void ACP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	m_kdfGenerator->Generate(Output, Offset, Length);
}

std::vector<byte> ACP::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd, 0, rnd.size());

	return rnd;
}

ushort ACP::NextUInt16()
{
	ushort x = 0;
	Utility::MemoryTools::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint ACP::NextUInt32()
{
	uint x = 0;
	Utility::MemoryTools::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong ACP::NextUInt64()
{
	ulong x = 0;
	Utility::MemoryTools::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void ACP::Reset()
{
	std::vector<byte> key;

	try
	{
		// initialize the kdf
		Collect();
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string(ex.what()), ErrorCodes::UnKnown);
	}
}

//~~~Private Functions~~~//

void ACP::Collect()
{
	const size_t KBLOCK = 72;

	std::vector<byte> state(0);
	std::vector<byte> buffer(KBLOCK);
	ulong ts = Utility::SystemTools::TimeStamp(m_hasTsc);
	// add the first timestamp
	ArrayTools::Append(ts, state);

	// add system state
	ArrayTools::Append(MemoryInfo(), state);
	ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	ArrayTools::Append(ProcessInfo(), state);
	ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	ArrayTools::Append(SystemInfo(), state);
	ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	ArrayTools::Append(TimeInfo(), state);
	// filter zeroes
	Filter(state);

	// add rdrand
	if (m_hasRdrand)
	{
		RDP rpv;
		rpv.Generate(buffer);
		ArrayTools::Append(buffer, state);
		ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	}

#if defined(CEX_ACP_JITTER)
	// add jitter
	if (m_hasTsc)
	{
		CJP jpv;
		jpv.Generate(buffer);
		ArrayTools::Append(buffer, state);
		ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	}
#endif

	// last block size
	size_t padLen = ((state.size() % KBLOCK) == 0) ? KBLOCK : KBLOCK - (state.size() % KBLOCK);
	if (padLen < KBLOCK / 2)
	{
		padLen += KBLOCK;
	}

	// forward padding
	CSP cvd;
	buffer.resize(padLen);
	cvd.Generate(buffer);
	ArrayTools::Append(buffer, state);

	// initialize cSHAKE-512
	std::vector<byte> cust(72);
	cvd.Generate(cust);
	m_kdfGenerator->Initialize(state, cust);
}

void ACP::Filter(std::vector<byte> &State)
{
	if (State.size() == 0)
	{
		return;
	}

	ArrayTools::Remove(static_cast<byte>(0), State);
}

std::vector<byte> ACP::MemoryInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		MEMORYSTATUSEX info = Utility::SystemTools::MemoryStatus();

		ArrayTools::Append(info.dwMemoryLoad, state);
		ArrayTools::Append(info.ullAvailExtendedVirtual, state);
		ArrayTools::Append(info.ullAvailPageFile, state);
		ArrayTools::Append(info.ullAvailPhys, state);
		ArrayTools::Append(info.ullAvailVirtual, state);
		ArrayTools::Append(info.ullTotalPageFile, state);
		ArrayTools::Append(info.ullTotalPhys, state);
		ArrayTools::Append(info.ullTotalVirtual, state);
		ArrayTools::Append(Utility::SystemTools::MemoryPhysicalTotal(), state);
		ArrayTools::Append(Utility::SystemTools::MemoryPhysicalUsed(), state);
		ArrayTools::Append(Utility::SystemTools::MemoryVirtualTotal(), state);
		ArrayTools::Append(Utility::SystemTools::MemoryVirtualUsed(), state);
	}
	catch (std::exception&)
	{
	}


#elif defined(CEX_OS_POSIX)

	ArrayTools::Append(Utility::SystemTools::MemoryPhysicalTotal(), state);
	ArrayTools::Append(Utility::SystemTools::MemoryPhysicalUsed(), state);
	ArrayTools::Append(Utility::SystemTools::MemoryVirtualTotal(), state);
	ArrayTools::Append(Utility::SystemTools::MemoryVirtualUsed(), state);

#endif

	return state;
}

std::vector<byte> ACP::ProcessInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		std::vector<PROCESSENTRY32W> info = Utility::SystemTools::ProcessEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayTools::Append(info[i].pcPriClassBase, state);
			ArrayTools::Append(info[i].szExeFile, state);
			ArrayTools::Append(info[i].th32ParentProcessID, state);
			ArrayTools::Append(info[i].th32ProcessID, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<MODULEENTRY32W> info = Utility::SystemTools::ModuleEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayTools::Append(info[i].GlblcntUsage, state);
			ArrayTools::Append(info[i].hModule, state);
			ArrayTools::Append(info[i].modBaseAddr, state);
			ArrayTools::Append(info[i].modBaseSize, state);
			ArrayTools::Append(info[i].ProccntUsage, state);
			ArrayTools::Append(info[i].szExePath, state);
			ArrayTools::Append(info[i].szModule, state);
			ArrayTools::Append(info[i].th32ModuleID, state);
			ArrayTools::Append(info[i].th32ProcessID, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<HEAPENTRY32> info = Utility::SystemTools::HeapList();

		if (info.size() != 0)
		{
			ArrayTools::Append(info[0].th32HeapID, state);
			ArrayTools::Append(info[0].th32ProcessID, state);
			ArrayTools::Append(info[0].hHandle, state);

			for (size_t i = 0; i < info.size(); ++i)
			{
				ArrayTools::Append(info[i].dwAddress, state);
				ArrayTools::Append(info[i].dwBlockSize, state);
				ArrayTools::Append(info[i].dwFlags, state);
				ArrayTools::Append(info[i].dwLockCount, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayTools::Append(Utility::SystemTools::ProcessEntries(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

void ACP::Scope()
{
	CpuDetect detect;
	m_hasRdrand = detect.RDRAND();
	m_hasTsc = detect.RDTSCP();
}

std::vector<byte> ACP::SystemInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = Utility::SystemTools::CursorPosition();
	ArrayTools::Append(pnt.x, state);
	ArrayTools::Append(pnt.y, state);
	ArrayTools::AppendString(Utility::SystemTools::ComputerName(), state);
	ArrayTools::Append(Utility::SystemTools::ProcessId(), state);
	ArrayTools::Append(Utility::SystemTools::CurrentThreadId(), state);
	ArrayTools::Append(Utility::SystemTools::OsVersion(), state);

	try
	{
		SYSTEM_INFO info = Utility::SystemTools::SystemInfo();

		ArrayTools::Append(info.dwActiveProcessorMask, state);
		ArrayTools::Append(info.dwAllocationGranularity, state);
		ArrayTools::Append(info.dwNumberOfProcessors, state);
		ArrayTools::Append(info.dwPageSize, state);
		ArrayTools::Append(info.dwProcessorType, state);
		ArrayTools::Append(info.lpMaximumApplicationAddress, state);
		ArrayTools::Append(info.lpMinimumApplicationAddress, state);
		ArrayTools::Append(info.wProcessorLevel, state);
		ArrayTools::Append(info.wProcessorRevision, state);
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayTools::AppendString(Utility::SystemTools::ComputerName(), state);
		ArrayTools::Append(Utility::SystemTools::ProcessId(), state);
		ArrayTools::Append(Utility::SystemTools::SystemInfo(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

std::vector<byte> ACP::TimeInfo()
{
	std::vector<byte> state(0);

	ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc), state);
	ArrayTools::Append(Utility::SystemTools::TimeCurrentNS(), state);
	ArrayTools::Append(Utility::SystemTools::TimeSinceBoot(), state);

	return state;
}

NAMESPACE_PROVIDEREND
