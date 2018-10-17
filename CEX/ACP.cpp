#include "ACP.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CJP.h"
#include "CSP.h"
#include "RDP.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_PROVIDER

const std::string ACP::CLASS_NAME("ACP");

//~~~Constructor~~~//

ACP::ACP()
	:
	m_kdfGenerator(new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512)),
	m_hasRdrand(false),
	m_hasTsc(false),
	m_isAvailable(true)
{
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
		throw CryptoRandomException("ACP:Generate", "The output buffer is too small!");
	}
	if (!m_isAvailable)
	{
		throw CryptoRandomException("ACP:Generate", "Random provider is not available!");
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
	Utility::MemUtils::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint ACP::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong ACP::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

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
		throw CryptoRandomException("ACP:Reset", "Entropy collection has failed!", std::string(ex.what()));
	}
}

//~~~Private Functions~~~//

void ACP::Collect()
{
	const size_t KBLOCK = 72;

	std::vector<byte> state(0);
	std::vector<byte> buffer(KBLOCK);
	ulong ts = Utility::SysUtils::TimeStamp(m_hasTsc);
	// add the first timestamp
	Utility::ArrayUtils::Append(ts, state);

	// add system state
	Utility::ArrayUtils::Append(MemoryInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(ProcessInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(SystemInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(TimeInfo(), state);
	// filter zeroes
	Filter(state);

	// add rdrand
	if (m_hasRdrand)
	{
		RDP rpv;
		rpv.Generate(buffer);
		Utility::ArrayUtils::Append(buffer, state);
		Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	}

#if defined(CEX_ACP_JITTER)
	// add jitter
	if (m_hasTsc)
	{
		CJP jpv;
		jpv.Generate(buffer);
		Utility::ArrayUtils::Append(buffer, state);
		Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
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
	Utility::ArrayUtils::Append(buffer, state);

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

	Utility::ArrayUtils::Remove(static_cast<byte>(0), State);
}

std::vector<byte> ACP::MemoryInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		MEMORYSTATUSEX info = Utility::SysUtils::MemoryStatus();

		Utility::ArrayUtils::Append(info.dwMemoryLoad, state);
		Utility::ArrayUtils::Append(info.ullAvailExtendedVirtual, state);
		Utility::ArrayUtils::Append(info.ullAvailPageFile, state);
		Utility::ArrayUtils::Append(info.ullAvailPhys, state);
		Utility::ArrayUtils::Append(info.ullAvailVirtual, state);
		Utility::ArrayUtils::Append(info.ullTotalPageFile, state);
		Utility::ArrayUtils::Append(info.ullTotalPhys, state);
		Utility::ArrayUtils::Append(info.ullTotalVirtual, state);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalTotal(), state);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalUsed(), state);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualTotal(), state);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualUsed(), state);
	}
	catch (std::exception&)
	{
	}


#elif defined(CEX_OS_POSIX)

	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalTotal(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalUsed(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualTotal(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualUsed(), state);

#endif

	return state;
}

std::vector<byte> ACP::ProcessInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		std::vector<PROCESSENTRY32W> info = Utility::SysUtils::ProcessEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayUtils::Append(info[i].pcPriClassBase, state);
			Utility::ArrayUtils::Append(info[i].szExeFile, state);
			Utility::ArrayUtils::Append(info[i].th32ParentProcessID, state);
			Utility::ArrayUtils::Append(info[i].th32ProcessID, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<MODULEENTRY32W> info = Utility::SysUtils::ModuleEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayUtils::Append(info[i].GlblcntUsage, state);
			Utility::ArrayUtils::Append(info[i].hModule, state);
			Utility::ArrayUtils::Append(info[i].modBaseAddr, state);
			Utility::ArrayUtils::Append(info[i].modBaseSize, state);
			Utility::ArrayUtils::Append(info[i].ProccntUsage, state);
			Utility::ArrayUtils::Append(info[i].szExePath, state);
			Utility::ArrayUtils::Append(info[i].szModule, state);
			Utility::ArrayUtils::Append(info[i].th32ModuleID, state);
			Utility::ArrayUtils::Append(info[i].th32ProcessID, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<HEAPENTRY32> info = Utility::SysUtils::HeapList();

		if (info.size() != 0)
		{
			Utility::ArrayUtils::Append(info[0].th32HeapID, state);
			Utility::ArrayUtils::Append(info[0].th32ProcessID, state);
			Utility::ArrayUtils::Append(info[0].hHandle, state);

			for (size_t i = 0; i < info.size(); ++i)
			{
				Utility::ArrayUtils::Append(info[i].dwAddress, state);
				Utility::ArrayUtils::Append(info[i].dwBlockSize, state);
				Utility::ArrayUtils::Append(info[i].dwFlags, state);
				Utility::ArrayUtils::Append(info[i].dwLockCount, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		Utility::ArrayUtils::Append(Utility::SysUtils::ProcessEntries(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

void ACP::Scope()
{
	Common::CpuDetect detect;
	m_hasRdrand = detect.RDRAND();
	m_hasTsc = detect.RDTSCP();
}

std::vector<byte> ACP::SystemInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = Utility::SysUtils::CursorPosition();
	Utility::ArrayUtils::Append(pnt.x, state);
	Utility::ArrayUtils::Append(pnt.y, state);
	Utility::ArrayUtils::AppendString(Utility::SysUtils::ComputerName(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::CurrentThreadId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::OsVersion(), state);

	try
	{
		SYSTEM_INFO info = Utility::SysUtils::SystemInfo();

		Utility::ArrayUtils::Append(info.dwActiveProcessorMask, state);
		Utility::ArrayUtils::Append(info.dwAllocationGranularity, state);
		Utility::ArrayUtils::Append(info.dwNumberOfProcessors, state);
		Utility::ArrayUtils::Append(info.dwPageSize, state);
		Utility::ArrayUtils::Append(info.dwProcessorType, state);
		Utility::ArrayUtils::Append(info.lpMaximumApplicationAddress, state);
		Utility::ArrayUtils::Append(info.lpMinimumApplicationAddress, state);
		Utility::ArrayUtils::Append(info.wProcessorLevel, state);
		Utility::ArrayUtils::Append(info.wProcessorRevision, state);
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		Utility::ArrayUtils::AppendString(Utility::SysUtils::ComputerName(), state);
		Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), state);
		Utility::ArrayUtils::Append(Utility::SysUtils::SystemInfo(), state);
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

	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeCurrentNS(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeSinceBoot(), state);

	return state;
}

NAMESPACE_PROVIDEREND
