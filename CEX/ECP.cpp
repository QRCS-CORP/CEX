#include "ECP.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_PROVIDER

const std::string ECP::CLASS_NAME("ECP");

//~~~Constructor~~~//

ECP::ECP()
	:
	m_kdfGenerator(new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512)),
	m_hasTsc(Utility::SysUtils::HasRdtsc()),
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_POSIX)
	m_isAvailable(true)
#else
	m_isAvailable(false)
#endif
{
	Reset();
}

ECP::~ECP()
{
	m_hasTsc = false;
	m_isAvailable = false;

	if (m_kdfGenerator != nullptr)
	{
		m_kdfGenerator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const Enumeration::Providers ECP::Enumeral() 
{ 
	return Enumeration::Providers::ECP; 
}

const bool ECP::IsAvailable() 
{ 
	return m_isAvailable; 
}

const std::string ECP::Name() 
{ 
	return CLASS_NAME; 
}

//~~~Public Functions~~~//

void ECP::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void ECP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	if (!m_isAvailable)
	{
		throw CryptoRandomException("ECP:Generate", "Random provider is not available!");
	}

	m_kdfGenerator->Generate(Output, Offset, Length);
}

std::vector<byte> ECP::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd, 0, rnd.size());

	return rnd;
}

ushort ECP::NextUInt16()
{
	ushort x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint ECP::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong ECP::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void ECP::Reset()
{
	std::vector<byte> key;

	try
	{
		// initialize the kdf
		Collect();
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException("ECP:Reset", "Entropy collection has failed!", std::string(ex.what()));
	}
}

//~~~Private Functions~~~//

void ECP::Collect()
{
	const size_t KBLOCK = 72;
	std::vector<byte> state(0);
	std::vector<byte> buffer(KBLOCK);
	ulong ts = Utility::SysUtils::TimeStamp(m_hasTsc);

	CSP pvd;
	pvd.Generate(buffer);
	// first block is system provider
	Utility::ArrayUtils::Append(buffer, state);
	// get the first timestamp
	Utility::ArrayUtils::Append(ts, state);
	// collect the entropy
	Utility::ArrayUtils::Append(DriveInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(MemoryInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(NetworkInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(ProcessInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(ProcessorInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(SystemInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(TimeInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayUtils::Append(UserInfo(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, state);

	// filter zeroes
	Filter(state);

	// size last block
	size_t padLen = ((state.size() % KBLOCK) == 0) ? KBLOCK : KBLOCK - (state.size() % KBLOCK);
	if (padLen < KBLOCK / 2)
	{
		padLen += KBLOCK;
	}

	// forward padding
	buffer.resize(padLen);
	pvd.Generate(buffer);
	Utility::ArrayUtils::Append(buffer, state);

	// initialize cSHAKE-512
	std::vector<byte> cust(72);
	pvd.Generate(cust);
	m_kdfGenerator->Initialize(state, cust);
}

void ECP::Filter(std::vector<byte> &State)
{
	// filter zero bytes and shuffle
	if (State.size() != 0)
	{
		Utility::ArrayUtils::Remove(static_cast<byte>(0), State);
	}
}

std::vector<byte> ECP::DriveInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	std::vector<std::string> drives = Utility::SysUtils::LogicalDrives();

	for (size_t i = 0; i < drives.size(); ++i)
	{
		Utility::ArrayUtils::Append(Utility::SysUtils::DriveSpace(drives[i]), state);
	}

#elif defined(CEX_OS_POSIX)
	// TODO
#endif

	return state;
}

std::vector<byte> ECP::MemoryInfo()
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

std::vector<byte> ECP::NetworkInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	try
	{
		std::vector<PIP_ADAPTER_INFO> info = Utility::SysUtils::AdaptersInfo();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayUtils::Append(Utility::ArrayUtils::ToString(info[i]->AdapterName), state);
			Utility::ArrayUtils::Append(Utility::ArrayUtils::ToByteArray(info[i]->Address, 8), state);
			Utility::ArrayUtils::Append(info[i]->ComboIndex, state);
			Utility::ArrayUtils::Append(Utility::ArrayUtils::ToString(info[i]->Description), state);
			Utility::ArrayUtils::Append(info[i]->DhcpServer.IpAddress.String, state);
			Utility::ArrayUtils::Append(info[i]->IpAddressList.IpAddress.String, state);
			Utility::ArrayUtils::Append(info[i]->LeaseExpires, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		MIB_TCPSTATS info = Utility::SysUtils::TcpStatistics();

		Utility::ArrayUtils::Append(info.dwActiveOpens, state);
		Utility::ArrayUtils::Append(info.dwAttemptFails, state);
		Utility::ArrayUtils::Append(info.dwCurrEstab, state);
		Utility::ArrayUtils::Append(info.dwEstabResets, state);
		Utility::ArrayUtils::Append(info.dwInErrs, state);
		Utility::ArrayUtils::Append(info.dwInSegs, state);
		Utility::ArrayUtils::Append(info.dwMaxConn, state);
		Utility::ArrayUtils::Append(info.dwNumConns, state);
		Utility::ArrayUtils::Append(info.dwOutRsts, state);
		Utility::ArrayUtils::Append(info.dwOutSegs, state);
		Utility::ArrayUtils::Append(info.dwPassiveOpens, state);
		Utility::ArrayUtils::Append(info.dwRetransSegs, state);
		Utility::ArrayUtils::Append(info.dwRtoAlgorithm, state);
		Utility::ArrayUtils::Append(info.dwRtoMax, state);
		Utility::ArrayUtils::Append(info.dwRtoMin, state);
		Utility::ArrayUtils::Append(info.RtoAlgorithm, state);
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)
	// TODO
#endif

	return state;
}

std::vector<byte> ECP::ProcessInfo()
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

std::vector<byte> ECP::ProcessorInfo()
{
	std::vector<byte> state(0);
	Common::CpuDetect detect;

	Utility::ArrayUtils::Append(detect.BusRefFrequency(), state);
	Utility::ArrayUtils::Append(detect.FrequencyBase(), state);
	Utility::ArrayUtils::Append(detect.FrequencyMax(), state);
	Utility::ArrayUtils::Append(detect.FrequencyBase(), state);
	Utility::ArrayUtils::Append(detect.SerialNumber(), state);

	return state;
}

std::vector<byte> ECP::SystemInfo()
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

	std::vector<std::string> clsids = Utility::SysUtils::SystemIds();
	for (size_t i = 0; i < clsids.size(); ++i)
	{
		Utility::ArrayUtils::AppendString(clsids[i], state);
	}

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

std::vector<byte> ECP::TimeInfo()
{
	std::vector<byte> state(0);

	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeCurrentNS(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeSinceBoot(), state);

	return state;
}

std::vector<byte> ECP::UserInfo()
{
	std::vector<byte> state(0);

	Utility::ArrayUtils::AppendString(Utility::SysUtils::UserName(), state);
	Utility::ArrayUtils::AppendString(Utility::SysUtils::UserId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::UserToken(), state);

	return state;
}

NAMESPACE_PROVIDEREND
