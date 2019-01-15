#include "ECP.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Utility::MemoryTools;

const std::string ECP::CLASS_NAME("ECP");

//~~~Constructor~~~//

ECP::ECP()
	:
	m_kdfGenerator(new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512)),
	m_hasTsc(Utility::SystemTools::HasRdtsc()),
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
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
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
	MemoryTools::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint ECP::NextUInt32()
{
	uint x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong ECP::NextUInt64()
{
	ulong x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

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
		throw CryptoRandomException(CLASS_NAME, std::string("Reset"), std::string(ex.what()), ErrorCodes::UnKnown);
	}
}

//~~~Private Functions~~~//

void ECP::Collect()
{
	const size_t KBLOCK = 72;
	std::vector<byte> state(0);
	std::vector<byte> buffer(KBLOCK);
	ulong ts = Utility::SystemTools::TimeStamp(m_hasTsc);

	CSP pvd;
	pvd.Generate(buffer);
	// first block is system provider
	Utility::ArrayTools::Append(buffer, state);
	// get the first timestamp
	Utility::ArrayTools::Append(ts, state);
	// collect the entropy
	Utility::ArrayTools::Append(DriveInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(MemoryInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(NetworkInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(ProcessInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(ProcessorInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(SystemInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(TimeInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);
	Utility::ArrayTools::Append(UserInfo(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc) - ts, state);

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
	Utility::ArrayTools::Append(buffer, state);

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
		Utility::ArrayTools::Remove(static_cast<byte>(0), State);
	}
}

std::vector<byte> ECP::DriveInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)
	std::vector<std::string> drives = Utility::SystemTools::LogicalDrives();

	for (size_t i = 0; i < drives.size(); ++i)
	{
		Utility::ArrayTools::Append(Utility::SystemTools::DriveSpace(drives[i]), state);
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
		MEMORYSTATUSEX info = Utility::SystemTools::MemoryStatus();

		Utility::ArrayTools::Append(info.dwMemoryLoad, state);
		Utility::ArrayTools::Append(info.ullAvailExtendedVirtual, state);
		Utility::ArrayTools::Append(info.ullAvailPageFile, state);
		Utility::ArrayTools::Append(info.ullAvailPhys, state);
		Utility::ArrayTools::Append(info.ullAvailVirtual, state);
		Utility::ArrayTools::Append(info.ullTotalPageFile, state);
		Utility::ArrayTools::Append(info.ullTotalPhys, state);
		Utility::ArrayTools::Append(info.ullTotalVirtual, state);
		Utility::ArrayTools::Append(Utility::SystemTools::MemoryPhysicalTotal(), state);
		Utility::ArrayTools::Append(Utility::SystemTools::MemoryPhysicalUsed(), state);
		Utility::ArrayTools::Append(Utility::SystemTools::MemoryVirtualTotal(), state);
		Utility::ArrayTools::Append(Utility::SystemTools::MemoryVirtualUsed(), state);
	}
	catch (std::exception&)
	{
	}


#elif defined(CEX_OS_POSIX)

	Utility::ArrayTools::Append(Utility::SystemTools::MemoryPhysicalTotal(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::MemoryPhysicalUsed(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::MemoryVirtualTotal(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::MemoryVirtualUsed(), state);

#endif

	return state;
}

std::vector<byte> ECP::NetworkInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	try
	{
		std::vector<PIP_ADAPTER_INFO> info = Utility::SystemTools::AdaptersInfo();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayTools::Append(Utility::ArrayTools::ToString(info[i]->AdapterName), state);
			Utility::ArrayTools::Append(Utility::ArrayTools::ToByteArray(info[i]->Address, 8), state);
			Utility::ArrayTools::Append(info[i]->ComboIndex, state);
			Utility::ArrayTools::Append(Utility::ArrayTools::ToString(info[i]->Description), state);
			Utility::ArrayTools::Append(info[i]->DhcpServer.IpAddress.String, state);
			Utility::ArrayTools::Append(info[i]->IpAddressList.IpAddress.String, state);
			Utility::ArrayTools::Append(info[i]->LeaseExpires, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		MIB_TCPSTATS info = Utility::SystemTools::TcpStatistics();

		Utility::ArrayTools::Append(info.dwActiveOpens, state);
		Utility::ArrayTools::Append(info.dwAttemptFails, state);
		Utility::ArrayTools::Append(info.dwCurrEstab, state);
		Utility::ArrayTools::Append(info.dwEstabResets, state);
		Utility::ArrayTools::Append(info.dwInErrs, state);
		Utility::ArrayTools::Append(info.dwInSegs, state);
		Utility::ArrayTools::Append(info.dwMaxConn, state);
		Utility::ArrayTools::Append(info.dwNumConns, state);
		Utility::ArrayTools::Append(info.dwOutRsts, state);
		Utility::ArrayTools::Append(info.dwOutSegs, state);
		Utility::ArrayTools::Append(info.dwPassiveOpens, state);
		Utility::ArrayTools::Append(info.dwRetransSegs, state);
		Utility::ArrayTools::Append(info.dwRtoAlgorithm, state);
		Utility::ArrayTools::Append(info.dwRtoMax, state);
		Utility::ArrayTools::Append(info.dwRtoMin, state);
		Utility::ArrayTools::Append(info.RtoAlgorithm, state);
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
		std::vector<PROCESSENTRY32W> info = Utility::SystemTools::ProcessEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayTools::Append(info[i].pcPriClassBase, state);
			Utility::ArrayTools::Append(info[i].szExeFile, state);
			Utility::ArrayTools::Append(info[i].th32ParentProcessID, state);
			Utility::ArrayTools::Append(info[i].th32ProcessID, state);
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
			Utility::ArrayTools::Append(info[i].GlblcntUsage, state);
			Utility::ArrayTools::Append(info[i].hModule, state);
			Utility::ArrayTools::Append(info[i].modBaseAddr, state);
			Utility::ArrayTools::Append(info[i].modBaseSize, state);
			Utility::ArrayTools::Append(info[i].ProccntUsage, state);
			Utility::ArrayTools::Append(info[i].szExePath, state);
			Utility::ArrayTools::Append(info[i].szModule, state);
			Utility::ArrayTools::Append(info[i].th32ModuleID, state);
			Utility::ArrayTools::Append(info[i].th32ProcessID, state);
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
			Utility::ArrayTools::Append(info[0].th32HeapID, state);
			Utility::ArrayTools::Append(info[0].th32ProcessID, state);
			Utility::ArrayTools::Append(info[0].hHandle, state);

			for (size_t i = 0; i < info.size(); ++i)
			{
				Utility::ArrayTools::Append(info[i].dwAddress, state);
				Utility::ArrayTools::Append(info[i].dwBlockSize, state);
				Utility::ArrayTools::Append(info[i].dwFlags, state);
				Utility::ArrayTools::Append(info[i].dwLockCount, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		Utility::ArrayTools::Append(Utility::SystemTools::ProcessEntries(), state);
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
	CpuDetect detect;

	Utility::ArrayTools::Append(detect.BusRefFrequency(), state);
	Utility::ArrayTools::Append(detect.FrequencyBase(), state);
	Utility::ArrayTools::Append(detect.FrequencyMax(), state);
	Utility::ArrayTools::Append(detect.FrequencyBase(), state);
	Utility::ArrayTools::Append(detect.SerialNumber(), state);

	return state;
}

std::vector<byte> ECP::SystemInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = Utility::SystemTools::CursorPosition();

	Utility::ArrayTools::Append(pnt.x, state);
	Utility::ArrayTools::Append(pnt.y, state);
	Utility::ArrayTools::AppendString(Utility::SystemTools::ComputerName(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::ProcessId(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::CurrentThreadId(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::OsVersion(), state);

	std::vector<std::string> clsids = Utility::SystemTools::SystemIds();
	for (size_t i = 0; i < clsids.size(); ++i)
	{
		Utility::ArrayTools::AppendString(clsids[i], state);
	}

	try
	{
		SYSTEM_INFO info = Utility::SystemTools::SystemInfo();

		Utility::ArrayTools::Append(info.dwActiveProcessorMask, state);
		Utility::ArrayTools::Append(info.dwAllocationGranularity, state);
		Utility::ArrayTools::Append(info.dwNumberOfProcessors, state);
		Utility::ArrayTools::Append(info.dwPageSize, state);
		Utility::ArrayTools::Append(info.dwProcessorType, state);
		Utility::ArrayTools::Append(info.lpMaximumApplicationAddress, state);
		Utility::ArrayTools::Append(info.lpMinimumApplicationAddress, state);
		Utility::ArrayTools::Append(info.wProcessorLevel, state);
		Utility::ArrayTools::Append(info.wProcessorRevision, state);
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		Utility::ArrayTools::AppendString(Utility::SystemTools::ComputerName(), state);
		Utility::ArrayTools::Append(Utility::SystemTools::ProcessId(), state);
		Utility::ArrayTools::Append(Utility::SystemTools::SystemInfo(), state);
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

	Utility::ArrayTools::Append(Utility::SystemTools::TimeStamp(m_hasTsc), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeCurrentNS(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::TimeSinceBoot(), state);

	return state;
}

std::vector<byte> ECP::UserInfo()
{
	std::vector<byte> state(0);

	Utility::ArrayTools::AppendString(Utility::SystemTools::UserName(), state);
	Utility::ArrayTools::AppendString(Utility::SystemTools::UserId(), state);
	Utility::ArrayTools::Append(Utility::SystemTools::UserToken(), state);

	return state;
}

NAMESPACE_PROVIDEREND
