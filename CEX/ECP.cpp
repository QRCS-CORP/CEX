#include "ECP.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Tools::ArrayTools;
using Tools::MemoryTools;
using Enumeration::ProviderConvert;
using Tools::SystemTools;

const bool ECP::HAS_TSC = SystemTools::HasRdtsc();

//~~~Constructor~~~//

ECP::ECP()
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(new ProviderSelfTest),
#endif
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_POSIX)
	ProviderBase(true, Providers::ECP, ProviderConvert::ToName(Providers::ECP)),
#else
	ProviderBase(false, Providers::ECP, ProviderConvert::ToName(Providers::ECP)),
#endif
	m_rngGenerator(new Kdf::SHAKE(SHAKE_MODE))
{
	Reset();
}

ECP::~ECP()
{
	if (m_pvdSelfTest != nullptr)
	{
		m_pvdSelfTest.reset(nullptr);
	}

	if (m_rngGenerator != nullptr)
	{
		m_rngGenerator.reset(nullptr);
	}
}

//~~~Public Functions~~~//

void ECP::Generate(std::vector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	SecureVector<uint8_t> tmp(Output.size());

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, 0, tmp.size());
}

void ECP::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	SecureVector<uint8_t> tmp(Length);

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, Offset, tmp.size());
}

void ECP::Generate(SecureVector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(Output, 0, Output.size(), m_rngGenerator);
}

void ECP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(Output, Offset, Length, m_rngGenerator);
}

void ECP::Reset()
{
	std::vector<uint8_t> seed;

	try
	{
		// collect samples from various entropy sources to create the seed
		seed = Collect();

		if (seed.size() == 0)
		{
			throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random generators seed collection has failed!"), ErrorCodes::InvalidState);
		}
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	CSP cvd;
	// use the system provider to create the customization string
	std::vector<uint8_t> cust(64);
	cvd.Generate(cust);
	// initialize cSHAKE-512
	m_rngGenerator->Initialize(seed, cust);
}

//~~~Private Functions~~~//

std::vector<uint8_t> ECP::Collect()
{
	const size_t SMPLEN = 64;
	std::vector<uint8_t> state(0);
	std::vector<uint8_t> buffer(SMPLEN);
	uint64_t ts = SystemTools::TimeStamp(HAS_TSC);

	CSP pvd;
	pvd.Generate(buffer);
	// first block is system provider
	ArrayTools::AppendVector(buffer, state);
	// get the first timestamp
	ArrayTools::AppendValue(ts, state);
	// collect the entropy
	ArrayTools::AppendVector(DriveInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(MemoryInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(NetworkInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(ProcessInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(ProcessorInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(SystemInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(TimeInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(UserInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);

	// filter zeroes
	Filter(state);
	// compress to 512 bits
	state = Compress(state);

	return state;
}

std::vector<uint8_t> ECP::Compress(std::vector<uint8_t> &State)
{
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE512);
	std::vector<uint8_t> seed(gen.SecurityLevel() / 8);

	gen.Initialize(State);
	gen.Generate(seed);

	return seed;
}

void ECP::Filter(std::vector<uint8_t> &State)
{
	// filter zero bytes and shuffle
	if (State.size() != 0)
	{
		ArrayTools::Remove(static_cast<uint8_t>(0), State);
	}
}

bool ECP::FipsTest()
{
	bool fail;

	fail = false;

#if defined(CEX_FIPS140_ENABLED)

	SecureVector<uint8_t> smp(m_pvdSelfTest->SELFTEST_LENGTH);

	Generate(smp, 0, smp.size(), m_rngGenerator);

	if (!m_pvdSelfTest->SelfTest(smp))
	{
		fail = true;
	}

#endif

	return (fail == false);
}

std::vector<uint8_t> ECP::DriveInfo()
{
	std::vector<uint8_t> state(0);

#if defined(CEX_OS_WINDOWS)
	std::vector<std::string> drives = SystemTools::LogicalDrives();

	for (size_t i = 0; i < drives.size(); ++i)
	{
		ArrayTools::AppendVector(SystemTools::DriveSpace(drives[i]), state);
	}

#elif defined(CEX_OS_POSIX)

	ArrayTools::AppendValue(SystemTools::AvailableFreeSpace(), state);

#endif

	return state;
}

void ECP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length, std::unique_ptr<SHAKE> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

std::vector<uint8_t> ECP::MemoryInfo()
{
	std::vector<uint8_t> state(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		MEMORYSTATUSEX info = SystemTools::MemoryStatus();
		ArrayTools::AppendObject(&info, state, sizeof(info));

		ArrayTools::AppendValue(SystemTools::MemoryPhysicalTotal(), state);
		ArrayTools::AppendValue(SystemTools::MemoryPhysicalUsed(), state);
		ArrayTools::AppendValue(SystemTools::MemoryVirtualTotal(), state);
		ArrayTools::AppendValue(SystemTools::MemoryVirtualUsed(), state);
	}
	catch (std::exception&)
	{
	}


#elif defined(CEX_OS_POSIX)

	ArrayTools::AppendValue(SystemTools::MemoryPhysicalTotal(), state);
	ArrayTools::AppendValue(SystemTools::MemoryPhysicalUsed(), state);
	ArrayTools::AppendValue(SystemTools::MemoryVirtualTotal(), state);
	ArrayTools::AppendValue(SystemTools::MemoryVirtualUsed(), state);

#endif

	return state;
}

std::vector<uint8_t> ECP::NetworkInfo()
{
	std::vector<uint8_t> state(0);

#if defined(CEX_OS_WINDOWS)

	try
	{
		std::vector<PIP_ADAPTER_INFO> info = SystemTools::AdaptersInfo();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayTools::AppendString(ArrayTools::ToString(info[i]->AdapterName, ArrayTools::StringSize(info[i]->AdapterName, sizeof(info[i]->AdapterName))), state);
			ArrayTools::AppendVector(ArrayTools::ToByteArray(info[i]->Address, 8), state);
			ArrayTools::AppendValue(info[i]->ComboIndex, state);
			ArrayTools::AppendString(ArrayTools::ToString(info[i]->Description, ArrayTools::StringSize(info[i]->Description, sizeof(info[i]->Description))), state);
			ArrayTools::AppendValue(info[i]->DhcpServer.IpAddress.String, state);
			ArrayTools::AppendValue(info[i]->IpAddressList.IpAddress.String, state);
			ArrayTools::AppendValue(info[i]->LeaseExpires, state);
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		MIB_TCPSTATS info = SystemTools::TcpStatistics();
		ArrayTools::AppendObject(&info, state, sizeof(info));
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)
	
	ArrayTools::AppendVector(SystemTools::NetworkStatistics(), state);

#endif

	return state;
}

std::vector<uint8_t> ECP::ProcessInfo()
{
	std::vector<uint8_t> state(0);
	size_t i;

#if defined(CEX_OS_WINDOWS)
	try
	{
		std::vector<PROCESSENTRY32W> info = SystemTools::ProcessEntries();

		if (info.size() != 0)
		{
			for (i = 0; i < info.size(); ++i)
			{
				ArrayTools::AppendValue(info[i].pcPriClassBase, state);
				ArrayTools::AppendString(ArrayTools::ToString(info[i].szExeFile, ArrayTools::StringSize(info[i].szExeFile, sizeof(info[i].szExeFile)), true), state);
				ArrayTools::AppendValue(info[i].th32ParentProcessID, state);
				ArrayTools::AppendValue(info[i].th32ProcessID, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<MODULEENTRY32W> info = SystemTools::ModuleEntries();

		if (info.size() != 0)
		{
			for (i = 0; i < info.size(); ++i)
			{
				ArrayTools::AppendValue(info[i].GlblcntUsage, state);
				ArrayTools::AppendValue(info[i].hModule, state);
				ArrayTools::AppendValue(info[i].modBaseAddr, state);
				ArrayTools::AppendValue(info[i].modBaseSize, state);
				ArrayTools::AppendValue(info[i].ProccntUsage, state);
				ArrayTools::AppendString(ArrayTools::ToString(info[i].szExePath, ArrayTools::StringSize(info[i].szExePath, sizeof(info[i].szExePath)), true), state);
				ArrayTools::AppendValue(info[i].szModule, state);
				ArrayTools::AppendValue(info[i].th32ModuleID, state);
				ArrayTools::AppendValue(info[i].th32ProcessID, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

	try
	{
		std::vector<HEAPENTRY32> info = SystemTools::HeapList();

		if (info.size() != 0)
		{
			ArrayTools::AppendValue(info[0].th32HeapID, state);
			ArrayTools::AppendValue(info[0].th32ProcessID, state);
			ArrayTools::AppendValue(info[0].hHandle, state);

			for (size_t i = 0; i < info.size(); ++i)
			{
				ArrayTools::AppendValue(info[i].dwAddress, state);
				ArrayTools::AppendValue(info[i].dwBlockSize, state);
				ArrayTools::AppendValue(info[i].dwFlags, state);
				ArrayTools::AppendValue(info[i].dwLockCount, state);
			}
		}
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayTools::AppendVector(SystemTools::ProcessEntries(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

std::vector<uint8_t> ECP::ProcessorInfo()
{
	std::vector<uint8_t> state(0);
	CpuDetect dtc;

	ArrayTools::AppendValue(dtc.BusRefFrequency(), state);
	ArrayTools::AppendValue(dtc.FrequencyBase(), state);
	ArrayTools::AppendValue(dtc.FrequencyMax(), state);
	ArrayTools::AppendValue(dtc.FrequencyBase(), state);
	ArrayTools::AppendString(dtc.SerialNumber(), state);

	return state;
}

std::vector<uint8_t> ECP::SystemInfo()
{
	std::vector<uint8_t> state(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = SystemTools::CursorPosition();
	ArrayTools::AppendObject(&pnt, state, sizeof(pnt));

	ArrayTools::AppendString(SystemTools::ComputerName(), state);
	ArrayTools::AppendValue(SystemTools::ProcessId(), state);
	ArrayTools::AppendValue(SystemTools::CurrentThreadId(), state);
	ArrayTools::AppendString(SystemTools::OsVersion(), state);

	try
	{
		SYSTEM_INFO info = SystemTools::SystemInfo();
		ArrayTools::AppendObject(&info, state, sizeof(info));
	}
	catch (std::exception&)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		ArrayTools::AppendString(SystemTools::ComputerName(), state);
		ArrayTools::AppendValue(SystemTools::ProcessId(), state);
		ArrayTools::AppendString(SystemTools::DeviceStatistics(), state);
	}
	catch (std::exception&)
	{
	}

#endif

	return state;
}

std::vector<uint8_t> ECP::TimeInfo()
{
	std::vector<uint8_t> state(0);

	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC), state);
	ArrayTools::AppendValue(SystemTools::TimeCurrentNS(), state);
	ArrayTools::AppendValue(SystemTools::TimeSinceBoot(), state);

	return state;
}

std::vector<uint8_t> ECP::UserInfo()
{
	std::vector<uint8_t> state(0);

	ArrayTools::AppendString(SystemTools::UserName(), state);
	ArrayTools::AppendString(SystemTools::UserId(), state);
	ArrayTools::AppendVector(SystemTools::UserToken(), state);

	return state;
}

NAMESPACE_PROVIDEREND
