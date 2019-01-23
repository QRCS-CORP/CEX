#include "ECP.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Utility::ArrayTools;
using Utility::MemoryTools;
using Utility::SystemTools;

const std::string ECP::CLASS_NAME("ECP");
const bool ECP::TIMER_HAS_TSC = SystemTools::HasRdtsc();

//~~~Constructor~~~//

ECP::ECP()
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(),
#endif
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_POSIX)
	ProviderBase(true, Providers::ECP, CLASS_NAME),
#else
	ProviderBase(false, Providers::ECP, CLASS_NAME),
#endif
	m_kdfGenerator(new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512))
{
	Reset();
}

ECP::~ECP()
{
	if (m_kdfGenerator != nullptr)
	{
		m_kdfGenerator.reset(nullptr);
	}
}

//~~~Public Functions~~~//

void ECP::Generate(std::vector<byte> &Output)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, 0, Output.size(), m_kdfGenerator);
}

void ECP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, Offset, Length, m_kdfGenerator);
}

void ECP::Generate(SecureVector<byte> &Output)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, 0, Output.size(), m_kdfGenerator);
}

void ECP::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if (!IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (!FipsTest())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	GetRandom(Output, Offset, Length, m_kdfGenerator);
}

void ECP::Reset()
{
	std::vector<byte> seed;

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
	std::vector<byte> cust(64);
	cvd.Generate(cust);
	// initialize cSHAKE-512
	m_kdfGenerator->Initialize(seed, cust);
}

//~~~Private Functions~~~//

std::vector<byte> ECP::Collect()
{
	const size_t SMPLEN = 64;
	std::vector<byte> state(0);
	std::vector<byte> buffer(SMPLEN);
	ulong ts = SystemTools::TimeStamp(TIMER_HAS_TSC);

	CSP pvd;
	pvd.Generate(buffer);
	// first block is system provider
	ArrayTools::AppendVector(buffer, state);
	// get the first timestamp
	ArrayTools::AppendValue(ts, state);
	// collect the entropy
	ArrayTools::AppendVector(DriveInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(MemoryInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(NetworkInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(ProcessInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(ProcessorInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(SystemInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(TimeInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);
	ArrayTools::AppendVector(UserInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC) - ts, state);

	// filter zeroes
	Filter(state);
	// compress to 512 bits
	state = Compress(state);

	return state;
}

std::vector<byte> ECP::Compress(std::vector<byte> &State)
{
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE512);
	std::vector<byte> seed(gen.SecurityLevel() / 8);

	gen.Initialize(State);
	gen.Generate(seed);

	return seed;
}

void ECP::Filter(std::vector<byte> &State)
{
	// filter zero bytes and shuffle
	if (State.size() != 0)
	{
		ArrayTools::Remove(static_cast<byte>(0), State);
	}
}

bool ECP::FipsTest()
{
	bool fail;

	fail = false;

#if defined(CEX_FIPS140_ENABLED)

	std::vector<byte> tmp(m_pvdSelfTest.SELFTEST_LENGTH);
	SecureVector<byte> smp(m_pvdSelfTest.SELFTEST_LENGTH);

	GetRandom(tmp, 0, tmp.size(), m_kdfGenerator);
	MemoryTools::Copy(tmp, 0, smp, 0, smp.size());
	MemoryTools::Clear(tmp, 0, tmp.size());

	if (!m_pvdSelfTest.SelfTest(smp))
	{
		fail = true;
	}

#endif

	return (fail == false);
}

std::vector<byte> ECP::DriveInfo()
{
	std::vector<byte> state(0);

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

void ECP::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IKdf> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

void ECP::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IKdf> &Generator)
{
	std::vector<byte> smp(Length);

	Generator->Generate(smp, 0, Length);
	Insert(smp, 0, Output, Offset, Length);
	Clear(smp);
}

std::vector<byte> ECP::MemoryInfo()
{
	std::vector<byte> state(0);

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

std::vector<byte> ECP::NetworkInfo()
{
	std::vector<byte> state(0);

#if defined(CEX_OS_WINDOWS)

	try
	{
		std::vector<PIP_ADAPTER_INFO> info = SystemTools::AdaptersInfo();

		for (size_t i = 0; i < info.size(); ++i)
		{
			ArrayTools::AppendString(ArrayTools::ToString(info[i]->AdapterName), state);
			ArrayTools::AppendVector(ArrayTools::ToByteArray(info[i]->Address, 8), state);
			ArrayTools::AppendValue(info[i]->ComboIndex, state);
			ArrayTools::AppendString(ArrayTools::ToString(info[i]->Description), state);
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

std::vector<byte> ECP::ProcessInfo()
{
	std::vector<byte> state(0);
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
				ArrayTools::AppendString(ArrayTools::ToString(info[i].szExeFile), state);
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
				ArrayTools::AppendString(ArrayTools::ToString(info[i].szExePath), state);
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

std::vector<byte> ECP::ProcessorInfo()
{
	std::vector<byte> state(0);
	CpuDetect detect;

	ArrayTools::AppendValue(detect.BusRefFrequency(), state);
	ArrayTools::AppendValue(detect.FrequencyBase(), state);
	ArrayTools::AppendValue(detect.FrequencyMax(), state);
	ArrayTools::AppendValue(detect.FrequencyBase(), state);
	ArrayTools::AppendString(detect.SerialNumber(), state);

	return state;
}

std::vector<byte> ECP::SystemInfo()
{
	std::vector<byte> state(0);

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

std::vector<byte> ECP::TimeInfo()
{
	std::vector<byte> state(0);

	ArrayTools::AppendValue(SystemTools::TimeStamp(TIMER_HAS_TSC), state);
	ArrayTools::AppendValue(SystemTools::TimeCurrentNS(), state);
	ArrayTools::AppendValue(SystemTools::TimeSinceBoot(), state);

	return state;
}

std::vector<byte> ECP::UserInfo()
{
	std::vector<byte> state(0);

	ArrayTools::AppendString(SystemTools::UserName(), state);
	ArrayTools::AppendString(SystemTools::UserId(), state);
	ArrayTools::AppendVector(SystemTools::UserToken(), state);

	return state;
}

NAMESPACE_PROVIDEREND
