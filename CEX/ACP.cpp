#include "ACP.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CJP.h"
#include "CSP.h"
#include "RDP.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Tools::ArrayTools;
using Enumeration::ErrorCodes;
using Tools::MemoryTools;
using Enumeration::ProviderConvert;
using Tools::SystemTools;

const bool ACP::HAS_RDRAND = SystemTools::HasRdRand();
const bool ACP::HAS_TSC = SystemTools::HasRdtsc();

//~~~Constructor~~~//

ACP::ACP()
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(new ProviderSelfTest),
#endif
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_POSIX)
	ProviderBase(true, Providers::ACP, ProviderConvert::ToName(Providers::ACP)),
#else
	ProviderBase(false, Providers::ACP, ProviderConvert::ToName(Providers::ACP)),
#endif
	m_rngGenerator(new Kdf::SHAKE(SHAKE_MODE))
{
	Reset();
}

ACP::~ACP()
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

void ACP::Generate(std::vector<uint8_t> &Output)
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

void ACP::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
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

void ACP::Generate(SecureVector<uint8_t> &Output)
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

void ACP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
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

	Generate(Output, Offset, Length, m_rngGenerator);
}

void ACP::Reset()
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
	std::vector<uint8_t> cust(32);
	cvd.Generate(cust);
	// initialize cSHAKE-512
	m_rngGenerator->Initialize(seed, cust);
}

//~~~Private Functions~~~//

std::vector<uint8_t> ACP::Collect()
{
	const size_t SMPLEN = 32;

	std::vector<uint8_t> state(0);
	std::vector<uint8_t> buffer(SMPLEN);
	uint64_t ts;

	// add the first timestamp
	ts = SystemTools::TimeStamp(HAS_TSC);
	ArrayTools::AppendValue(ts, state);

	// add system state and mix in timer delta
	ArrayTools::AppendVector(MemoryInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(ProcessInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(SystemInfo(), state);
	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC) - ts, state);
	ArrayTools::AppendVector(TimeInfo(), state);

	// filter zeroes
	Filter(state);
	// compress to 512 bits
	state = Compress(state);

	// add rdrand block
	if (HAS_RDRAND)
	{
		RDP rpv;
		rpv.Generate(buffer);
		ArrayTools::AppendVector(buffer, state);
	}

	// add jitter block
#if defined(CEX_ACP_JITTER)
	if (HAS_TSC)
	{
		CJP jpv;
		jpv.Generate(buffer);
		ArrayTools::AppendVector(buffer, state);
	}
#endif

	return state;
}

std::vector<uint8_t> ACP::Compress(std::vector<uint8_t> &State)
{
	Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE512);
	std::vector<uint8_t> seed(gen.SecurityLevel() / 8);

	gen.Initialize(State);
	gen.Generate(seed);

	return seed;
}

void ACP::Filter(std::vector<uint8_t> &State)
{
	if (State.size() != 0)
	{
		ArrayTools::Remove(static_cast<uint8_t>(0x00), State);
	}
}

bool ACP::FipsTest()
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

void ACP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length, std::unique_ptr<SHAKE> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

std::vector<uint8_t> ACP::MemoryInfo()
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

std::vector<uint8_t> ACP::ProcessInfo()
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
				size_t slen = ArrayTools::StringSize(info[i].szExeFile, sizeof(info[i].szExeFile));
				std::string buf = ArrayTools::ToString(info[i].szExeFile, slen, true);
				ArrayTools::AppendString(buf, state);
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
				size_t slen = ArrayTools::StringSize(info[i].szExePath, sizeof(info[i].szExePath));
				std::string buf = ArrayTools::ToString(info[i].szExePath, slen, true);
				ArrayTools::AppendString(buf, state);
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

std::vector<uint8_t> ACP::SystemInfo()
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

std::vector<uint8_t> ACP::TimeInfo()
{
	std::vector<uint8_t> state(0);

	ArrayTools::AppendValue(SystemTools::TimeStamp(HAS_TSC), state);
	ArrayTools::AppendValue(SystemTools::TimeCurrentNS(), state);
	ArrayTools::AppendValue(SystemTools::TimeSinceBoot(), state);

	return state;
}

NAMESPACE_PROVIDEREND
