#include "ECP.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "Keccak512.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_PROVIDER

const std::string ECP::CLASS_NAME("ECP");

//~~~Properties~~~//

const Enumeration::Providers ECP::Enumeral() 
{ 
	return Enumeration::Providers::ECP; 
}

const bool ECP::IsAvailable() 
{ 
	return m_isAvailable; 
}

const std::string &ECP::Name() 
{ 
	return CLASS_NAME; 
}

//~~~Constructor~~~//

ECP::ECP()
	:
	m_cipherMode(0),
	m_hasTsc(Utility::SysUtils::HasRdtsc()),
	m_isAvailable(false)
{
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_POSIX)
	m_isAvailable = true;
#endif

	Reset();
}

ECP::~ECP()
{
	Destroy();
}

//~~~Public Functions~~~//

void ECP::Destroy()
{
	if (m_cipherMode != 0)
		delete m_cipherMode;
}

void ECP::GetBytes(std::vector<byte> &Output)
{
	GetBytes(Output, 0, Output.size());
}

void ECP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (!m_isAvailable)
		throw CryptoRandomException("ECP:Engine", "Random provider is not available!");
	if (Offset + Length > Output.size())
		throw CryptoRandomException("ECP:GetBytes", "The array is too small to fulfill this request!");

	std::vector<byte> data(Length);
	m_cipherMode->Transform(data, 0, Output, Offset, Length);
}

std::vector<byte> ECP::GetBytes(size_t Length)
{
	std::vector<byte> data(Length);
	GetBytes(data);

	return data;
}

uint ECP::Next()
{
	uint rndNum;
	std::vector<byte> rndData(sizeof(uint));
	GetBytes(rndData);
	Utility::MemUtils::Copy<byte, uint>(rndData, 0, rndNum, sizeof(uint));

	return rndNum;
}

void ECP::Reset()
{
	std::vector<byte> key;

	try
	{
		// collect entropy, filter, and compress
		key = Collect();
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException("ECP:Reset", "Entropy collection has failed!", std::string(ex.what()));
	}

	// initialize the cipher
	m_cipherMode = Helper::CipherModeFromName::GetInstance(Enumeration::CipherModes::CTR, Enumeration::BlockCiphers::AHX);
	// get the iv and hkdf info from system provider
	std::vector<Key::Symmetric::SymmetricKeySize> keySizes = m_cipherMode->LegalKeySizes();
	std::vector<byte> info(keySizes[0].InfoSize());
	std::vector<byte> iv(16);
	CSP pvd;
	pvd.GetBytes(info);
	pvd.GetBytes(iv);
	Key::Symmetric::SymmetricKey kp(key, iv, info);
	m_cipherMode->Initialize(true, kp);
}

//~~~Private Functions~~~//

std::vector<byte> ECP::Collect()
{
	const size_t KBLK = 136;

	std::vector<byte> sysState(0);
	std::vector<byte> rndBuffer(KBLK);
	ulong ts = Utility::SysUtils::TimeStamp(m_hasTsc);

	CSP pvd;
	pvd.GetBytes(rndBuffer);
	// first block is system provider
	Utility::ArrayUtils::Append(rndBuffer, sysState);
	// get the first timestamp
	Utility::ArrayUtils::Append(ts, sysState);
	// collect the entropy
	Utility::ArrayUtils::Append(DriveInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(MemoryInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(NetworkInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(ProcessInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(ProcessorInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(SystemInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(TimeInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);
	Utility::ArrayUtils::Append(UserInfo(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc) - ts, sysState);

	// last block size
	size_t padLen = ((sysState.size() % KBLK) == 0) ? KBLK : KBLK - (sysState.size() % KBLK);
	if (padLen < KBLK / 2)
		padLen += KBLK;

	// forward padding
	rndBuffer.resize(padLen);
	pvd.GetBytes(rndBuffer);
	Utility::ArrayUtils::Append(rndBuffer, sysState);

	// filter zeroes and shuffle
	Filter(sysState);

	return Compress(sysState);
}

std::vector<byte> ECP::Compress(std::vector<byte> &State)
{
	Digest::Keccak512 dgt;
	std::vector<byte> outKey(dgt.DigestSize());
	dgt.Compute(State, outKey);

	return outKey;
}

void ECP::Filter(std::vector<byte> &State)
{
	// filter zero bytes and shuffle
	if (State.size() == 0)
		return;

	Utility::ArrayUtils::Remove((byte)0, State);
}

std::vector<byte> ECP::DriveInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)
	std::vector<std::string> drives = Utility::SysUtils::LogicalDrives();

	for (size_t i = 0; i < drives.size(); ++i)
		Utility::ArrayUtils::Append(Utility::SysUtils::DriveSpace(drives[i]), sysState);

#elif defined(CEX_OS_POSIX)
	// TODO
#endif

	return sysState;
}

std::vector<byte> ECP::MemoryInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		MEMORYSTATUSEX info = Utility::SysUtils::MemoryStatus();

		Utility::ArrayUtils::Append(info.dwMemoryLoad, sysState);
		Utility::ArrayUtils::Append(info.ullAvailExtendedVirtual, sysState);
		Utility::ArrayUtils::Append(info.ullAvailPageFile, sysState);
		Utility::ArrayUtils::Append(info.ullAvailPhys, sysState);
		Utility::ArrayUtils::Append(info.ullAvailVirtual, sysState);
		Utility::ArrayUtils::Append(info.ullTotalPageFile, sysState);
		Utility::ArrayUtils::Append(info.ullTotalPhys, sysState);
		Utility::ArrayUtils::Append(info.ullTotalVirtual, sysState);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalTotal(), sysState);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalUsed(), sysState);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualTotal(), sysState);
		Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualUsed(), sysState);
	}
	catch (...)
	{
	}


#elif defined(CEX_OS_POSIX)

	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalTotal(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryPhysicalUsed(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualTotal(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::MemoryVirtualUsed(), sysState);

#endif

	return sysState;
}

std::vector<byte> ECP::NetworkInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)

	try
	{
		std::vector<PIP_ADAPTER_INFO> info = Utility::SysUtils::AdaptersInfo();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayUtils::Append(Utility::ArrayUtils::ToString(info[i]->AdapterName), sysState);
			Utility::ArrayUtils::Append(Utility::ArrayUtils::ToByteArray(info[i]->Address, 8), sysState);
			Utility::ArrayUtils::Append(info[i]->ComboIndex, sysState);
			Utility::ArrayUtils::Append(Utility::ArrayUtils::ToString(info[i]->Description), sysState);
			Utility::ArrayUtils::Append(info[i]->DhcpServer.IpAddress.String, sysState);
			Utility::ArrayUtils::Append(info[i]->IpAddressList.IpAddress.String, sysState);
			Utility::ArrayUtils::Append(info[i]->LeaseExpires, sysState);
		}
	}
	catch (...)
	{
	}

	try
	{
		MIB_TCPSTATS info = Utility::SysUtils::TcpStatistics();

		Utility::ArrayUtils::Append(info.dwActiveOpens, sysState);
		Utility::ArrayUtils::Append(info.dwAttemptFails, sysState);
		Utility::ArrayUtils::Append(info.dwCurrEstab, sysState);
		Utility::ArrayUtils::Append(info.dwEstabResets, sysState);
		Utility::ArrayUtils::Append(info.dwInErrs, sysState);
		Utility::ArrayUtils::Append(info.dwInSegs, sysState);
		Utility::ArrayUtils::Append(info.dwMaxConn, sysState);
		Utility::ArrayUtils::Append(info.dwNumConns, sysState);
		Utility::ArrayUtils::Append(info.dwOutRsts, sysState);
		Utility::ArrayUtils::Append(info.dwOutSegs, sysState);
		Utility::ArrayUtils::Append(info.dwPassiveOpens, sysState);
		Utility::ArrayUtils::Append(info.dwRetransSegs, sysState);
		Utility::ArrayUtils::Append(info.dwRtoAlgorithm, sysState);
		Utility::ArrayUtils::Append(info.dwRtoMax, sysState);
		Utility::ArrayUtils::Append(info.dwRtoMin, sysState);
		Utility::ArrayUtils::Append(info.RtoAlgorithm, sysState);
	}
	catch (...)
	{
	}

#elif defined(CEX_OS_POSIX)
	// TODO
#endif

	return sysState;
}

std::vector<byte> ECP::ProcessInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)
	try
	{
		std::vector<PROCESSENTRY32W> info = Utility::SysUtils::ProcessEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayUtils::Append(info[i].pcPriClassBase, sysState);
			Utility::ArrayUtils::Append(info[i].szExeFile, sysState);
			Utility::ArrayUtils::Append(info[i].th32ParentProcessID, sysState);
			Utility::ArrayUtils::Append(info[i].th32ProcessID, sysState);
		}
	}
	catch (...)
	{
	}

	try
	{
		std::vector<MODULEENTRY32W> info = Utility::SysUtils::ModuleEntries();

		for (size_t i = 0; i < info.size(); ++i)
		{
			Utility::ArrayUtils::Append(info[i].GlblcntUsage, sysState);
			Utility::ArrayUtils::Append(info[i].hModule, sysState);
			Utility::ArrayUtils::Append(info[i].modBaseAddr, sysState);
			Utility::ArrayUtils::Append(info[i].modBaseSize, sysState);
			Utility::ArrayUtils::Append(info[i].ProccntUsage, sysState);
			Utility::ArrayUtils::Append(info[i].szExePath, sysState);
			Utility::ArrayUtils::Append(info[i].szModule, sysState);
			Utility::ArrayUtils::Append(info[i].th32ModuleID, sysState);
			Utility::ArrayUtils::Append(info[i].th32ProcessID, sysState);
		}
	}
	catch (...)
	{
	}

	try
	{
		std::vector<HEAPENTRY32> info = Utility::SysUtils::HeapList();

		if (info.size() != 0)
		{
			Utility::ArrayUtils::Append(info[0].th32HeapID, sysState);
			Utility::ArrayUtils::Append(info[0].th32ProcessID, sysState);
			Utility::ArrayUtils::Append(info[0].hHandle, sysState);

			for (size_t i = 0; i < info.size(); ++i)
			{
				Utility::ArrayUtils::Append(info[i].dwAddress, sysState);
				Utility::ArrayUtils::Append(info[i].dwBlockSize, sysState);
				Utility::ArrayUtils::Append(info[i].dwFlags, sysState);
				Utility::ArrayUtils::Append(info[i].dwLockCount, sysState);
			}
		}
	}
	catch (...)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		Utility::ArrayUtils::Append(Utility::SysUtils::ProcessEntries(), sysState);
	}
	catch (...)
	{
	}

#endif

	return sysState;
}

std::vector<byte> ECP::ProcessorInfo()
{
	std::vector<byte> sysState(0);
	Common::CpuDetect detect;

	Utility::ArrayUtils::Append(detect.BusSpeed(), sysState);
	Utility::ArrayUtils::Append(detect.FrequencyBase(), sysState);
	Utility::ArrayUtils::Append(detect.FrequencyMax(), sysState);
	Utility::ArrayUtils::Append(detect.FrequencyBase(), sysState);
	Utility::ArrayUtils::Append(detect.SerialNumber(), sysState);

	return sysState;
}

std::vector<byte> ECP::SystemInfo()
{
	std::vector<byte> sysState(0);

#if defined(CEX_OS_WINDOWS)

	POINT pnt = Utility::SysUtils::CursorPosition();

	Utility::ArrayUtils::Append(pnt.x, sysState);
	Utility::ArrayUtils::Append(pnt.y, sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::ComputerName(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::CurrentThreadId(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::OsVersion(), sysState);

	std::vector<std::string> clsids = Utility::SysUtils::SystemIds();
	for (size_t i = 0; i < clsids.size(); ++i)
		Utility::ArrayUtils::Append(clsids[i], sysState);

	try
	{
		SYSTEM_INFO info = Utility::SysUtils::SystemInfo();

		Utility::ArrayUtils::Append(info.dwActiveProcessorMask, sysState);
		Utility::ArrayUtils::Append(info.dwAllocationGranularity, sysState);
		Utility::ArrayUtils::Append(info.dwNumberOfProcessors, sysState);
		Utility::ArrayUtils::Append(info.dwPageSize, sysState);
		Utility::ArrayUtils::Append(info.dwProcessorType, sysState);
		Utility::ArrayUtils::Append(info.lpMaximumApplicationAddress, sysState);
		Utility::ArrayUtils::Append(info.lpMinimumApplicationAddress, sysState);
		Utility::ArrayUtils::Append(info.wProcessorLevel, sysState);
		Utility::ArrayUtils::Append(info.wProcessorRevision, sysState);
	}
	catch (...)
	{
	}

#elif defined(CEX_OS_POSIX)

	try
	{
		Utility::ArrayUtils::Append(Utility::SysUtils::ComputerName(), sysState);
		Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), sysState);
		Utility::ArrayUtils::Append(Utility::SysUtils::SystemInfo(), sysState);
	}
	catch (...)
	{
	}

#endif

	return sysState;
}

std::vector<byte> ECP::TimeInfo()
{
	std::vector<byte> sysState(0);

	Utility::ArrayUtils::Append(Utility::SysUtils::TimeStamp(m_hasTsc), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeCurrentNS(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::TimeSinceBoot(), sysState);

	return sysState;
}

std::vector<byte> ECP::UserInfo()
{
	std::vector<byte> sysState(0);

	Utility::ArrayUtils::Append(Utility::SysUtils::UserName(), sysState);
	Utility::ArrayUtils::Append(Utility::SysUtils::UserId(), sysState);

	return sysState;
}

NAMESPACE_PROVIDEREND