#include "KeccakParams.h"
#include "CryptoDigestException.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

KeccakParams::KeccakParams()
	:
	m_nodeOffset(0),
	m_treeVersion(1),
	m_outputSize(0),
	m_leafSize(0),
	m_treeDepth(0),
	m_treeFanout(0),
	m_reserved(0),
	m_dstCode(0)
{
}

KeccakParams::KeccakParams(ulong OutputSize, uint LeafSize, byte Fanout)
	:
	m_nodeOffset(0),
	m_treeVersion(1),
	m_outputSize(OutputSize),
	m_leafSize(LeafSize),
	m_treeDepth(0),
	m_treeFanout(Fanout),
	m_reserved(0),
	m_dstCode(0)
{
	if (OutputSize != 32 && OutputSize != 64 && OutputSize != 128)
	{
		throw Exception::CryptoDigestException("KeccakParams:Ctor", "The output size is invalid!");
	}
	if (Fanout > 0 && LeafSize == 0 || Fanout == 0 && LeafSize != 0)
	{
		throw Exception::CryptoDigestException("KeccakParams:Ctor", "The fanout and leaf sizes are invalid!");
	}

	m_dstCode.resize(DistributionCodeMax());
}

KeccakParams::KeccakParams(const std::vector<byte> &TreeArray)
	:
	m_nodeOffset(0),
	m_treeVersion(0),
	m_outputSize(0),
	m_leafSize(0),
	m_treeDepth(0),
	m_treeFanout(0),
	m_reserved(0),
	m_dstCode(0)
{
	CexAssert(TreeArray.size() >= GetHeaderSize(), "The TreeArray buffer is too short!");

	m_nodeOffset = Utility::IntUtils::LeBytesTo32(TreeArray, 0);
	m_treeVersion = Utility::IntUtils::LeBytesTo16(TreeArray, 4);
	m_outputSize = Utility::IntUtils::LeBytesTo64(TreeArray, 6);
	m_leafSize = Utility::IntUtils::LeBytesTo32(TreeArray, 14);
	std::memcpy(&m_treeDepth, &TreeArray[18], 1);
	std::memcpy(&m_treeFanout, &TreeArray[19], 1);
	m_reserved = Utility::IntUtils::LeBytesTo32(TreeArray, 20);
	m_dstCode.resize(DistributionCodeMax());
	std::memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
}

KeccakParams::KeccakParams(uint NodeOffset, ulong OutputSize, ushort Version, uint LeafSize, byte Fanout, byte TreeDepth, std::vector<byte> &Info)
	:
	m_nodeOffset(NodeOffset),
	m_treeVersion(Version),
	m_outputSize(OutputSize),
	m_leafSize(LeafSize),
	m_treeDepth(TreeDepth),
	m_treeFanout(Fanout),
	m_reserved(0),
	m_dstCode(Info)
{
	m_dstCode.resize(DistributionCodeMax());

	CexAssert(m_treeFanout == 0 || m_treeFanout > 0 && (m_leafSize != OutputSize || m_treeFanout % 2 == 0), "The fan-out must be an even number and should align to processor cores!");
}

//~~~Accessors~~~//

std::vector<byte> &KeccakParams::DistributionCode()
{
	return m_dstCode;
}

const size_t KeccakParams::DistributionCodeMax()
{
	if (m_outputSize == 32)
	{
		return 112;
	}
	else
	{
		return 48;
	}
}

byte &KeccakParams::FanOut()
{
	return m_treeFanout;
}

uint &KeccakParams::LeafSize()
{
	return m_leafSize;
}

uint &KeccakParams::NodeOffset()
{
	return m_nodeOffset;
}

ulong &KeccakParams::OutputSize()
{
	return m_outputSize;
}

uint &KeccakParams::Reserved()
{
	return m_reserved;
}

ushort &KeccakParams::Version()
{
	return m_treeVersion;
}

//~~~Public Functions~~~//

KeccakParams KeccakParams::Clone()
{
	return KeccakParams(ToBytes());
}

KeccakParams* KeccakParams::DeepCopy()
{
	return new KeccakParams(ToBytes());
}

bool KeccakParams::Equals(KeccakParams &Input)
{
	if (this->GetHashCode() != Input.GetHashCode())
	{
		return false;
	}

	return true;
}

int KeccakParams::GetHashCode()
{
	int result = 31 * m_treeVersion;
	result += 31 * m_nodeOffset;
	result += 31 * m_leafSize;
	result += 31 * m_outputSize;
	result += 31 * m_treeDepth;
	result += 31 * m_treeFanout;
	result += 31 * m_reserved;

	for (size_t i = 0; i < m_dstCode.size(); ++i)
	{
		result += 31 * m_dstCode[i];
	}

	return result;
}

size_t KeccakParams::GetHeaderSize()
{
	return HDR_SIZE + DistributionCodeMax();
}

void KeccakParams::Reset()
{
	m_nodeOffset = 0;
	m_treeVersion = 0;
	m_outputSize = 0;
	m_leafSize = 0;
	m_treeDepth = 0;
	m_treeFanout = 0;
	m_reserved = 0;
	m_dstCode.clear();
}

std::vector<byte> KeccakParams::ToBytes()
{
	std::vector<byte> config(GetHeaderSize());

	Utility::IntUtils::Le32ToBytes(m_nodeOffset, config, 0);
	Utility::IntUtils::Le16ToBytes(m_treeVersion, config, 4);
	Utility::IntUtils::Le64ToBytes(m_outputSize, config, 6);
	Utility::IntUtils::Le32ToBytes(m_leafSize, config, 14);
	std::memcpy(&config[18], &m_treeDepth, 1);
	std::memcpy(&config[19], &m_treeFanout, 1);
	Utility::IntUtils::Le32ToBytes(m_reserved, config, 20);
	std::memcpy(&config[24], &m_dstCode[0], m_dstCode.size());

	return config;
}

NAMESPACE_DIGESTEND