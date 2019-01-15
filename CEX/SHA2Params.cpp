#include "SHA2Params.h"
#include "IntegerTools.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;
using Enumeration::ErrorCodes;

const std::string SHA2Params::CLASS_NAME("SHA2Params");

SHA2Params::SHA2Params()
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

SHA2Params::SHA2Params(ulong OutputSize, uint LeafSize, byte Fanout)
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
	if (OutputSize != 32 && OutputSize != 64)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The output size is invalid!"), ErrorCodes::IllegalOperation);
	}
	if (Fanout > 0 && LeafSize == 0 || Fanout == 0 && LeafSize != 0)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The fanout and leaf sizes are invalid!"), ErrorCodes::IllegalOperation);
	}

	m_dstCode.resize(DistributionCodeMax());
}

SHA2Params::SHA2Params(const std::vector<byte> &TreeArray)
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
	if (TreeArray.size() < GetHeaderSize())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The TreeArray buffer is too short!"), ErrorCodes::IllegalOperation);
	}

	m_nodeOffset = Utility::IntegerTools::LeBytesTo32(TreeArray, 0);
	m_treeVersion = Utility::IntegerTools::LeBytesTo16(TreeArray, 4);
	m_outputSize = Utility::IntegerTools::LeBytesTo64(TreeArray, 6);
	m_leafSize = Utility::IntegerTools::LeBytesTo32(TreeArray, 14);
	std::memcpy(&m_treeDepth, &TreeArray[18], 1);
	std::memcpy(&m_treeFanout, &TreeArray[19], 1);
	m_reserved = Utility::IntegerTools::LeBytesTo32(TreeArray, 20);
	m_dstCode.resize(DistributionCodeMax());
	std::memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
}

SHA2Params::SHA2Params(uint NodeOffset, ulong OutputSize, ushort Version, uint LeafSize, byte Fanout, byte TreeDepth, std::vector<byte> &Info)
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

SHA2Params::~SHA2Params()
{
	Reset();
}

//~~~Accessors~~~//

byte &SHA2Params::FanOut()
{
	return m_treeFanout;
}

uint &SHA2Params::LeafSize()
{
	return m_leafSize;
}

uint &SHA2Params::NodeOffset()
{
	return m_nodeOffset;
}

ulong &SHA2Params::OutputSize()
{
	return m_outputSize;
}

uint &SHA2Params::Reserved()
{
	return m_reserved;
}

std::vector<byte> &SHA2Params::DistributionCode()
{
	return m_dstCode;
}

const size_t SHA2Params::DistributionCodeMax()
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

ushort &SHA2Params::Version()
{
	return m_treeVersion;
}

//~~~Public Functions~~~//

SHA2Params SHA2Params::Clone()
{
	return SHA2Params(ToBytes());
}

SHA2Params* SHA2Params::DeepCopy()
{
	return new SHA2Params(ToBytes());
}

bool SHA2Params::Equals(SHA2Params &Input)
{
	if (this->GetHashCode() != Input.GetHashCode())
	{
		return false;
	}

	return true;
}

int SHA2Params::GetHashCode()
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

size_t SHA2Params::GetHeaderSize()
{
	return HDR_SIZE + DistributionCodeMax();
}

void SHA2Params::Reset()
{
	m_dstCode.clear();
	m_leafSize = 0;
	m_nodeOffset = 0;
	m_outputSize = 0;
	m_treeDepth = 0;
	m_treeFanout = 0;
	m_treeVersion = 0;
	m_reserved = 0;
}

std::vector<byte> SHA2Params::ToBytes()
{
	std::vector<byte> config(GetHeaderSize());

	Utility::IntegerTools::Le32ToBytes(m_nodeOffset, config, 0);
	Utility::IntegerTools::Le16ToBytes(m_treeVersion, config, 4);
	Utility::IntegerTools::Le64ToBytes(m_outputSize, config, 6);
	Utility::IntegerTools::Le32ToBytes(m_leafSize, config, 14);
	std::memcpy(&config[18], &m_treeDepth, 1);
	std::memcpy(&config[19], &m_treeFanout, 1);
	Utility::IntegerTools::Le32ToBytes(m_reserved, config, 20);
	std::memcpy(&config[24], &m_dstCode[0], m_dstCode.size());

	return config;
}

NAMESPACE_DIGESTEND
