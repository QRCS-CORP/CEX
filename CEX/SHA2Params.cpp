#include "SHA2Params.h"
#include "IntegerTools.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;

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

SHA2Params::SHA2Params(uint64_t OutputSize, uint32_t LeafSize, uint8_t Fanout)
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

SHA2Params::SHA2Params(const std::vector<uint8_t> &TreeArray)
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
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The TreeArray buffer is too int16_t!"), ErrorCodes::IllegalOperation);
	}

	m_nodeOffset = IntegerTools::LeBytesTo32(TreeArray, 0);
	m_treeVersion = IntegerTools::LeBytesTo16(TreeArray, 4);
	m_outputSize = IntegerTools::LeBytesTo64(TreeArray, 6);
	m_leafSize = IntegerTools::LeBytesTo32(TreeArray, 14);
	std::memcpy(&m_treeDepth, &TreeArray[18], 1);
	std::memcpy(&m_treeFanout, &TreeArray[19], 1);
	m_reserved = IntegerTools::LeBytesTo32(TreeArray, 20);
	m_dstCode.resize(DistributionCodeMax());
	std::memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
}

SHA2Params::SHA2Params(uint32_t NodeOffset, uint64_t OutputSize, uint16_t Version, uint32_t LeafSize, uint8_t Fanout, uint8_t TreeDepth, std::vector<uint8_t> &Info)
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

	CEXASSERT(m_treeFanout == 0 || m_treeFanout > 0 && (m_leafSize != OutputSize || m_treeFanout % 2 == 0), "The fan-out must be an even number and should align to processor cores!");
}

SHA2Params::~SHA2Params()
{
	Reset();
}

//~~~Accessors~~~//

uint8_t &SHA2Params::FanOut()
{
	return m_treeFanout;
}

uint32_t &SHA2Params::LeafSize()
{
	return m_leafSize;
}

uint32_t &SHA2Params::NodeOffset()
{
	return m_nodeOffset;
}

uint64_t &SHA2Params::OutputSize()
{
	return m_outputSize;
}

uint32_t &SHA2Params::Reserved()
{
	return m_reserved;
}

std::vector<uint8_t> &SHA2Params::DistributionCode()
{
	return m_dstCode;
}

const size_t SHA2Params::DistributionCodeMax()
{
	size_t res;

	if (m_outputSize == 32)
	{
		res = 112;
	}
	else
	{
		res = 48;
	}

	return res;
}

uint16_t &SHA2Params::Version()
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
	bool res(true);

	if (this->GetHashCode() != Input.GetHashCode())
	{
		res = false;
	}

	return res;
}

int32_t SHA2Params::GetHashCode()
{
	int32_t result = 31 * m_treeVersion;
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

std::vector<uint8_t> SHA2Params::ToBytes()
{
	std::vector<uint8_t> config(GetHeaderSize());

	IntegerTools::Le32ToBytes(m_nodeOffset, config, 0);
	IntegerTools::Le16ToBytes(m_treeVersion, config, 4);
	IntegerTools::Le64ToBytes(m_outputSize, config, 6);
	IntegerTools::Le32ToBytes(m_leafSize, config, 14);
	std::memcpy(&config[18], &m_treeDepth, 1);
	std::memcpy(&config[19], &m_treeFanout, 1);
	IntegerTools::Le32ToBytes(m_reserved, config, 20);
	std::memcpy(&config[24], &m_dstCode[0], m_dstCode.size());

	return config;
}

NAMESPACE_DIGESTEND
