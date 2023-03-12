#include "BlakeParams.h"

NAMESPACE_DIGEST

using Enumeration::ErrorCodes;

const std::string BlakeParams::CLASS_NAME("BlakeParams");

BlakeParams::BlakeParams() :
	m_dstCode(0),
	m_fanOut(0),
	m_innerLen(0),
	m_keyLen(0),
	m_leafSize(0),
	m_maxDepth(0),
	m_nodeDepth(0),
	m_nodeOffset(0),
	m_outputSize(0),
	m_reserved(0)
{
}

BlakeParams::BlakeParams(uint8_t OutputSize, uint8_t TreeDepth, uint8_t Fanout, uint8_t LeafSize, uint8_t InnerLength)
	:
	m_dstCode(0),
	m_fanOut(Fanout),
	m_innerLen(InnerLength),
	m_keyLen(0),
	m_leafSize(LeafSize),
	m_maxDepth(TreeDepth),
	m_nodeDepth(0),
	m_nodeOffset(0),
	m_outputSize(OutputSize),
	m_reserved(0)
{
	if (OutputSize != 32 && OutputSize != 64)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The output size is invalid!"), ErrorCodes::IllegalOperation);
	}
	if (Fanout > 1 && InnerLength == 0 || Fanout == 1 && InnerLength != 0)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The fanout and leaf sizes are invalid!"), ErrorCodes::IllegalOperation);
	}

	m_dstCode.resize(DistributionCodeMax());
}

BlakeParams::BlakeParams(const std::vector<uint8_t> &TreeArray)
	:
	m_dstCode(0),
	m_fanOut(0),
	m_innerLen(0),
	m_keyLen(0),
	m_leafSize(0),
	m_maxDepth(0),
	m_nodeDepth(0),
	m_nodeOffset(0),
	m_outputSize(0),
	m_reserved(0)
{
	if (TreeArray.size() != 32 && TreeArray.size() != 64)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The TreeArray buffer size is invalid!"), ErrorCodes::IllegalOperation);
	}

	std::memcpy(&m_outputSize, &TreeArray[0], 1);
	std::memcpy(&m_keyLen, &TreeArray[1], 1);
	std::memcpy(&m_fanOut, &TreeArray[2], 1);
	std::memcpy(&m_maxDepth, &TreeArray[3], 1);
	m_leafSize = IntegerTools::LeBytesTo32(TreeArray, 4);
	std::memcpy(&m_nodeOffset, &TreeArray[8], 1);
	std::memcpy(&m_nodeDepth, &TreeArray[9], 1);
	std::memcpy(&m_innerLen, &TreeArray[10], 1);
	std::memcpy(&m_reserved, &TreeArray[11], 1);
	m_dstCode.resize(DistributionCodeMax());
	std::memcpy(&m_dstCode[0], &TreeArray[12], m_dstCode.size());
}

BlakeParams::BlakeParams(uint8_t OutputSize, uint8_t KeyLength, uint8_t FanOut, uint8_t MaxDepth, uint32_t LeafLength, uint8_t NodeOffset, uint8_t NodeDepth, uint8_t InnerLength, std::vector<uint8_t> &DistributionCode)
	:
	m_dstCode(DistributionCode),
	m_fanOut(FanOut),
	m_innerLen(InnerLength),
	m_keyLen(KeyLength),
	m_leafSize(LeafLength),
	m_maxDepth(MaxDepth),
	m_nodeDepth(NodeDepth),
	m_nodeOffset(NodeOffset),
	m_outputSize(OutputSize),
	m_reserved(0)
{
	m_dstCode.resize(DistributionCodeMax());
}

//~~~Accessors~~~//

uint8_t &BlakeParams::FanOut() 
{ 
	return m_fanOut;
}

uint8_t &BlakeParams::KeyLength() 
{ 
	return m_keyLen; 
}

uint8_t &BlakeParams::InnerLength()
{ 
	return m_innerLen;
}

uint32_t &BlakeParams::LeafLength() 
{ 
	return m_leafSize; 
}

uint8_t &BlakeParams::MaxDepth()
{ 
	return m_maxDepth; 
}

uint8_t &BlakeParams::NodeOffset()
{ 
	return m_nodeOffset; 
}

uint8_t &BlakeParams::NodeDepth() 
{ 
	return m_nodeDepth;
}

uint8_t &BlakeParams::OutputSize() 
{ 
	return m_outputSize; 
}

uint8_t &BlakeParams::Reserved()
{ 
	return m_reserved; 
}

std::vector<uint8_t> &BlakeParams::DistributionCode()
{ 
	return m_dstCode; 
}

const size_t BlakeParams::DistributionCodeMax()
{
	return ((m_outputSize == 32) ? 12 : 40);
}

//~~~Public Functions~~~//

BlakeParams BlakeParams::Clone()
{
	BlakeParams result(ToBytes());
	return result;
}

BlakeParams* BlakeParams::DeepCopy()
{
	return new BlakeParams(ToBytes());
}

bool BlakeParams::Equals(BlakeParams &Input)
{
	return (GetHashCode() == Input.GetHashCode());
}

int32_t BlakeParams::GetHashCode()
{
	int32_t result = 31 * m_outputSize;

	result += 31 * m_keyLen;
	result += 31 * m_fanOut;
	result += 31 * m_maxDepth;
	result += 31 * m_leafSize;
	result += 31 * m_nodeOffset;
	result += 31 * m_nodeDepth;
	result += 31 * m_innerLen;
	result += 31 * m_reserved;

	for (size_t i = 0; i < m_dstCode.size(); ++i)
	{
		result += 31 * m_dstCode[i];
	}

	return result;
}

size_t BlakeParams::GetHeaderSize()
{
	return m_outputSize;
}

void BlakeParams::Reset()
{
	m_outputSize = 0;
	m_fanOut = 0;
	m_innerLen = 0;
	m_keyLen = 0;
	m_leafSize = 0;
	m_maxDepth = 0;
	m_nodeDepth = 0;
	m_nodeOffset = 0;
	m_reserved = 0;
	std::memset(&m_dstCode[0], 0, m_dstCode.size());
}

std::vector<uint8_t> BlakeParams::ToBytes()
{
	std::vector<uint8_t> trs(GetHeaderSize());

	std::memcpy(&trs[0], &m_outputSize, 1);
	std::memcpy(&trs[1], &m_keyLen, 1);
	std::memcpy(&trs[2], &m_fanOut, 1);
	std::memcpy(&trs[3], &m_maxDepth, 1);
	IntegerTools::Le32ToBytes(m_leafSize, trs, 4);
	std::memcpy(&trs[8], &m_nodeOffset, 1);
	std::memcpy(&trs[9], &m_nodeDepth, 1);
	std::memcpy(&trs[10], &m_innerLen, 1);
	std::memcpy(&trs[11], &m_reserved, 1);
	std::memcpy(&trs[12], &m_dstCode[0], m_dstCode.size());

	return trs;
}

NAMESPACE_DIGESTEND
