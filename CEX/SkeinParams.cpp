#include "SkeinParams.h"
#include "IntegerTools.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;

const std::string SkeinParams::CLASS_NAME("SkeinParams");

SkeinParams::SkeinParams()
	:
	m_treeSchema{ 83, 72, 65, 51 },
	m_treeVersion(1),
	m_reserved1(0),
	m_outputSize(0),
	m_leafSize(0),
	m_treeDepth(0),
	m_treeFanout(0),
	m_reserved2(0),
	m_reserved3(0),
	m_dstCode(0)
{
}

SkeinParams::SkeinParams(uint64_t OutputSize, uint8_t LeafSize, uint8_t Fanout)
	:
	m_treeSchema{ 83, 72, 65, 51 },
	m_treeVersion(1),
	m_reserved1(0),
	m_outputSize(OutputSize),
	m_leafSize(LeafSize),
	m_treeDepth(0),
	m_treeFanout(Fanout),
	m_reserved2(0),
	m_reserved3(0),
	m_dstCode(0)
{
	CEXASSERT(OutputSize == 32 || OutputSize == 64 || OutputSize == 128, "The output size is invalid!");
	CEXASSERT(Fanout > 0 && LeafSize > 0 || Fanout == 0 && LeafSize == 0, "The fanout and leaf sizes are invalid!");

	if (OutputSize != 32 && OutputSize != 64 && OutputSize != 128)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The output size is invalid!"), ErrorCodes::IllegalOperation);
	}
	if (Fanout > 0 && LeafSize == 0 || Fanout == 0 && LeafSize != 0)
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The fanout and leaf sizes are invalid!"), ErrorCodes::IllegalOperation);
	}

	m_dstCode.resize(DistributionCodeMax());
}

SkeinParams::SkeinParams(const std::vector<uint8_t> &TreeArray)
	:
	m_treeSchema(4),
	m_treeVersion(0),
	m_reserved1(0),
	m_outputSize(0),
	m_leafSize(0),
	m_treeDepth(0),
	m_treeFanout(0),
	m_reserved2(0),
	m_reserved3(0),
	m_dstCode(0)
{
	if (TreeArray.size() < GetHeaderSize())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The TreeArray buffer size is invalid!"), ErrorCodes::IllegalOperation);
	}

	std::memcpy(&m_treeSchema[0], &TreeArray[0], 4);
	m_treeVersion = IntegerTools::LeBytesTo16(TreeArray, 4);
	m_reserved1 = IntegerTools::LeBytesTo16(TreeArray, 6);
	m_outputSize = IntegerTools::LeBytesTo64(TreeArray, 8);
	std::memcpy(&m_leafSize, &TreeArray[16], 1);
	std::memcpy(&m_treeDepth, &TreeArray[17], 1);
	std::memcpy(&m_treeFanout, &TreeArray[18], 1);
	std::memcpy(&m_reserved2, &TreeArray[19], 1);
	m_reserved3 = IntegerTools::LeBytesTo32(TreeArray, 20);
	m_dstCode.resize(DistributionCodeMax());
	std::memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
}

SkeinParams::SkeinParams(const std::vector<uint8_t> &Schema, uint64_t OutputSize, uint16_t Version, uint32_t LeafSize, uint8_t Fanout, uint8_t TreeDepth, std::vector<uint8_t> &DistributionCode)
	:
	m_treeSchema(Schema),
	m_treeVersion(Version),
	m_reserved1(0),
	m_outputSize(OutputSize),
	m_leafSize(LeafSize),
	m_treeDepth(TreeDepth),
	m_treeFanout(Fanout),
	m_reserved2(0),
	m_reserved3(0),
	m_dstCode(DistributionCode)
{
	m_dstCode.resize(DistributionCodeMax());

	CEXASSERT(Schema.size() == 4, "The Schema must be 4 bytes in length!");
	CEXASSERT(TreeDepth == 0, "The tree depth is always 0!");
	CEXASSERT(Version == 1, "The version number must be 1!");
	CEXASSERT(m_treeFanout == 0 || m_treeFanout > 0 && (m_leafSize != OutputSize || m_treeFanout % 2 == 0), "The fan-out must be an even number and should align to processor cores!");
}

//~~~Accessors~~~//

uint8_t &SkeinParams::FanOut()
{
	return m_treeFanout;
}

uint8_t &SkeinParams::LeafSize()
{
	return m_leafSize;
}

uint64_t &SkeinParams::OutputSize() 
{ 
	return m_outputSize;
}

uint16_t &SkeinParams::Reserved1() 
{ 
	return m_reserved1;
}

uint8_t &SkeinParams::Reserved2() 
{ 
	return m_reserved2; 
}

uint32_t &SkeinParams::Reserved3() 
{ 
	return m_reserved3; 
}

std::vector<uint8_t> &SkeinParams::DistributionCode() 
{ 
	return m_dstCode;
}

const size_t SkeinParams::DistributionCodeMax()
{
	return (m_outputSize - HDR_SIZE);
}

std::vector<uint8_t> &SkeinParams::Schema() 
{ 
	return m_treeSchema;
}

uint16_t &SkeinParams::Version() 
{ 
	return m_treeVersion; 
}

//~~~Public Functions~~~//

std::vector<uint64_t> SkeinParams::GetConfig()
{
	std::vector<uint64_t> config(m_outputSize / sizeof(uint64_t));

	// set schema bytes
	config[0] = IntegerTools::LeBytesTo32(m_treeSchema, 0);
	// version and key size
	config[0] |= (static_cast<uint64_t>(m_treeVersion) << 32);
	config[0] |= (static_cast<uint64_t>(m_reserved1) << 48);
	// output size
	config[1] = m_outputSize * sizeof(uint64_t);
	// leaf size and fanout
	config[2] |= (static_cast<uint64_t>(m_leafSize));
	config[2] |= (static_cast<uint64_t>(m_treeFanout) << 8);
	config[2] |= (static_cast<uint64_t>(m_treeDepth) << 16);
	config[2] |= (static_cast<uint64_t>(m_reserved2) << 24);
	config[2] |= (static_cast<uint64_t>(m_reserved3) << 32);

	// distribution code
	for (size_t i = 3; i < config.size(); ++i)
	{
		config[i] = IntegerTools::LeBytesTo64(m_dstCode, (i - 3) * sizeof(uint64_t));
	}

	return config;
}

SkeinParams SkeinParams::Clone()
{
	return SkeinParams(ToBytes());
}

SkeinParams* SkeinParams::DeepCopy()
{
	return new SkeinParams(ToBytes());
}

bool SkeinParams::Equals(SkeinParams &Input)
{
	return (this->GetHashCode() == Input.GetHashCode());
}

int32_t SkeinParams::GetHashCode()
{
	int32_t result = 31 * m_treeVersion;
	result += 31 * m_reserved1;
	result += 31 * m_leafSize;
	result += 31 * m_outputSize;
	result += 31 * m_treeDepth;
	result += 31 * m_treeFanout;
	result += 31 * m_reserved2;
	result += 31 * m_reserved3;

	for (size_t i = 0; i < m_dstCode.size(); ++i)
	{
		result += 31 * m_dstCode[i];
	}
	for (size_t i = 0; i < m_treeSchema.size(); ++i)
	{
		result += 31 * m_treeSchema[i];
	}

	return result;
}

size_t SkeinParams::GetHeaderSize()
{
	return HDR_SIZE + DistributionCodeMax();
}

void SkeinParams::Reset()
{
	m_treeSchema.clear();
	m_treeVersion = 0;
	m_reserved1 = 0;
	m_outputSize = 0;
	m_leafSize = 0;
	m_treeDepth = 0;
	m_treeFanout = 0;
	m_reserved2 = 0;
	m_reserved3 = 0;
	m_dstCode.clear();
}

std::vector<uint8_t> SkeinParams::ToBytes()
{
	std::vector<uint8_t> trs(GetHeaderSize(), 0);

	std::memcpy(&trs[0], &m_treeSchema[0], 4);
	IntegerTools::Le16ToBytes(m_treeVersion, trs, 4);
	IntegerTools::Le16ToBytes(m_reserved1, trs, 6);
	IntegerTools::Le64ToBytes(m_outputSize, trs, 8);
	std::memcpy(&trs[16], &m_leafSize, 1);
	std::memcpy(&trs[17], &m_treeDepth, 1);
	std::memcpy(&trs[18], &m_treeFanout, 1);
	std::memcpy(&trs[19], &m_reserved2, 1);
	IntegerTools::Le32ToBytes(m_reserved3, trs, 20);
	std::memcpy(&trs[24], &m_dstCode[0], m_dstCode.size());

	return trs;
}

NAMESPACE_DIGESTEND
