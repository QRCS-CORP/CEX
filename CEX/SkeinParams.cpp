#include "SkeinParams.h"
#include "CryptoDigestException.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

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
{}

SkeinParams::SkeinParams(ulong OutputSize, byte LeafSize, byte Fanout)
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
	CexAssert(OutputSize == 32 || OutputSize == 64 || OutputSize == 128, "The output size is invalid!");
	CexAssert(Fanout > 0 && LeafSize > 0 || Fanout == 0 && LeafSize == 0, "The fanout and leaf sizes are invalid!");

	if (OutputSize != 32 && OutputSize != 64 && OutputSize != 128)
	{
		throw Exception::CryptoDigestException("SkeinParams:Ctor", "The output size is invalid!");
	}
	if (Fanout > 0 && LeafSize == 0 || Fanout == 0 && LeafSize != 0)
	{
		throw Exception::CryptoDigestException("SkeinParams:Ctor", "The fanout and leaf sizes are invalid!");
	}

	m_dstCode.resize(DistributionCodeMax());
}

SkeinParams::SkeinParams(const std::vector<byte> &TreeArray)
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
	CexAssert(TreeArray.size() >= GetHeaderSize(), "The TreeArray buffer is too short!");

	std::memcpy(&m_treeSchema[0], &TreeArray[0], 4);
	m_treeVersion = Utility::IntUtils::LeBytesTo16(TreeArray, 4);
	m_reserved1 = Utility::IntUtils::LeBytesTo16(TreeArray, 6);
	m_outputSize = Utility::IntUtils::LeBytesTo64(TreeArray, 8);
	std::memcpy(&m_leafSize, &TreeArray[16], 1);
	std::memcpy(&m_treeDepth, &TreeArray[17], 1);
	std::memcpy(&m_treeFanout, &TreeArray[18], 1);
	std::memcpy(&m_reserved2, &TreeArray[19], 1);
	m_reserved3 = Utility::IntUtils::LeBytesTo32(TreeArray, 20);
	m_dstCode.resize(DistributionCodeMax());
	std::memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
}

SkeinParams::SkeinParams(const std::vector<byte> &Schema, ulong OutputSize, ushort Version, uint LeafSize, byte Fanout, byte TreeDepth, std::vector<byte> &DistributionCode)
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

	CexAssert(Schema.size() == 4, "The Schema must be 4 bytes in length!");
	CexAssert(TreeDepth == 0, "The tree depth is always 0!");
	CexAssert(Version == 1, "The version number must be 1!");
	CexAssert(m_treeFanout == 0 || m_treeFanout > 0 && (m_leafSize != OutputSize || m_treeFanout % 2 == 0), "The fan-out must be an even number and should align to processor cores!");
}

//~~~Accessors~~~//

byte &SkeinParams::FanOut()
{
	return m_treeFanout;
}

byte &SkeinParams::LeafSize()
{
	return m_leafSize;
}

ulong &SkeinParams::OutputSize() 
{ 
	return m_outputSize;
}

ushort &SkeinParams::Reserved1() 
{ 
	return m_reserved1;
}

byte &SkeinParams::Reserved2() 
{ 
	return m_reserved2; 
}

uint &SkeinParams::Reserved3() 
{ 
	return m_reserved3; 
}

std::vector<byte> &SkeinParams::DistributionCode() 
{ 
	return m_dstCode;
}

const size_t SkeinParams::DistributionCodeMax()
{
	return (m_outputSize - HDR_SIZE);
}

std::vector<byte> &SkeinParams::Schema() 
{ 
	return m_treeSchema;
}

ushort &SkeinParams::Version() 
{ 
	return m_treeVersion; 
}

//~~~Public Functions~~~//

std::vector<ulong> SkeinParams::GetConfig()
{
	std::vector<ulong> config(m_outputSize / sizeof(ulong));

	// set schema bytes
	config[0] = Utility::IntUtils::LeBytesTo32(m_treeSchema, 0);
	// version and key size
	config[0] |= (static_cast<ulong>(m_treeVersion) << 32);
	config[0] |= (static_cast<ulong>(m_reserved1) << 48);
	// output size
	config[1] = m_outputSize * sizeof(ulong);
	// leaf size and fanout
	config[2] |= (static_cast<ulong>(m_leafSize));
	config[2] |= (static_cast<ulong>(m_treeFanout) << 8);
	config[2] |= (static_cast<ulong>(m_treeDepth) << 16);
	config[2] |= (static_cast<ulong>(m_reserved2) << 24);
	config[2] |= (static_cast<ulong>(m_reserved3) << 32);

	// distribution code
	for (size_t i = 3; i < config.size(); ++i)
	{
		config[i] = Utility::IntUtils::LeBytesTo64(m_dstCode, (i - 3) * sizeof(ulong));
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

int SkeinParams::GetHashCode()
{
	int result = 31 * m_treeVersion;
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

std::vector<byte> SkeinParams::ToBytes()
{
	std::vector<byte> trs(GetHeaderSize(), 0);

	std::memcpy(&trs[0], &m_treeSchema[0], 4);
	Utility::IntUtils::Le16ToBytes(m_treeVersion, trs, 4);
	Utility::IntUtils::Le16ToBytes(m_reserved1, trs, 6);
	Utility::IntUtils::Le64ToBytes(m_outputSize, trs, 8);
	std::memcpy(&trs[16], &m_leafSize, 1);
	std::memcpy(&trs[17], &m_treeDepth, 1);
	std::memcpy(&trs[18], &m_treeFanout, 1);
	std::memcpy(&trs[19], &m_reserved2, 1);
	Utility::IntUtils::Le32ToBytes(m_reserved3, trs, 20);
	std::memcpy(&trs[24], &m_dstCode[0], m_dstCode.size());

	return trs;
}

NAMESPACE_DIGESTEND