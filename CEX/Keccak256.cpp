#include "Keccak256.h"
#include "Keccak.h"
#include "ArrayUtils.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

void Keccak256::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("Keccak256:BlockUpdate", "The Input buffer is too short!");

	if (m_bufferIndex != 0)
	{
		if (Length + m_bufferIndex >= m_blockSize)
		{
			size_t chunkSize = m_blockSize - m_bufferIndex;
			memcpy(&m_buffer[m_bufferIndex], &Input[InOffset], chunkSize);
			Keccak::TransformBlock(m_buffer, 0, m_state, m_blockSize);
			Length -= chunkSize;
			InOffset += chunkSize;
			m_bufferIndex = 0;
		}
	}

	while (Length >= m_buffer.size())
	{
		Keccak::TransformBlock(Input, InOffset, m_state, m_blockSize);
		InOffset += m_buffer.size();
		Length -= m_buffer.size();
	}

	if (Length != 0)
	{
		memcpy(&m_buffer[m_bufferIndex], &Input[InOffset], Length);
		m_bufferIndex += Length;
	}
}

void Keccak256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(m_digestSize);
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void Keccak256::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_digestSize = 0;
		m_blockSize = 0;

		try
		{
			Utility::ArrayUtils::ClearVector(m_buffer);
			Utility::ArrayUtils::ClearVector(m_state);
		}
		catch (std::exception& ex)
		{
			throw CryptoDigestException("Keccak256:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t Keccak256::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < m_digestSize)
		throw CryptoDigestException("Keccak256:DoFinal", "The Output buffer is too short!");

	memset(&m_buffer[m_bufferIndex], (byte)0, m_buffer.size() - m_bufferIndex);

	m_buffer[m_bufferIndex] = 1;
	m_buffer[m_blockSize - 1] |= 128;

	Keccak::TransformBlock(m_buffer, 0, m_state, m_blockSize);

	m_state[1] = ~m_state[1];
	m_state[2] = ~m_state[2];
	m_state[8] = ~m_state[8];
	m_state[12] = ~m_state[12];
	m_state[17] = ~m_state[17];

	std::vector<byte> longBytes;
	IntUtils::Word64sToBytes(m_state, longBytes);
	memcpy(&Output[OutOffset], &longBytes[0], m_digestSize);
	Initialize();

	return m_digestSize;
}

void Keccak256::Reset()
{
	Initialize();
}

void Keccak256::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	BlockUpdate(one, 0, 1);
}

//~~~Protected Methods~~~//

void Keccak256::Initialize()
{
	std::fill(m_state.begin(), m_state.end(), 0);
	m_buffer.resize(m_blockSize, 0);
	m_bufferIndex = 0;

	const ulong UInt64_MaxValue = 0xFFFFFFFFFFFFFFFF;
	m_state[1] = UInt64_MaxValue;
	m_state[2] = UInt64_MaxValue;
	m_state[8] = UInt64_MaxValue;
	m_state[12] = UInt64_MaxValue;
	m_state[17] = UInt64_MaxValue;
	m_state[20] = UInt64_MaxValue;
}

NAMESPACE_DIGESTEND