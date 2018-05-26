#include "Poly1305.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"

NAMESPACE_MAC

using Utility::IntUtils;

const std::string Poly1305::CLASS_NAME("Poly1305");

//~~~Constructor~~~//

Poly1305::Poly1305(BlockCiphers CipherType)
	:
	m_autoClamp(true),
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) : nullptr),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, 0, 0), SymmetricKeySize(KEY_SIZE, BLOCK_SIZE, 0) },
	m_macState(),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0)
{
	if (static_cast<byte>(CipherType) > static_cast<byte>(BlockCiphers::Twofish))
	{
		throw CryptoMacException("Poly1305:Ctor", "HX ciphers are not supported with Poly1305!");
	}
}

Poly1305::Poly1305(IBlockCipher* Cipher)
	:
	m_autoClamp(true),
	m_blockCipher(Cipher != nullptr ? Cipher : 
		throw CryptoMacException("Poly1305:Ctor", "The block cipher instance can not be null!")),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, 0, 0), SymmetricKeySize(KEY_SIZE, BLOCK_SIZE, 0) },
	m_macState(),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0)
{
	if (static_cast<byte>(m_blockCipher->Enumeral()) > static_cast<byte>(BlockCiphers::Twofish))
	{
		throw CryptoMacException("Poly1305:Ctor", "HX ciphers are not supported with Poly1305!");
	}
}

Poly1305::~Poly1305()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_msgLength = 0;
		m_macState.Reset();
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_msgBuffer);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_blockCipher != nullptr)
			{
				m_blockCipher.reset(nullptr);
			}
		}
		else
		{
			if (m_blockCipher != nullptr)
			{
				m_blockCipher.release();
			}
		}
	}
}

//~~~Accessors~~~//

bool &Poly1305::AutoClamp()
{
	return m_autoClamp;
}

const size_t Poly1305::BlockSize()
{
	return BLOCK_SIZE;
}

const Macs Poly1305::Enumeral()
{
	return Macs::Poly1305;
}

const size_t Poly1305::MacSize()
{
	return BLOCK_SIZE;
}

const bool Poly1305::IsInitialized()
{
	return m_isInitialized;
}

std::vector<SymmetricKeySize> Poly1305::LegalKeySizes() const
{
	return m_legalKeySizes;
};

const std::string Poly1305::Name()
{
	return (m_blockCipher != nullptr) ? (CLASS_NAME + "-" + m_blockCipher->Name()) : CLASS_NAME;
}

//~~~Public Functions~~~//

void Poly1305::Clamp(std::vector<byte> &Key)
{
	// r3, r7, r11, r15 have top four bits clear (0,1,... 15)
	Key[3] &= R_MASK_HIGH_4;
	Key[7] &= R_MASK_HIGH_4;
	Key[11] &= R_MASK_HIGH_4;
	Key[15] &= R_MASK_HIGH_4;

	// r4, r8, r12 have bottom two bits clear (0,4,8,... 252)
	Key[4] &= R_MASK_LOW_2;
	Key[8] &= R_MASK_LOW_2;
	Key[12] &= R_MASK_LOW_2;
}

void Poly1305::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");

	if (Output.size() != BLOCK_SIZE)
	{
		Output.resize(BLOCK_SIZE);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Poly1305::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");
	CexAssert((Output.size() - OutOffset) >= BLOCK_SIZE, "The Output buffer is too short");

	if (m_msgLength > 0)
	{
		ProcessBlock(m_msgBuffer, 0, m_msgLength);
	}

	uint b = m_macState.H[0] >> 26;
	m_macState.H[0] = m_macState.H[0] & 0x3FFFFFFUL;
	m_macState.H[1] += b;
	b = m_macState.H[1] >> 26; 
	m_macState.H[1] = m_macState.H[1] & 0x3FFFFFFUL;
	m_macState.H[2] += b; 
	b = m_macState.H[2] >> 26;
	m_macState.H[2] = m_macState.H[2] & 0x3FFFFFFUL;
	m_macState.H[3] += b;
	b = m_macState.H[3] >> 26; 
	m_macState.H[3] = m_macState.H[3] & 0x3FFFFFFUL;
	m_macState.H[4] += b; 
	b = m_macState.H[4] >> 26; 
	m_macState.H[4] = m_macState.H[4] & 0x3FFFFFFUL;
	m_macState.H[0] += b * 5;

	uint g0 = m_macState.H[0] + 5;
	b = g0 >> 26;
	g0 &= 0x3FFFFFFUL;
	uint g1 = m_macState.H[1] + b;
	b = g1 >> 26; 
	g1 &= 0x3FFFFFFUL;
	uint g2 = m_macState.H[2] + b;
	b = g2 >> 26;
	g2 &= 0x3FFFFFFUL;
	uint g3 = m_macState.H[3] + b;
	b = g3 >> 26; 
	g3 &= 0x3FFFFFFUL;
	uint g4 = m_macState.H[4] + b - (1 << 26);

	b = (g4 >> 31) - 1;
	uint nb = ~b;
	m_macState.H[0] = (m_macState.H[0] & nb) | (g0 & b);
	m_macState.H[1] = (m_macState.H[1] & nb) | (g1 & b);
	m_macState.H[2] = (m_macState.H[2] & nb) | (g2 & b);
	m_macState.H[3] = (m_macState.H[3] & nb) | (g3 & b);
	m_macState.H[4] = (m_macState.H[4] & nb) | (g4 & b);

	ulong f0 = (m_macState.H[0] | (m_macState.H[1] << 26)) + static_cast<ulong>(m_macState.K[0]);
	ulong f1 = ((m_macState.H[1] >> 6) | (m_macState.H[2] << 20)) + static_cast<ulong>(m_macState.K[1]);
	ulong f2 = ((m_macState.H[2] >> 12) | (m_macState.H[3] << 14)) + static_cast<ulong>(m_macState.K[2]);
	ulong f3 = ((m_macState.H[3] >> 18) | (m_macState.H[4] << 8)) + static_cast<ulong>(m_macState.K[3]);

	IntUtils::Le32ToBytes((uint)f0, Output, OutOffset);
	f1 += (f0 >> 32);
	IntUtils::Le32ToBytes((uint)f1, Output, OutOffset + 4);
	f2 += (f1 >> 32);
	IntUtils::Le32ToBytes((uint)f2, Output, OutOffset + 8);
	f3 += (f2 >> 32);
	IntUtils::Le32ToBytes((uint)f3, Output, OutOffset + 12);
	Reset();

	return BLOCK_SIZE;
}

void Poly1305::Initialize(ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size(), KeyParams.Nonce().size(), 0))
	{
		throw CryptoMacException("Poly1305:Initialize", "Key size is invalid; must be a legal key size!");
	}
	if (!m_autoClamp && m_blockCipher != nullptr && KeyParams.Nonce().size() == BLOCK_SIZE && !IsClamped(KeyParams.Key()))
	{
		throw CryptoMacException("Poly1305:Initialize", "The key is invalid; must be clamped before initialized!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	std::vector<byte> tmpR(BLOCK_SIZE);
	std::memcpy(&tmpR[0], &KeyParams.Key()[0], BLOCK_SIZE);

	// with the Poly1305-AES version, if the input key has not been pre-conditioned and autoclamp is set, 
	// clamp the R portion of the key automatically rather than throw an exception
	if (m_autoClamp && m_blockCipher != nullptr && KeyParams.Nonce().size() == BLOCK_SIZE && !IsClamped(tmpR))
	{
		Clamp(tmpR);
	}

	uint t0 = IntUtils::LeBytesTo32(tmpR, 0);
	uint t1 = IntUtils::LeBytesTo32(tmpR, 4);
	uint t2 = IntUtils::LeBytesTo32(tmpR, 8);
	uint t3 = IntUtils::LeBytesTo32(tmpR, 12);

	// clamping
	m_macState.R[0] = t0 & 0x03FFFFFFUL;
	m_macState.R[1] = ((t0 >> 26) | (t1 << 6)) & 0x03FFFF03UL;
	m_macState.R[2] = ((t1 >> 20) | (t2 << 12)) & 0x03FFC0FFUL;
	m_macState.R[3] = ((t2 >> 14) | (t3 << 18)) & 0x03F03FFFUL;
	m_macState.R[4] = (t3 >> 8) & 0x000FFFFFUL;

	// precompute multipliers
	m_macState.S[0] = m_macState.R[1] * 5;
	m_macState.S[1] = m_macState.R[2] * 5;
	m_macState.S[2] = m_macState.R[3] * 5;
	m_macState.S[3] = m_macState.R[4] * 5;

	std::vector<byte> tmpK(0);
	size_t kOff;

	if (m_blockCipher != nullptr && KeyParams.Nonce().size() == BLOCK_SIZE)
	{
		// use encrypted nonce
		tmpK.resize(BLOCK_SIZE);
		kOff = 0;
		std::vector<byte> cprK(BLOCK_SIZE);
		std::memcpy(&cprK[0], &KeyParams.Key()[BLOCK_SIZE], BLOCK_SIZE);
		m_blockCipher->Initialize(true, Key::Symmetric::SymmetricKey(cprK));
		m_blockCipher->EncryptBlock(KeyParams.Nonce(), 0, tmpK, 0);
	}
	else
	{
		tmpK = KeyParams.Key();
		kOff = BLOCK_SIZE;
	}

	m_macState.K[0] = IntUtils::LeBytesTo32(tmpK, kOff + 0);
	m_macState.K[1] = IntUtils::LeBytesTo32(tmpK, kOff + 4);
	m_macState.K[2] = IntUtils::LeBytesTo32(tmpK, kOff + 8);
	m_macState.K[3] = IntUtils::LeBytesTo32(tmpK, kOff + 12);

	m_isInitialized = true;
}

bool Poly1305::IsClamped(const std::vector<byte> &Key)
{
	std::vector<byte> tmpK(Key.size());
	std::memcpy(&tmpK[0], &Key[0], Key.size());
	Clamp(tmpK);

	return (Key == tmpK);
}

void Poly1305::Reset()
{
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
	m_macState.Reset();
	m_isInitialized = false;
}

void Poly1305::Update(byte Input)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");

	if (m_msgLength == m_msgBuffer.size())
	{
		ProcessBlock(m_msgBuffer, 0, BLOCK_SIZE);
		m_msgLength = 0;
	}

	++m_msgLength;
	m_msgBuffer[m_msgLength] = Input;
}

void Poly1305::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");
	CexAssert((InOffset + Length) <= Input.size(), "The Mac is not initialized");

	if (Length != 0)
	{
		if (m_msgLength != 0 && (m_msgLength + Length >= BLOCK_SIZE))
		{
			const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
			if (RMDLEN != 0)
			{
				Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
			}

			ProcessBlock(m_msgBuffer, 0, BLOCK_SIZE);
			m_msgLength = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		// loop through blocks
		while (Length >= BLOCK_SIZE)
		{
			ProcessBlock(Input, InOffset, BLOCK_SIZE);
			Length -= BLOCK_SIZE;
			InOffset += BLOCK_SIZE;
		}

		if (Length > 0)
		{
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

ulong Poly1305::CMul(uint A, uint B)
{
	return static_cast<ulong>(A) * B;
}

void Poly1305::ProcessBlock(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	ulong t0;
	ulong t1;
	ulong t2;
	ulong t3;

	if (Length >= BLOCK_SIZE)
	{
		t0 = IntUtils::LeBytesTo32(Input, InOffset);
		t1 = IntUtils::LeBytesTo32(Input, InOffset + 4);
		t2 = IntUtils::LeBytesTo32(Input, InOffset + 8);
		t3 = IntUtils::LeBytesTo32(Input, InOffset + 12);
	}
	else
	{
		std::array<byte, BLOCK_SIZE> buffer;
		std::memset(&buffer[Length], 0, BLOCK_SIZE - Length);
		std::memcpy(&buffer[0], &Input[InOffset], Length);
		buffer[Length] = 1;

		t0 = IntUtils::LeBytesTo32(buffer, 0);
		t1 = IntUtils::LeBytesTo32(buffer, 4);
		t2 = IntUtils::LeBytesTo32(buffer, 8);
		t3 = IntUtils::LeBytesTo32(buffer, 12);
	}

	m_macState.H[0] += static_cast<uint>(t0 & 0x3FFFFFFUL);
	m_macState.H[1] += static_cast<uint>((((t1 << 32) | t0) >> 26) & 0x3FFFFFFUL);
	m_macState.H[2] += static_cast<uint>((((t2 << 32) | t1) >> 20) & 0x3FFFFFFUL);
	m_macState.H[3] += static_cast<uint>((((t3 << 32) | t2) >> 14) & 0x3FFFFFFUL);
	m_macState.H[4] += static_cast<uint>(t3 >> 8);

	if (Length == BLOCK_SIZE)
	{
		m_macState.H[4] += (1 << 24);
	}

	ulong tp0 = CMul(m_macState.H[0], m_macState.R[0]) + CMul(m_macState.H[1], m_macState.S[3]) + CMul(m_macState.H[2], m_macState.S[2]) + CMul(m_macState.H[3], m_macState.S[1]) + CMul(m_macState.H[4], m_macState.S[0]);
	ulong tp1 = CMul(m_macState.H[0], m_macState.R[1]) + CMul(m_macState.H[1], m_macState.R[0]) + CMul(m_macState.H[2], m_macState.S[3]) + CMul(m_macState.H[3], m_macState.S[2]) + CMul(m_macState.H[4], m_macState.S[1]);
	ulong tp2 = CMul(m_macState.H[0], m_macState.R[2]) + CMul(m_macState.H[1], m_macState.R[1]) + CMul(m_macState.H[2], m_macState.R[0]) + CMul(m_macState.H[3], m_macState.S[3]) + CMul(m_macState.H[4], m_macState.S[2]);
	ulong tp3 = CMul(m_macState.H[0], m_macState.R[3]) + CMul(m_macState.H[1], m_macState.R[2]) + CMul(m_macState.H[2], m_macState.R[1]) + CMul(m_macState.H[3], m_macState.R[0]) + CMul(m_macState.H[4], m_macState.S[3]);
	ulong tp4 = CMul(m_macState.H[0], m_macState.R[4]) + CMul(m_macState.H[1], m_macState.R[3]) + CMul(m_macState.H[2], m_macState.R[2]) + CMul(m_macState.H[3], m_macState.R[1]) + CMul(m_macState.H[4], m_macState.R[0]);

	ulong b;
	m_macState.H[0] = static_cast<uint>(tp0 & 0x3FFFFFFUL);
	b = (tp0 >> 26);
	tp1 += b; 
	m_macState.H[1] = static_cast<uint>(tp1 & 0x3FFFFFFUL);
	b = (tp1 >> 26);
	tp2 += b;
	m_macState.H[2] = static_cast<uint>(tp2 & 0x3FFFFFFUL);
	b = (tp2 >> 26);
	tp3 += b;
	m_macState.H[3] = static_cast<uint>(tp3 & 0x3FFFFFFUL);
	b = (tp3 >> 26);
	tp4 += b;
	m_macState.H[4] = static_cast<uint>(tp4 & 0x3FFFFFFUL);
	b = (tp4 >> 26);
	m_macState.H[0] += static_cast<uint>(b * 5);
}

NAMESPACE_MACEND
