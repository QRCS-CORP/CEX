#include "VMAC.h"
#include "IntUtils.h"

NAMESPACE_MAC

using CEX::Utility::IntUtils;

void VMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((InOffset + Length) > Input.size())
		throw CryptoMacException("VMAC:Ctor", "The Input buffer is too short!");
#endif

	for (size_t i = 0; i < Length; ++i)
		Update(Input[InOffset + i]);
}

void VMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (!m_isInitialized)
		throw CryptoMacException("VMAC:ComputeMac", "The Mac is not initialized!");
#endif

	if (Output.size() != MAC_SIZE)
		Output.resize(MAC_SIZE);

	BlockUpdate(Input, 0, (int)Input.size());
	DoFinal(Output, 0);
}

void VMAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_blockSize = 0;
		m_isInitialized = false;
		G = 0;
		N = 0;
		S = 0;
		X1 = 0;
		X2 = 0;
		X3 = 0;
		X4 = 0;
		IntUtils::ClearVector(P);
		IntUtils::ClearVector(T);
		IntUtils::ClearVector(m_workingKey);
		IntUtils::ClearVector(m_workingIV);
		m_isDestroyed = true;
	}
}

size_t VMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Output.size() - OutOffset < MAC_SIZE)
		throw CryptoMacException("VMAC:DoFinal", "The Output buffer is too short!");
#endif

	size_t ctr = 1;
	byte ptmp;

	// execute the post-processing phase
	while (ctr != 25)
	{
		S = P[(S + P[N & CTFF]) & CTFF];
		X4 = P[(X4 + X3 + ctr) & CTFF];
		X3 = P[(X3 + X2 + ctr) & CTFF];
		X2 = P[(X2 + X1 + ctr) & CTFF];
		X1 = P[(X1 + S + ctr) & CTFF];
		T[G & CT1F] = (byte)(T[G & CT1F] ^ X1);
		T[(G + 1) & CT1F] = (byte)(T[(G + 1) & CT1F] ^ X2);
		T[(G + 2) & CT1F] = (byte)(T[(G + 2) & CT1F] ^ X3);
		T[(G + 3) & CT1F] = (byte)(T[(G + 3) & CT1F] ^ X4);
		G = (byte)((G + 4) & CT1F);

		ptmp = P[N & CTFF];
		P[N & CTFF] = P[S & CTFF];
		P[S & CTFF] = ptmp;
		N = (byte)((N + 1) & CTFF);

		++ctr;
	}

	// input T to the IV-phase of the VMPC KSA
	ctr = 0;
	while (ctr != 768)
	{
		S = P[(S + P[ctr & CTFF] + T[ctr & CT1F]) & CTFF];
		ptmp = P[ctr & CTFF];
		P[ctr & CTFF] = P[S & CTFF];
		P[S & CTFF] = ptmp;

		++ctr;
	}

	// store 20 new outputs of the VMPC Stream Cipher input table M
	std::vector<byte> M(20);
	ctr = 0;
	while (ctr != 20)
	{
		S = P[(S + P[ctr & CTFF]) & CTFF];
		M[ctr] = P[(P[(P[S & CTFF]) & CTFF] + 1) & CTFF];
		ptmp = P[ctr & CTFF];
		P[ctr & CTFF] = P[S & CTFF];
		P[S & CTFF] = ptmp;

		++ctr;
	}

	memcpy(&Output[OutOffset], &M[0], M.size());
	Reset();

	return M.size();
}

void VMAC::Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (MacKey.size() == 0)
		throw CryptoMacException("VMAC:Initialize", "Key can not be zero length!");
	if (IV.size() < 1 || IV.size() > 768)
		throw CryptoMacException("VMAC:Initialize", "VMAC requires 1 to 768 bytes of IV!");
#endif

	m_workingIV.resize(IV.size());
	memcpy(&m_workingIV[0], &IV[0], IV.size());
	m_workingKey.resize(MacKey.size());
	memcpy(&m_workingKey[0], &MacKey[0], MacKey.size());

	Reset();
	m_isInitialized = true;
}

void VMAC::Reset()
{
	G = N = S = X1 = X2 = X3 = X4 = 0;
	T.clear();
	T.resize(32, (byte)0);
	InitKey(m_workingKey, m_workingIV);
}

void VMAC::Update(byte Input)
{
	S = P[(S + P[N & CTFF]) & CTFF];
	byte btmp = (byte)(Input ^ P[(P[(P[S & CTFF]) & CTFF] + 1) & CTFF]);

	X4 = P[(X4 + X3) & CTFF];
	X3 = P[(X3 + X2) & CTFF];
	X2 = P[(X2 + X1) & CTFF];
	X1 = P[(X1 + S + btmp) & CTFF];
	T[G & CT1F] = (byte)(T[G & CT1F] ^ X1);
	T[(G + 1) & CT1F] = (byte)(T[(G + 1) & CT1F] ^ X2);
	T[(G + 2) & CT1F] = (byte)(T[(G + 2) & CT1F] ^ X3);
	T[(G + 3) & CT1F] = (byte)(T[(G + 3) & CT1F] ^ X4);
	G = (byte)((G + 4) & CT1F);

	btmp = P[N & CTFF];
	P[N & CTFF] = P[S & CTFF];
	P[S & CTFF] = btmp;
	N = (byte)((N + 1) & CTFF);
}

void VMAC::InitKey(std::vector<byte> &Key, std::vector<byte> &Iv)
{
	size_t ctr = 0;

	while (ctr != 256)
	{
		P[ctr] = (byte)ctr;
		++ctr;
	}

	byte btmp = 0;

	ctr = 0;
	while (ctr != 768)
	{
		S = P[(S + P[ctr & CTFF] + Key[ctr % Key.size()]) & CTFF];
		btmp = P[ctr & CTFF];
		P[ctr & CTFF] = P[S & CTFF];
		P[S & CTFF] = btmp;
		++ctr;
	}

	ctr = 0;
	while (ctr != 768)
	{
		S = P[(S + P[ctr & CTFF] + Iv[ctr % Iv.size()]) & CTFF];
		btmp = P[ctr & CTFF];
		P[ctr & CTFF] = P[S & CTFF];
		P[S & CTFF] = btmp;
		++ctr;
	}

	N = 0;
}

NAMESPACE_MACEND