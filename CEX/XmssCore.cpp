#include "XMSSCore.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "SHA2.h"
#include "XMSSUtils.h"

NAMESPACE_XMSS

using Utility::IntegerTools;
using Digest::Keccak;
using Utility::MemoryTools;
using Digest::SHA2;

void XMSSCore::AddressToBytes(std::vector<byte> &Input, const std::array<uint, 8> & Address)
{
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		UllToBytes(Input, (i * 4), 4, Address[i]);
	}
}

int32_t XMSSCore::CoreHash(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, size_t InLength)
{
	int32_t ret;

	ret = 0;

	switch (Params.HashFunction)
	{
	case XMSS_SHA2_256:
	{
		SHA2::Compute256(Input, InOffset, InLength, Output, OutOffset);
		break;
	}
	case XMSS_SHA2_512:
	{
		SHA2::Compute512(Input, InOffset, InLength, Output, OutOffset);
		break;
	}
	case XMSS_SHAKE_128:
	{
		Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, Keccak::KECCAK256_DIGEST_SIZE, Keccak::KECCAK128_RATE_SIZE);
		break;
	}
	case XMSS_SHAKE_256:
	{
		Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, Keccak::KECCAK512_DIGEST_SIZE, Keccak::KECCAK256_RATE_SIZE);
		break;
	}
	default:
	{
		ret = -1;
	}
	}

	return ret;
}

int32_t XMSSCore::Prf(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, const std::vector<byte> &Key, size_t KeyOffset)
{
	std::vector<byte> buf((Params.N * 2) + XMSS_PRFCTR_SIZE);
	int32_t ret;

	UllToBytes(buf, 0, Params.N, XMSS_HASH_PADDING_PRF);
	MemoryTools::Copy(Key, KeyOffset, buf, Params.N, Params.N);
	MemoryTools::Copy(Input, 0, buf, 2 * Params.N, XMSS_PRFCTR_SIZE);
	ret = CoreHash(Params, Output, OutOffset, buf, 0, (Params.N * 2) + XMSS_PRFCTR_SIZE);

	return ret;
}

int32_t XMSSCore::HashMessage(const XmssParams &Params, std::vector<byte> &Output, const std::vector<byte> &R, size_t ROffset, const std::vector<byte> &Root, ulong Idx, std::vector<byte> &MsgPrefix, size_t MsgOffset, ulong Msglength)
{
	UllToBytes(MsgPrefix, MsgOffset, Params.N, XMSS_HASH_PADDING_HASH);
	MemoryTools::Copy(R, ROffset, MsgPrefix, MsgOffset + Params.N, Params.N);
	MemoryTools::Copy(Root, 0, MsgPrefix, MsgOffset + (Params.N * 2), Params.N);
	UllToBytes(MsgPrefix, MsgOffset + (Params.N * 3), Params.N, Idx);

	return CoreHash(Params, Output, 0, MsgPrefix, MsgOffset, Msglength + (Params.N * 4));
}

int32_t XMSSCore::ThashH(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	std::vector<byte> bitmask(Params.N * 2);
	std::vector<byte> buf(Params.N * 4);
	std::vector<byte> tmpa(XMSS_PRFCTR_SIZE);
	size_t i;
	int32_t ret;

	// set the function padding
	UllToBytes(buf, 0, Params.N, XMSS_HASH_PADDING_H);

	// generate the n-byte key
	SetKeyAndMask(Address, 0);
	AddressToBytes(tmpa, Address);
	Prf(Params, buf, Params.N, tmpa, PubSeed, 0);

	// generate the 2n-byte mask
	SetKeyAndMask(Address, 1);
	AddressToBytes(tmpa, Address);
	Prf(Params, bitmask, 0, tmpa, PubSeed, 0);

	SetKeyAndMask(Address, 2);
	AddressToBytes(tmpa, Address);
	Prf(Params, bitmask, Params.N, tmpa, PubSeed, 0);

	for (i = 0; i < Params.N * 2; ++i)
	{
		buf[i + (Params.N * 2)] = Input[InOffset + i] ^ bitmask[i];
	}

	ret = CoreHash(Params, Output, OutOffset, buf, 0, 4 * Params.N);

	return ret;
}

int32_t XMSSCore::ThashF(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	std::vector<byte> bitmask(Params.N);
	std::vector<byte> buf(Params.N * 3);
	std::vector<byte> tmpa(XMSS_PRFCTR_SIZE);
	size_t i;
	int32_t ret;

	// set the function padding
	UllToBytes(buf, 0, Params.N, XMSS_HASH_PADDING_F);

	// generate the n-byte key
	SetKeyAndMask(Address, 0);
	AddressToBytes(tmpa, Address);
	Prf(Params, buf, Params.N, tmpa, PubSeed, 0);

	// generate the n-byte mask
	SetKeyAndMask(Address, 1);
	AddressToBytes(tmpa, Address);
	Prf(Params, bitmask, 0, tmpa, PubSeed, 0);

	for (i = 0; i < Params.N; ++i)
	{
		buf[(Params.N * 2) + i] = Input[InOffset + i] ^ bitmask[i];
	}

	ret = CoreHash(Params, Output, OutOffset, buf, 0, 3 * Params.N);

	return ret;
}

// hash_address.c //

void XMSSCore::SetLayerAddress(std::array<uint, 8> & Address, uint Layer)
{
	Address[0] = Layer;
}

void XMSSCore::SetTreeAddress(std::array<uint, 8> & Address, ulong Tree)
{
	Address[1] = (uint)(Tree >> 32);
	Address[2] = (uint)Tree;
}

void XMSSCore::SetType(std::array<uint, 8> & Address, uint Type)
{
	Address[3] = Type;
}

void XMSSCore::SetKeyAndMask(std::array<uint, 8> & Address, uint Mask)
{
	Address[7] = Mask;
}

void XMSSCore::CopySubtreeAdress(std::array<uint, 8> & Output, const std::array<uint, 8> & Input)
{
	Output[0] = Input[0];
	Output[1] = Input[1];
	Output[2] = Input[2];
}

void XMSSCore::SetOtsAddress(std::array<uint, 8> & Address, uint Ots)
{
	Address[4] = Ots;
}

void XMSSCore::SetChainAddress(std::array<uint, 8> & Address, uint Chain)
{
	Address[5] = Chain;
}

void XMSSCore::SetHashAddress(std::array<uint, 8> & Address, uint Hash)
{
	Address[6] = Hash;
}

void XMSSCore::SetLtreeAddress(std::array<uint, 8> & Address, uint Ltree)
{
	Address[4] = Ltree;
}

void XMSSCore::SetTreeHeight(std::array<uint, 8> & Address, uint Height)
{
	Address[5] = Height;
}

void XMSSCore::SetTreeIndex(std::array<uint, 8> & Address, uint Index)
{
	Address[6] = Index;
}

// params.c //

int32_t XMSSCore::XmssParseOid(XmssParams &Params, const uint Oid)
{
	int32_t ret;

	switch (Oid)
	{
	case 0x00000001:
	case 0x00000002:
	case 0x00000003:
	{
		Params.HashFunction = XMSS_SHA2_256;
		break;
	}
	case 0x00000004:
	case 0x00000005:
	case 0x00000006:
	{
		Params.HashFunction = XMSS_SHA2_512;
		break;
	}
	case 0x00000007:
	case 0x00000008:
	case 0x00000009:
	{
		Params.HashFunction = XMSS_SHAKE_128;
		break;
	}
	case 0x0000000A:
	case 0x0000000B:
	case 0x0000000C:
	{
		Params.HashFunction = XMSS_SHAKE_256;
		break;
	}
	default:
	{
		ret = -1;
	}
	}

	switch (Oid)
	{
	case 0x00000001:
	case 0x00000002:
	case 0x00000003:
	case 0x00000007:
	case 0x00000008:
	case 0x00000009:
	{
		Params.N = 32;
		break;
	}
	case 0x00000004:
	case 0x00000005:
	case 0x00000006:
	case 0x0000000A:
	case 0x0000000B:
	case 0x0000000C:
	{
		Params.N = 64;
		break;
	}
	default:
	{
		return -1;
	}
	}

	switch (Oid)
	{
	case 0x00000001:
	case 0x00000004:
	case 0x00000007:
	case 0x0000000A:
	{
		Params.FullHeight = 10;
		break;
	}
	case 0x00000002:
	case 0x00000005:
	case 0x00000008:
	case 0x0000000B:
	{
		Params.FullHeight = 16;
		break;
	}
	case 0x00000003:
	case 0x00000006:
	case 0x00000009:
	case 0x0000000C:
	{
		Params.FullHeight = 20;
		break;
	}
	default:
	{
		return -1;
	}
	}

	Params.BdsK = 0;
	Params.D = 1;
	Params.WotsW = 16;

	return InitializeParams(Params);
}

int32_t XMSSCore::XmssMtParseOid(XmssParams &Params, const uint Oid)
{
	switch (Oid)
	{
	case 0x00000001:
	case 0x00000002:
	case 0x00000003:
	case 0x00000004:
	case 0x00000005:
	case 0x00000006:
	case 0x00000007:
	case 0x00000008:
	{
		Params.HashFunction = XMSS_SHA2_256;
		break;
	}
	case 0x00000009:
	case 0x0000000A:
	case 0x0000000B:
	case 0x0000000C:
	case 0x0000000D:
	case 0x0000000E:
	case 0x0000000F:
	case 0x00000010:
	{
		Params.HashFunction = XMSS_SHA2_512;
		break;
	}
	case 0x00000011:
	case 0x00000012:
	case 0x00000013:
	case 0x00000014:
	case 0x00000015:
	case 0x00000016:
	case 0x00000017:
	case 0x00000018:
	{
		Params.HashFunction = XMSS_SHAKE_128;
		break;
	}
	case 0x00000019:
	case 0x0000001A:
	case 0x0000001B:
	case 0x0000001C:
	case 0x0000001D:
	case 0x0000001E:
	case 0x0000001F:
	case 0x00000020:
	{
		Params.HashFunction = XMSS_SHAKE_256;
		break;
	}
	default:
	{
		return -1;
	}
	}

	switch (Oid)
	{
	case 0x00000001:
	case 0x00000002:
	case 0x00000003:
	case 0x00000004:
	case 0x00000005:
	case 0x00000006:
	case 0x00000007:
	case 0x00000008:
	case 0x00000011:
	case 0x00000012:
	case 0x00000013:
	case 0x00000014:
	case 0x00000015:
	case 0x00000016:
	case 0x00000017:
	case 0x00000018:
	{
		Params.N = 32;
		break;
	}
	case 0x00000009:
	case 0x0000000A:
	case 0x0000000B:
	case 0x0000000C:
	case 0x0000000D:
	case 0x0000000E:
	case 0x0000000F:
	case 0x00000010:
	case 0x00000019:
	case 0x0000001A:
	case 0x0000001B:
	case 0x0000001C:
	case 0x0000001D:
	case 0x0000001E:
	case 0x0000001F:
	case 0x00000020:
	{
		Params.N = 64;
		break;
	}
	default:
	{
		return -1;
	}
	}

	switch (Oid)
	{
	case 0x00000001:
	case 0x00000002:
	case 0x00000009:
	case 0x0000000a:
	case 0x00000011:
	case 0x00000012:
	case 0x00000019:
	case 0x0000001A:
	{
		Params.FullHeight = 20;
		break;
	}
	case 0x00000003:
	case 0x00000004:
	case 0x00000005:
	case 0x0000000B:
	case 0x0000000C:
	case 0x0000000D:
	case 0x00000013:
	case 0x00000014:
	case 0x00000015:
	case 0x0000001B:
	case 0x0000001C:
	case 0x0000001D:
	{
		Params.FullHeight = 40;
		break;
	}
	case 0x00000006:
	case 0x00000007:
	case 0x00000008:
	case 0x0000000E:
	case 0x0000000F:
	case 0x00000010:
	case 0x00000016:
	case 0x00000017:
	case 0x00000018:
	case 0x0000001E:
	case 0x0000001F:
	case 0x00000020:
	{
		Params.FullHeight = 60;
		break;
	}
	default:
	{
		return -1;
	}
	}

	switch (Oid)
	{
	case 0x00000001:
	case 0x00000003:
	case 0x00000009:
	case 0x0000000b:
	case 0x00000011:
	case 0x00000013:
	case 0x00000019:
	case 0x0000001B:
	{
		Params.D = 2;
		break;
	}
	case 0x00000002:
	case 0x00000004:
	case 0x0000000A:
	case 0x0000000c:
	case 0x00000012:
	case 0x00000014:
	case 0x0000001A:
	case 0x0000001C:
	{
		Params.D = 4;
		break;
	}
	case 0x00000005:
	case 0x0000000D:
	case 0x00000015:
	case 0x0000001D:
	{
		Params.D = 8;
		break;
	}
	case 0x00000006:
	case 0x0000000E:
	case 0x00000016:
	case 0x0000001E:
	{
		Params.D = 3;
		break;
	}
	case 0x00000007:
	case 0x0000000F:
	case 0x00000017:
	case 0x0000001F:
	{
		Params.D = 6;
		break;
	}
	case 0x00000008:
	case 0x00000010:
	case 0x00000018:
	case 0x00000020:
	{
		Params.D = 12;
		break;
	}
	default:
	{
		return -1;
	}
	}

	Params.BdsK = 0;
	Params.WotsW = 16;

	return InitializeParams(Params);
}

int32_t XMSSCore::InitializeParams(XmssParams &Params)
{
	Params.TreeHeight = Params.FullHeight / Params.D;

	if (Params.WotsW == 4)
	{
		Params.WotsLogW = 2;
		Params.WotsLen1 = (Params.N * 8) / Params.WotsLogW;
		// len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1
		Params.WotsLen2 = 5;
	}
	else if (Params.WotsW == 16)
	{
		Params.WotsLogW = 4;
		Params.WotsLen1 = (Params.N * 8) / Params.WotsLogW;
		// len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1
		Params.WotsLen2 = 3;
	}
	else if (Params.WotsW == 256)
	{
		Params.WotsLogW = 8;
		Params.WotsLen1 = (Params.N * 8) / Params.WotsLogW;
		// len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1
		Params.WotsLen2 = 2;
	}
	else
	{
		return -1;
	}

	Params.WotsLen = Params.WotsLen1 + Params.WotsLen2;
	Params.WotsSignatureSize = Params.WotsLen * Params.N;

	if (Params.D == 1)
	{
		// assume this is XMSS, not XMSS^MT
		// in XMSS, always use fixed 4 bytes for IndexSize
		Params.IndexSize = 4;
	}
	else
	{
		// in XMSS^MT, round IndexSize up to nearest byte
		Params.IndexSize = (Params.FullHeight + 7) / 8;
	}

	Params.SignatureSize = (Params.IndexSize +
		Params.N +
		(Params.WotsSignatureSize * Params.D) +
		(Params.FullHeight * Params.N));

	Params.PublicKeySize = 2 * Params.N;
	Params.SecretKeySize = CoreSkBytes(Params);

	return 0;
}

// utils.c //

void XMSSCore::UllToBytes(std::vector<byte> &Output, size_t Offset, size_t Length, ulong Input)
{
	size_t i;

	i = Length;

	// iterate over out in decreasing order, for big-endianness
	do
	{
		--i;
		Output[Offset + i] = Input & 0xFF;
		Input = Input >> 8;
	} while (i != 0);
}

ulong XMSSCore::BytesToUll(const std::vector<byte> &Input, size_t Length)
{
	ulong ret;
	size_t i;

	ret = 0;

	for (i = 0; i < Length; ++i)
	{
		ret |= ((ulong)Input[i]) << (8 * (Length - 1 - i));
	}

	return ret;
}

// wots.c //

void XMSSCore::ExpandSeed(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input)
{
	std::vector<byte> ctr(XMSS_PRFCTR_SIZE);
	size_t i;

	for (i = 0; i < Params.WotsLen; ++i)
	{
		UllToBytes(ctr, 0, XMSS_PRFCTR_SIZE, i);
		Prf(Params, Output, OutOffset + (Params.N * i), ctr, Input, 0);
	}
}

void XMSSCore::GenChain(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset,
	uint Start, uint Steps, const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	uint i;

	// initialize out with the value at position 'start'
	MemoryTools::Copy(Input, InOffset, Output, OutOffset, Params.N);

	// iterate 'steps' calls to the hash function
	for (i = Start; i < (Start + Steps) && i < Params.WotsW; ++i)
	{
		SetHashAddress(Address, i);
		ThashF(Params, Output, OutOffset, Output, OutOffset, PubSeed, Address);
	}
}

void XMSSCore::BaseW(const XmssParams &Params, std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<byte> &Input)
{
	size_t i;
	size_t inoft;
	int32_t bits;
	byte total;

	bits = 0;
	inoft = 0;

	for (i = 0; i < OutLength; ++i)
	{
		if (bits == 0)
		{
			total = Input[inoft];
			++inoft;
			bits += 8;
		}

		bits -= Params.WotsLogW;
		Output[OutOffset] = (total >> bits) & (Params.WotsW - 1);
		++OutOffset;
	}
}

void XMSSCore::WotsChecksum(const XmssParams &Params, std::vector<int32_t> &CsumBaseW, size_t CsumOffset, const std::vector<int32_t> &MsgBaseW)
{
	const size_t CSUMLEN = ((Params.WotsLen2 * Params.WotsLogW) + 7) / 8;
	std::vector<byte> csumdata(CSUMLEN);
	size_t i;
	int32_t csum;

	csum = 0;

	// compute checksum
	for (i = 0; i < Params.WotsLen1; ++i)
	{
		csum += Params.WotsW - MsgBaseW[i] - 1;
	}

	// convert checksum to base_w
	// make sure expected empty zero bits are the least significant bits
	csum = csum << (8 - ((Params.WotsLen2 * Params.WotsLogW) % 8));
	UllToBytes(csumdata, 0, CSUMLEN, static_cast<ulong>(csum));
	BaseW(Params, CsumBaseW, CsumOffset, Params.WotsLen2, csumdata);
}

void XMSSCore::ChainLengths(const XmssParams &Params, std::vector<int32_t> &Lengths, const std::vector<byte> &Message)
{
	BaseW(Params, Lengths, 0, Params.WotsLen1, Message);
	WotsChecksum(Params, Lengths, Params.WotsLen1, Lengths);
}

void XMSSCore::WotsPkGen(const XmssParams &Params, std::vector<byte> &PublicKey, const std::vector<byte> &Seed, const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	size_t i;

	// the SPXPWOTS+ private key is derived from the seed
	ExpandSeed(Params, PublicKey, 0, Seed);

	for (i = 0; i < Params.WotsLen; ++i)
	{
		SetChainAddress(Address, static_cast<uint>(i));
		GenChain(Params, PublicKey, Params.N * i, PublicKey, Params.N * i, 0, Params.WotsW - 1, PubSeed, Address);
	}
}

void XMSSCore::WotsSign(const XmssParams &Params, std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &Seed,
	const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	std::vector<int32_t> lengths(Params.WotsLen * sizeof(int32_t));
	size_t i;

	ChainLengths(Params, lengths, Message);

	// the SPXPWOTS+ private key is derived from the seed
	ExpandSeed(Params, Signature, SigOffset, Seed);

	for (i = 0; i < Params.WotsLen; ++i)
	{
		SetChainAddress(Address, static_cast<uint>(i));
		GenChain(Params, Signature, SigOffset + (Params.N * i), Signature, SigOffset + (Params.N * i), 0, lengths[i], PubSeed, Address);
	}
}

void XMSSCore::WotsPkFromSig(const XmssParams &Params, std::vector<byte> &PublicKey, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message,
	const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	std::vector<int32_t> lengths(Params.WotsLen * sizeof(int32_t));
	size_t i;

	ChainLengths(Params, lengths, Message);

	for (i = 0; i < Params.WotsLen; ++i)
	{
		SetChainAddress(Address, static_cast<uint>(i));
		GenChain(Params, PublicKey, Params.N * i, Signature, SigOffset + (Params.N * i), lengths[i], Params.WotsW - lengths[i] - 1, PubSeed, Address);
	}
}

// xmss.c //

int32_t XMSSCore::XmssKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, const uint Oid, std::unique_ptr<Prng::IPrng> &Rng)
{
	XmssParams params;
	size_t i;

	if (XmssParseOid(params, Oid))
	{
		return -1;
	}

	// For an implementation that uses runtime parameters, it is crucial
	// that the OID is part of the secret key as well;
	// i.e. not just for interoperability, but also for internal use
	for (i = 0; i < XMSS_OID_LEN; ++i)
	{
		PublicKey[XMSS_OID_LEN - i - 1] = (Oid >> (8 * i)) & 0xFF;
		SecretKey[XMSS_OID_LEN - i - 1] = (Oid >> (8 * i)) & 0xFF;
	}

	return XmssCoreKeyPair(params, PublicKey, SecretKey, Rng);
}

int32_t XMSSCore::XmssSign(std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength)
{
	XmssParams params;
	size_t i;
	uint oid;

	oid = 0;

	for (i = 0; i < XMSS_OID_LEN; ++i)
	{
		oid |= SecretKey[XMSS_OID_LEN - i - 1] << (i * 8);
	}

	if (XmssParseOid(params, oid))
	{
		return -1;
	}

	return XmssCoreSign(params, SecretKey, Signature, SigLength, Message, MsgLength);
}

int32_t XMSSCore::XmssSignOpen(std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey)
{
	XmssParams params;
	size_t i;
	uint oid;

	oid = 0;

	for (i = 0; i < XMSS_OID_LEN; ++i)
	{
		oid |= PublicKey[XMSS_OID_LEN - i - 1] << (i * 8);
	}

	if (XmssParseOid(params, oid))
	{
		return -1;
	}

	return XmssCoreSignOpen(params, Message, MsgLength, Signature, SigLength, PublicKey);
}

int32_t XMSSCore::XmssMtKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, const uint Oid, std::unique_ptr<Prng::IPrng> &Rng)
{
	XmssParams params;
	size_t i;

	if (XmssMtParseOid(params, Oid))
	{
		return -1;
	}

	for (i = 0; i < XMSS_OID_LEN; ++i)
	{
		PublicKey[XMSS_OID_LEN - i - 1] = (Oid >> (8 * i)) & 0xFF;
		SecretKey[XMSS_OID_LEN - i - 1] = (Oid >> (8 * i)) & 0xFF;
	}

	return XmssMtCoreKeyPair(params, PublicKey, SecretKey, Rng);
}

int32_t XMSSCore::XmssMtSign(std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength)
{
	XmssParams params;
	size_t i;
	uint oid;

	oid = 0;

	for (i = 0; i < XMSS_OID_LEN; ++i)
	{
		oid |= SecretKey[XMSS_OID_LEN - i - 1] << (i * 8);
	}

	if (XmssMtParseOid(params, oid))
	{
		return -1;
	}

	return XmssMtCoreSign(params, SecretKey, Signature, SigLength, Message, MsgLength);
}

int32_t XMSSCore::XmssMtSignOpen(std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey)
{
	XmssParams params;
	size_t i;
	uint oid;

	oid = 0;

	for (i = 0; i < XMSS_OID_LEN; ++i)
	{
		oid |= PublicKey[XMSS_OID_LEN - i - 1] << (i * 8);
	}

	if (XmssMtParseOid(params, oid))
	{
		return -1;
	}

	return XmssMtCoreSignOpen(params, Message, MsgLength, Signature, SigLength, PublicKey);
}

// xmms_commons.c //

void XMSSCore::LTree(const XmssParams &Params, std::vector<byte> &Leaf, size_t LeafOffset, std::vector<byte> &WotsPk, const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	size_t i;
	uint height;
	uint l;
	uint parentnodes;

	height = 0;
	l = static_cast<uint>(Params.WotsLen);
	SetTreeHeight(Address, height);

	while (l > 1)
	{
		parentnodes = l >> 1;

		for (i = 0; i < parentnodes; ++i)
		{
			SetTreeIndex(Address, static_cast<uint>(i));

			// hashes the nodes at (i*2)*params->n and (i*2)*params->n + 1
			ThashH(Params, WotsPk, i * Params.N, WotsPk, Params.N * (i * 2), PubSeed, Address);
		}
		// if the row contained an odd number of nodes, the last node was not hashed. Instead, we pull it up to the next layer
		if (l & 1)
		{
			MemoryTools::Copy(WotsPk, (l - 1) * Params.N, WotsPk, (l >> 1) * Params.N, Params.N);
			l = (l >> 1) + 1;
		}
		else
		{
			l = l >> 1;
		}

		++height;
		SetTreeHeight(Address, height);
	}

	MemoryTools::Copy(WotsPk, 0, Leaf, LeafOffset, Params.N);
}

void XMSSCore::ComputeRoot(const XmssParams &Params, std::vector<byte> &Root, const std::vector<byte> &Leaf, uint leafidx, const std::vector<byte> &Authpath, size_t AuthOffset,
	const std::vector<byte> &PubSeed, std::array<uint, 8> & Address)
{
	std::vector<byte> buffer(Params.N * 2);
	size_t aoft;
	uint i;

	aoft = AuthOffset;

	// if leafidx is odd (last bit = 1), current path element is a right child and authpath has to go left,
	// otherwise it is the other way around
	if (leafidx & 1)
	{
		MemoryTools::Copy(Authpath, aoft, buffer, 0, Params.N);
		MemoryTools::Copy(Leaf, 0, buffer, Params.N, Params.N);
	}
	else
	{
		MemoryTools::Copy(Leaf, 0, buffer, 0, Params.N);
		MemoryTools::Copy(Authpath, aoft, buffer, Params.N, Params.N);
	}

	aoft += Params.N;

	for (i = 0; i < Params.TreeHeight - 1; ++i)
	{
		SetTreeHeight(Address, i);
		leafidx >>= 1;
		SetTreeIndex(Address, leafidx);

		// pick the right or left neighbor, depending on parity of the node
		if (leafidx & 1)
		{
			ThashH(Params, buffer, Params.N, buffer, 0, PubSeed, Address);
			MemoryTools::Copy(Authpath, aoft, buffer, 0, Params.N);
		}
		else
		{
			ThashH(Params, buffer, 0, buffer, 0, PubSeed, Address);
			MemoryTools::Copy(Authpath, aoft, buffer, Params.N, Params.N);
		}

		aoft += Params.N;
	}

	// the last iteration is exceptional; we do not copy an authpath node
	SetTreeHeight(Address, Params.TreeHeight - 1);
	leafidx >>= 1;
	SetTreeIndex(Address, leafidx);
	ThashH(Params, Root, 0, buffer, 0, PubSeed, Address);
}

void XMSSCore::GenLeafWots(const XmssParams &Params, std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SkSeed, size_t SkOffset,
	const std::vector<byte> &PubSeed, std::array<uint, 8> & lTreeAddr, std::array<uint, 8> & OtsAddr)
{
	std::vector<byte> pk(Params.WotsSignatureSize);
	std::vector<byte> seed(Params.N);

	GetSeed(Params, seed, SkSeed, SkOffset, OtsAddr);
	WotsPkGen(Params, pk, seed, PubSeed, OtsAddr);
	LTree(Params, Leaf, LeafOffset, pk, PubSeed, lTreeAddr);
}

void XMSSCore::GetSeed(const XmssParams &Params, std::vector<byte> &Seed, const std::vector<byte> &SkSeed, size_t SkOffset, std::array<uint, 8> & Address)
{
	std::vector<byte> tmp(XMSS_PRFCTR_SIZE);

	// make sure that chain addr, hash addr, and key bit are zeroed
	SetChainAddress(Address, 0);
	SetHashAddress(Address, 0);
	SetKeyAndMask(Address, 0);

	// generate seed
	AddressToBytes(tmp, Address);
	Prf(Params, Seed, 0, tmp, SkSeed, SkOffset);
}

int32_t XMSSCore::XmssCoreSignOpen(const XmssParams &Params, std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey)
{
	// XMSS signatures are fundamentally an instance of XMSSMT signatures
	// For d=1, as is the case with XMSS, some of the calls in the XMSSMT
	// routine become vacuous (i.e. the loop only iterates once, and address
	// management can be simplified a bit)
	return XmssMtCoreSignOpen(Params, Message, MsgLength, Signature, SigLength, PublicKey);
}

int32_t XMSSCore::XmssMtCoreSignOpen(const XmssParams &Params, std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey)
{
	std::vector<byte> pubroot(Params.N);
	std::vector<byte> pubseed(Params.N);
	std::vector<byte> leaf(Params.N);
	std::vector<byte> root(Params.N);
	std::vector<byte> wotspk(Params.WotsSignatureSize);
	std::array<uint, 8> ltreeaddr = { 0 };
	std::array<uint, 8> nodeaddr = { 0 };
	std::array<uint, 8> otsaddr = { 0 };
	size_t pkoft;
	size_t smoft;
	ulong idx;
	uint i;
	uint idx_leaf;
	int32_t ret;

	pkoft = XMSS_OID_LEN;
	SetType(otsaddr, XMSS_ADDR_TYPE_OTS);
	SetType(ltreeaddr, XMSS_ADDR_TYPE_LTREE);
	SetType(nodeaddr, XMSS_ADDR_TYPE_HASHTREE);

	MemoryTools::Copy(PublicKey, pkoft, pubroot, 0, pubroot.size());
	MemoryTools::Copy(PublicKey, pkoft + Params.N, pubseed, 0, pubseed.size());

	MsgLength = SigLength - Params.SignatureSize;
	// convert the index bytes from the signature to an integer
	idx = BytesToUll(Signature, Params.IndexSize);
	// put the message all the way at the end of the m buffer, so that we can
	// prepend the required other inputs for the hash function
	MemoryTools::Copy(Signature, Params.SignatureSize, Message, Params.SignatureSize, MsgLength);
	// compute the message hash
	HashMessage(Params, root, Signature, Params.IndexSize, pubroot, idx, Message, Params.SignatureSize - (Params.N * 4), MsgLength);
	smoft = Params.IndexSize + Params.N;

	/* For each subtree.. */
	for (i = 0; i < Params.D; ++i)
	{
		idx_leaf = (uint)(idx & ((1ULL << Params.TreeHeight) - 1ULL));
		idx = idx >> Params.TreeHeight;

		SetLayerAddress(otsaddr, i);
		SetLayerAddress(ltreeaddr, i);
		SetLayerAddress(nodeaddr, i);

		SetTreeAddress(ltreeaddr, idx);
		SetTreeAddress(otsaddr, idx);
		SetTreeAddress(nodeaddr, idx);

		// the SPXPWOTS public key is only correct if the signature was correct
		SetOtsAddress(otsaddr, idx_leaf);

		// initially, root = mhash, but on subsequent iterations it is the root of the subtree below the currently processed subtree
		WotsPkFromSig(Params, wotspk, Signature, smoft, root, pubseed, otsaddr);
		smoft += Params.WotsSignatureSize;

		// compute the leaf node using the SPXPWOTS public key
		SetLtreeAddress(ltreeaddr, idx_leaf);
		LTree(Params, leaf, 0, wotspk, pubseed, ltreeaddr);

		// compute the root node of this subtree
		ComputeRoot(Params, root, leaf, idx_leaf, Signature, smoft, pubseed, nodeaddr);
		smoft += (size_t)Params.TreeHeight * Params.N;
	}

	// check if the root node equals the root node in the public key
	if (!IntegerTools::Compare(root, 0, pubroot, 0, Params.N))
	{
		// if failed, zero the signature
		MemoryTools::Clear(Message, 0, Message.size());
		MsgLength = 0;
		ret = -1;
	}
	else
	{
		// if verification was successful, resize and move the message
		MemoryTools::Copy(Signature, Params.SignatureSize, Message, 0, MsgLength);
		ret = 0;
	}

	return ret;
}

// xmss_core.c //

void XMSSCore::TreeHash(const XmssParams &Params, std::vector<byte> &Root, size_t RootOffset, std::vector<byte> &AuthPath, size_t AuthOffset, const std::vector<byte> &SkSeed,
	size_t SkOffset, const std::vector<byte> &PubSeed, uint LeafIdx, const std::array<uint, 8> & SubtreeAddress)
{
	std::vector<byte> stack(Params.N * (static_cast<size_t>(Params.TreeHeight) + 1));
	std::vector<uint> heights((static_cast<size_t>(Params.TreeHeight) + 1) * sizeof(uint));
	// we need all three types of addresses in parallel
	std::array<uint, 8> otsaddr = { 0 };
	std::array<uint, 8> ltreeaddr = { 0 };
	std::array<uint, 8> nodeaddr = { 0 };
	// the subtree has at most 2^20 leafs, so uint suffices
	uint idx;
	uint offset;
	uint tree_idx;

	// select the required subtree
	offset = 0;
	CopySubtreeAdress(otsaddr, SubtreeAddress);
	CopySubtreeAdress(ltreeaddr, SubtreeAddress);
	CopySubtreeAdress(nodeaddr, SubtreeAddress);

	SetType(otsaddr, XMSS_ADDR_TYPE_OTS);
	SetType(ltreeaddr, XMSS_ADDR_TYPE_LTREE);
	SetType(nodeaddr, XMSS_ADDR_TYPE_HASHTREE);

	for (idx = 0; idx < (1UL << Params.TreeHeight); idx++)
	{
		// add the next leaf node to the stack
		SetLtreeAddress(ltreeaddr, idx);
		SetOtsAddress(otsaddr, idx);
		GenLeafWots(Params, stack, offset * Params.N, SkSeed, SkOffset, PubSeed, ltreeaddr, otsaddr);
		offset++;
		heights[offset - 1] = 0;

		// if this is a node we need for the auth path
		if ((LeafIdx ^ 0x1) == idx)
		{
			MemoryTools::Copy(stack, (offset - 1) * Params.N, AuthPath, AuthOffset, Params.N);
		}

		// while the top-most nodes are of equal height
		while (offset >= 2 && heights[offset - 1] == heights[offset - 2])
		{
			// compute index of the new node, in the next layer
			tree_idx = (idx >> (heights[offset - 1] + 1));

			// hash the top-most nodes from the stack together
			// Note that tree height is the 'lower' layer, even though we use the index of the new node on the 'higher' layer
			// This follows from the fact that we address the hash function calls
			SetTreeHeight(nodeaddr, heights[offset - 1]);
			SetTreeIndex(nodeaddr, tree_idx);
			ThashH(Params, stack, (offset - 2) * Params.N, stack, Params.N * (offset - 2), PubSeed, nodeaddr);
			--offset;
			// note that the top-most node is now one layer higher
			++heights[offset - 1];

			// if this is a node we need for the auth path
			if (((LeafIdx >> heights[offset - 1]) ^ 0x1) == tree_idx)
			{
				MemoryTools::Copy(stack, (offset - 1) * Params.N, AuthPath, AuthOffset + heights[offset - 1] * Params.N, Params.N);
			}
		}
	}

	MemoryTools::Copy(stack, 0, Root, RootOffset, Params.N);
}

size_t XMSSCore::CoreSkBytes(const XmssParams &Params)
{
	return Params.IndexSize + (4 * Params.N);
}

int32_t XMSSCore::XmssCoreKeyPair(const XmssParams &Params, std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	// the key generation procedure of XMSS and XMSSMT is exactly the same.
	// the only important detail is that the right subtree must be selected;
	// this requires us to correctly set the d=1 parameter for XMSS
	return XmssMtCoreKeyPair(Params, PublicKey, SecretKey, Rng);
}

int32_t XMSSCore::XmssCoreSign(const XmssParams &Params, std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength)
{
	// XMSS signatures are fundamentally an instance of XMSSMT signatures.
	// for d=1, as is the case with XMSS, some of the calls in the XMSSMT
	// routine become vacuous (i.e. the loop only iterates once, and address
	// management can be simplified a bit)
	return XmssMtCoreSign(Params, SecretKey, Signature, SigLength, Message, MsgLength);
}

int32_t XMSSCore::XmssMtCoreKeyPair(const XmssParams &Params, std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	// we do not need the auth path in key generation, but it simplifies the
	// code to have just one treehash routine that computes both root and path in one function

	std::vector<byte> authpath(Params.TreeHeight * Params.N);
	std::vector<byte> pkseed(Params.N);
	std::array<uint, 8> toptreeaddr = { 0 };
	size_t skoft;
	int32_t ret;

	skoft = XMSS_OID_LEN;
	SetLayerAddress(toptreeaddr, Params.D - 1);

	// initialize index to 0
	MemoryTools::Clear(SecretKey, skoft, Params.IndexSize);
	skoft += Params.IndexSize;
	Rng->Generate(SecretKey, skoft, 2 * Params.N);

	// initialize pub seed
	Rng->Generate(SecretKey, skoft + (3 * Params.N), Params.N);
	MemoryTools::Copy(SecretKey, skoft + (3 * Params.N), PublicKey, XMSS_OID_LEN + Params.N, Params.N);
	MemoryTools::Copy(SecretKey, skoft + (3 * Params.N), pkseed, 0, Params.N);

	// compute root node of the top-most subtree
	TreeHash(Params, PublicKey, XMSS_OID_LEN, authpath, 0, SecretKey, skoft, pkseed, 0, toptreeaddr);
	MemoryTools::Copy(PublicKey, XMSS_OID_LEN, SecretKey, skoft + (2 * Params.N), Params.N);
	ret = 0;

	return ret;
}

int32_t XMSSCore::XmssMtCoreSign(const XmssParams &Params, std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength)
{
	std::array<uint, 8> otsaddr = { 0 };
	std::vector<byte> idx32(XMSS_PRFCTR_SIZE);
	std::vector<byte> otsseed(Params.N);
	std::vector<byte> pubroot(Params.N);
	std::vector<byte> pubseed(Params.N);
	std::vector<byte> root(Params.N);
	std::vector<byte> skseed(Params.N);
	std::vector<byte> skprf(Params.N);
	ulong idx;
	size_t skoft;
	size_t smoft;
	uint i;
	uint idxleaf;
	int32_t ret;

	skoft = XMSS_OID_LEN;
	MemoryTools::Copy(SecretKey, skoft + Params.IndexSize, skseed, 0, Params.N);
	MemoryTools::Copy(SecretKey, skoft + Params.IndexSize + Params.N, skprf, 0, Params.N);
	MemoryTools::Copy(SecretKey, skoft + Params.IndexSize + (2 * Params.N), pubroot, 0, Params.N);
	MemoryTools::Copy(SecretKey, skoft + Params.IndexSize + (3 * Params.N), pubseed, 0, Params.N);

	ret = -1;
	SetType(otsaddr, XMSS_ADDR_TYPE_OTS);

	// already put the message in the right place, to make it easier to prepend
	// things when computing the hash over the message
	MemoryTools::Copy(Message, 0, Signature, Params.SignatureSize, MsgLength);
	SigLength = Params.SignatureSize + MsgLength;

	// read and use the current index from the secret key
	idx = (uint)BytesToUll(Signature, Params.IndexSize);
	MemoryTools::Copy(SecretKey, skoft, Signature, 0, Params.IndexSize);

	// Note: the secret key can be updated here
	// increment the index in the secret key
	UllToBytes(SecretKey, skoft, Params.IndexSize, idx + 1);

	// compute the digest randomization value. */
	UllToBytes(idx32, 0, XMSS_PRFCTR_SIZE, idx);
	Prf(Params, Signature, Params.IndexSize, idx32, skprf, 0);

	// compute the message hash
	HashMessage(Params, root, Signature, Params.IndexSize, pubroot, idx, Signature, Params.SignatureSize - 4 * Params.N, MsgLength);
	smoft = Params.IndexSize + Params.N;

	SetType(otsaddr, XMSS_ADDR_TYPE_OTS);

	for (i = 0; i < Params.D; i++)
	{
		idxleaf = (idx & ((1ULL << Params.TreeHeight) - 1ULL));
		idx = idx >> Params.TreeHeight;

		SetLayerAddress(otsaddr, i);
		SetTreeAddress(otsaddr, idx);
		SetOtsAddress(otsaddr, idxleaf);

		// get a seed for the SPXPWOTS keypair
		GetSeed(Params, otsseed, skseed, 0, otsaddr);

		// compute a SPXPWOTS signature
		// initially, root = mhash, but on subsequent iterations it is the root of the subtree below the currently processed subtree
		WotsSign(Params, Signature, smoft, root, otsseed, pubseed, otsaddr);
		smoft += Params.WotsSignatureSize;

		// compute the authentication path for the used SPXPWOTS leaf
		TreeHash(Params, root, 0, Signature, smoft, skseed, 0, pubseed, idxleaf, otsaddr);
		smoft += Params.TreeHeight * Params.N;
	}


	ret = 0;

	return ret;
}

size_t XMSSCore::GetPublicKeySize(XmssParameters Parameters)
{
	XmssParams params;
	size_t klen;
	uint oid;

	klen = 0;
	oid = XMSSUtils::ToOid(Parameters);

	if (XMSSUtils::IsXMSS(Parameters))
	{
		XmssParseOid(params, oid);
	}
	else
	{
		XmssMtParseOid(params, oid);

	}

	klen = params.PublicKeySize + sizeof(oid);

	return klen;
}

size_t XMSSCore::GetPrivateKeySize(XmssParameters Parameters)
{
	XmssParams params;
	size_t klen;
	uint oid;

	klen = 0;
	oid = XMSSUtils::ToOid(Parameters);

	if (XMSSUtils::IsXMSS(Parameters))
	{
		XmssParseOid(params, oid);
	}
	else
	{
		XmssMtParseOid(params, oid);

	}

	klen = params.SecretKeySize + sizeof(oid);

	return klen;
}

size_t XMSSCore::GetSignatureSize(XmssParameters Parameters)
{
	XmssParams params;
	size_t slen;
	uint oid;

	slen = 0;
	oid = XMSSUtils::ToOid(Parameters);

	if (XMSSUtils::IsXMSS(Parameters))
	{
		XmssParseOid(params, oid);
	}
	else
	{
		XmssMtParseOid(params, oid);

	}

	slen = params.SignatureSize;

	return slen;
}

void XMSSCore::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, XmssParameters Parameters)
{
	uint oid;

	oid = XMSSUtils::ToOid(Parameters);

	if (XMSSUtils::IsXMSS(Parameters))
	{
		XmssParams params;
		XmssParseOid(params, oid);
		PublicKey.resize(params.PublicKeySize + sizeof(oid));
		PrivateKey.resize(params.SecretKeySize + sizeof(oid));
		XmssKeyPair(PublicKey, PrivateKey, oid, Rng);
	}
	else
	{
		XmssParams params;
		XmssMtParseOid(params, oid);
		PublicKey.resize(params.PublicKeySize + sizeof(oid));
		PrivateKey.resize(params.SecretKeySize + sizeof(oid));
		XmssMtKeyPair(PublicKey, PrivateKey, oid, Rng);
	}
}

size_t XMSSCore::Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, XmssParameters Parameters)
{
	size_t smlen;
	uint oid;

	smlen = 0;
	oid = XMSSUtils::ToOid(Parameters);
	std::vector<byte> sk2 = PrivateKey;

	if (XMSSUtils::IsXMSS(Parameters))
	{
		XmssParams params;
		XmssParseOid(params, oid);
		Signature.resize(params.SignatureSize + Message.size());
		XmssSign(sk2, Signature, smlen, Message, Message.size());
	}
	else
	{
		XmssParams params;
		XmssMtParseOid(params, oid);
		Signature.resize(params.SignatureSize + Message.size());
		XmssMtSign(sk2, Signature, smlen, Message, Message.size());
	}

	return smlen;
}

bool XMSSCore::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, XmssParameters Parameters)
{
	std::vector<byte> tmpm(0);
	size_t mlen;
	uint oid;
	int32_t ret;

	ret = 0;
	mlen = 0;
	oid = XMSSUtils::ToOid(Parameters);

	if (XMSSUtils::IsXMSS(Parameters))
	{
		XmssParams params;
		XmssParseOid(params, oid);
		tmpm.resize(Signature.size());
		ret = XmssSignOpen(tmpm, mlen, Signature, Signature.size(), PublicKey);
		Message.resize(mlen);
		MemoryTools::Copy(tmpm, 0, Message, 0, Message.size());
	}
	else
	{
		XmssParams params;
		XmssMtParseOid(params, oid);
		tmpm.resize(Signature.size());
		ret = XmssMtSignOpen(tmpm, mlen, Signature, Signature.size(), PublicKey);
		Message.resize(mlen);
		MemoryTools::Copy(tmpm, 0, Message, 0, Message.size());
	}

	return (ret == 0);
}

NAMESPACE_XMSSEND
