#include "SPXPWOTS.h"

NAMESPACE_SPHINCSPLUS

void SPXPWOTS::BaseW(std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<uint8_t> &Input)
{
	// base_w algorithm as described in draft
	// interprets an array of bytes as integers in base w
	// this only works when log_w is a divisor of 8

	size_t i;
	size_t inoff;
	int32_t bits;
	uint8_t total;

	bits = 0;
	inoff = 0;
	total = 0;

	for (i = 0; i < OutLength; ++i)
	{
		if (bits == 0)
		{
			total = Input[inoff];
			++inoff;
			bits += 8;
		}

		bits -= SPX_WOTS_LOGW;
		Output[OutOffset] = (total >> bits) & (SPX_WOTS_W - 1);
		++OutOffset;
	}
}

void SPXPWOTS::ChainLengths(std::vector<int32_t> &Lengths, const std::vector<uint8_t> &Message, size_t N)
{
	const size_t WOTSLEN1 = (8UL * N / SPX_WOTS_LOGW);
	// takes a message and derives the matching chain lengths
	BaseW(Lengths, 0, WOTSLEN1, Message);
	WotsChecksum(Lengths, WOTSLEN1, Lengths, N);
}

void SPXPWOTS::GenChain(std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, uint32_t Start, uint32_t Steps,
	const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t N)
{
	std::vector<uint8_t> mask(1 * N);
	uint32_t idx;

	// initialize out with the value at position 'start'
	MemoryTools::Copy(Input, InOffset, Output, OutOffset, N);

	// iterate 'steps' calls to the hash function
	for (idx = Start; idx < (Start + Steps) && idx < SPX_WOTS_W; ++idx)
	{
		SPXPUtils::SetHashAddress(Address, idx);
		THash(Output, OutOffset, Output, OutOffset, 1, PkSeed, Address, N + SPX_ADDR_BYTES + 1 * N, mask, N);
	}
}

void SPXPWOTS::THash(std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const size_t InputBlocks,
	const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> & Address, size_t BufLen, std::vector<uint8_t> &Mask, size_t N)
{
	std::vector<uint8_t> buf(BufLen);
	size_t i;

	MemoryTools::Copy(PkSeed, 0, buf, 0, N);
	SPXPUtils::AddressToBytes(buf, N, Address);

	SPXPUtils::XOF(buf, 0, N + SPX_ADDR_BYTES, Mask, 0, InputBlocks * N, Keccak::KECCAK256_RATE_SIZE);

	for (i = 0; i < InputBlocks * N; ++i)
	{
		buf[N + SPX_ADDR_BYTES + i] = Input[InOffset + i] ^ Mask[i];
	}

	SPXPUtils::XOF(buf, 0, N + SPX_ADDR_BYTES + InputBlocks * N, Output, OutOffset, N, Keccak::KECCAK256_RATE_SIZE);
}

void SPXPWOTS::WotsChecksum(std::vector<int32_t> &CSumBaseW, size_t BaseOffset, const std::vector<int32_t> &MsgBaseW, size_t N)
{
	// computes the SPXPWOTS+ checksum over a message (in base_w)

	const size_t WOTSLEN1 = (8UL * N / SPX_WOTS_LOGW);
	std::vector<uint8_t> csumbytes((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8);
	uint64_t csum;
	uint32_t idx;

	csum = 0;

	// compute checksum
	for (idx = 0; idx < WOTSLEN1; ++idx)
	{
		csum += static_cast<uint64_t>(SPX_WOTS_W - 1) - MsgBaseW[idx];
	}

	// convert checksum to base_w
	// make sure expected empty zero bits are the least significant bits
	csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
	SPXPUtils::UllToBytes(csumbytes, 0, csum, csumbytes.size());
	BaseW(CSumBaseW, BaseOffset, SPX_WOTS_LEN2, csumbytes);
}

void SPXPWOTS::WotsGenLeaf(std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed, uint32_t AddressIndex,
	const std::array<uint32_t, 8> & TreeAddress, size_t N)
{
	const size_t WOTSLEN = ((8UL * N / SPX_WOTS_LOGW) + SPX_WOTS_LEN2);
	const size_t WOTSBYTES = (WOTSLEN * N);
	// computes the leaf at a given address
	// first generates the SPXPWOTS key pair, then computes leaf by hashing horizontally
	std::vector<uint8_t> mask(WOTSLEN * N);
	std::vector<uint8_t> pk(WOTSBYTES);
	std::array<uint32_t, 8> wotsaddr = { 0 };
	std::array<uint32_t, 8> wotspkaddr = { 0 };

	SPXPUtils::SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
	SPXPUtils::SetType(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);
	SPXPUtils::CopySubtreeAddress(TreeAddress, wotsaddr);
	SPXPUtils::SetKeypairAddress(wotsaddr, AddressIndex);

	WotsGenPk(pk, SkSeed, PkSeed, wotsaddr, N);
	SPXPUtils::CopyKeypairAddress(wotsaddr, wotspkaddr);
	THash(Leaf, LeafOffset, pk, 0, WOTSLEN, PkSeed, wotspkaddr, N + SPX_ADDR_BYTES + WOTSLEN * N, mask, N);
}

void SPXPWOTS::WotsGenPk(std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> & Address, size_t N)
{
	const size_t WOTSLEN2 = (8UL * N / SPX_WOTS_LOGW) + SPX_WOTS_LEN2;

	size_t idx;

	for (idx = 0; idx < WOTSLEN2; ++idx)
	{
		SPXPUtils::SetChainAddress(Address, static_cast<uint32_t>(idx));
		WotsGenSk(PublicKey, idx * N, SkSeed, Address, N);
		GenChain(PublicKey, idx * N, PublicKey, idx * N, 0, SPX_WOTS_W - 1, PkSeed, Address, N);
	}
}

void SPXPWOTS::WotsGenSk(std::vector<uint8_t> &Key, size_t Offset, const std::vector<uint8_t> &KeySeed, std::array<uint32_t, 8> & WotsAddress, size_t N)
{
	// make sure that the hash address is actually zeroed
	SPXPUtils::SetHashAddress(WotsAddress, 0);
	// generate sk element
	SPXPUtils::PrfAddress(Key, Offset, KeySeed, WotsAddress, N);
}

void SPXPWOTS::WotsPkFromSig(std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message,
	const std::vector<uint8_t> &PrivateSeed, std::array<uint32_t, 8> & Address, size_t N)
{
	const size_t WOTSLEN = ((8UL * N / SPX_WOTS_LOGW) + SPX_WOTS_LEN2);
	std::vector<int32_t> lengths(WOTSLEN);
	size_t idx;

	ChainLengths(lengths, Message, N);

	for (idx = 0; idx < WOTSLEN; ++idx)
	{
		SPXPUtils::SetChainAddress(Address, static_cast<uint32_t>(idx));
		GenChain(PublicKey, idx * N, Signature, SigOffset + (idx * N), lengths[idx], (SPX_WOTS_W - 1) - lengths[idx], PrivateSeed, Address, N);
	}
}

void SPXPWOTS::WotsSign(std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &SecretSeed,
	const std::vector<uint8_t> &PublicSeed, std::array<uint32_t, 8> & Address, size_t N)
{
	const size_t WOTSLEN = ((8UL * N / SPX_WOTS_LOGW) + SPX_WOTS_LEN2);
	std::vector<int32_t> lengths(WOTSLEN);
	size_t idx;

	ChainLengths(lengths, Message, N);

	for (idx = 0; idx < WOTSLEN; ++idx)
	{
		SPXPUtils::SetChainAddress(Address, static_cast<uint32_t>(idx));
		WotsGenSk(Signature, SigOffset + (idx * N), SecretSeed, Address, N);
		GenChain(Signature, SigOffset + (idx * N), Signature, SigOffset + (idx * N), 0, lengths[idx], PublicSeed, Address, N);
	}
}

NAMESPACE_SPHINCSEND