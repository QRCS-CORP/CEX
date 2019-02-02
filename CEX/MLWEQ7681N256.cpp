#include "MLWEQ7681N256.h"
#include "MemoryTools.h"
#include "Keccak.h"

NAMESPACE_MODULELWE

using Digest::Keccak;

//~~~Constants~~~//

const std::array<ushort, 256> MLWEQ7681N256::Zetas =
{
	0x03DEU, 0x1D03U, 0x0A4AU, 0x1AA3U, 0x0242U, 0x0CD1U, 0x085FU, 0x0447U,
	0x01E4U, 0x18DAU, 0x0D08U, 0x1506U, 0x17C6U, 0x0EEFU, 0x036DU, 0x1618U,
	0x0DFFU, 0x1B62U, 0x190EU, 0x0107U, 0x0505U, 0x0123U, 0x1BE7U, 0x1CAAU,
	0x062DU, 0x140EU, 0x1440U, 0x172CU, 0x0FCAU, 0x168FU, 0x09A4U, 0x0003U,
	0x025EU, 0x02D9U, 0x1507U, 0x03C2U, 0x0CA8U, 0x1D7CU, 0x1409U, 0x1DE5U,
	0x1729U, 0x1365U, 0x099DU, 0x0281U, 0x0630U, 0x0A6AU, 0x0476U, 0x009DU,
	0x1CEFU, 0x1466U, 0x15E2U, 0x1416U, 0x17FCU, 0x156DU, 0x1343U, 0x0617U,
	0x0825U, 0x14A4U, 0x0808U, 0x0DD2U, 0x1C65U, 0x0DCFU, 0x1C16U, 0x07A5U,
	0x0D89U, 0x1A88U, 0x0602U, 0x1238U, 0x07E7U, 0x1DDBU, 0x0E4CU, 0x1DF9U,
	0x069EU, 0x1AF9U, 0x0F9BU, 0x0D93U, 0x1733U, 0x0743U, 0x1AFEU, 0x1152U,
	0x03FBU, 0x05D4U, 0x1BAFU, 0x1299U, 0x0291U, 0x12FBU, 0x16A6U, 0x0A50U,
	0x069DU, 0x0A2FU, 0x0ADEU, 0x1518U, 0x1942U, 0x03F2U, 0x03BDU, 0x0F0BU,
	0x0849U, 0x18F8U, 0x1C97U, 0x0D27U, 0x0E4BU, 0x0D2FU, 0x191EU, 0x1D9FU,
	0x060DU, 0x16E0U, 0x12A5U, 0x17C4U, 0x15A8U, 0x0672U, 0x0F9DU, 0x1126U,
	0x1A42U, 0x0B63U, 0x1095U, 0x0A4BU, 0x17F0U, 0x1DFCU, 0x1669U, 0x0650U,
	0x0D81U, 0x0C3CU, 0x1C1CU, 0x125EU, 0x185FU, 0x0353U, 0x084AU, 0x0BC1U,
	0x1DBDU, 0x1C7FU, 0x07D7U, 0x0143U, 0x13F8U, 0x0E84U, 0x08F1U, 0x192AU,
	0x1B35U, 0x0A99U, 0x1BD6U, 0x0D49U, 0x03C3U, 0x19C4U, 0x025FU, 0x13A3U,
	0x1BA6U, 0x1184U, 0x1731U, 0x03B0U, 0x0B2CU, 0x0A78U, 0x13B9U, 0x06F1U,
	0x16DAU, 0x0D3BU, 0x1957U, 0x1A79U, 0x12CCU, 0x1274U, 0x1BA5U, 0x00BAU,
	0x1AC0U, 0x1A89U, 0x0D87U, 0x16F5U, 0x0496U, 0x1BCCU, 0x0C05U, 0x1739U,
	0x19BFU, 0x024EU, 0x19F3U, 0x0539U, 0x1794U, 0x0F97U, 0x068BU, 0x0805U,
	0x17A7U, 0x048AU, 0x068FU, 0x0F2BU, 0x10D7U, 0x083AU, 0x1813U, 0x1186U,
	0x18E6U, 0x138EU, 0x11E0U, 0x10C0U, 0x143CU, 0x1006U, 0x011AU, 0x17E7U,
	0x1D13U, 0x18BAU, 0x0C70U, 0x136BU, 0x09E2U, 0x14CDU, 0x104BU, 0x1C11U,
	0x1437U, 0x1617U, 0x076AU, 0x017EU, 0x1C2BU, 0x002BU, 0x174DU, 0x17B9U,
	0x06C2U, 0x014CU, 0x0629U, 0x0CE8U, 0x0919U, 0x06A3U, 0x1806U, 0x094BU,
	0x13F9U, 0x014DU, 0x0DAEU, 0x11A5U, 0x05C8U, 0x0494U, 0x15BFU, 0x028BU,
	0x039DU, 0x11DDU, 0x0257U, 0x0557U, 0x100DU, 0x0747U, 0x1B11U, 0x0645U,
	0x0F1AU, 0x0811U, 0x0FD0U, 0x0347U, 0x1684U, 0x098FU, 0x07E6U, 0x0D11U,
	0x07C6U, 0x0FE3U, 0x07F4U, 0x0815U, 0x0DEFU, 0x1CCBU, 0x0940U, 0x0153U,
	0x1B23U, 0x086FU, 0x028EU, 0x1C9FU, 0x0AD0U, 0x1A14U, 0x03DBU, 0x08A6U
};

const std::array<ushort, 128> MLWEQ7681N256::OmegasInvMontgomery =
{
	0x03DEU, 0x00FEU, 0x035EU, 0x13B7U, 0x19BAU, 0x15A2U, 0x1130U, 0x1BBFU,
	0x07E9U, 0x1A94U, 0x0F12U, 0x063BU, 0x08FBU, 0x10F9U, 0x0527U, 0x1C1DU,
	0x1DFEU, 0x145DU, 0x0772U, 0x0E37U, 0x06D5U, 0x09C1U, 0x09F3U, 0x17D4U,
	0x0157U, 0x021AU, 0x1CDEU, 0x18FCU, 0x1CFAU, 0x04F3U, 0x029FU, 0x1002U,
	0x165CU, 0x01EBU, 0x1032U, 0x019CU, 0x102FU, 0x15F9U, 0x095DU, 0x15DCU,
	0x17EAU, 0x0ABEU, 0x0894U, 0x0605U, 0x09EBU, 0x081FU, 0x099BU, 0x0112U,
	0x1D64U, 0x198BU, 0x1397U, 0x17D1U, 0x1B80U, 0x1464U, 0x0A9CU, 0x06D8U,
	0x001CU, 0x09F8U, 0x0085U, 0x1159U, 0x1A3FU, 0x08FAU, 0x1B28U, 0x1BA3U,
	0x1240U, 0x15B7U, 0x1AAEU, 0x05A2U, 0x0BA3U, 0x01E5U, 0x11C5U, 0x1080U,
	0x17B1U, 0x0798U, 0x0005U, 0x0611U, 0x13B6U, 0x0D6CU, 0x129EU, 0x03BFU,
	0x0CDBU, 0x0E64U, 0x178FU, 0x0859U, 0x063DU, 0x0B5CU, 0x0721U, 0x17F4U,
	0x0062U, 0x04E3U, 0x10D2U, 0x0FB6U, 0x10DAU, 0x016AU, 0x0509U, 0x15B8U,
	0x0EF6U, 0x1A44U, 0x1A0FU, 0x04BFU, 0x08E9U, 0x1323U, 0x13D2U, 0x1764U,
	0x13B1U, 0x075BU, 0x0B06U, 0x1B70U, 0x0B68U, 0x0252U, 0x182DU, 0x1A06U,
	0x0CAFU, 0x0303U, 0x16BEU, 0x06CEU, 0x106EU, 0x0E66U, 0x0308U, 0x1763U,
	0x0008U, 0x0FB5U, 0x0026U, 0x161AU, 0x0BC9U, 0x17FFU, 0x0379U, 0x1078U
};

const std::array<ushort, 256> MLWEQ7681N256::PsisInvMontgomery =
{
	0x0400U, 0x136CU, 0x1693U, 0x1AFBU, 0x134FU, 0x1048U, 0x013BU, 0x15CCU,
	0x005AU, 0x01F1U, 0x0463U, 0x008EU, 0x1266U, 0x1597U, 0x098BU, 0x1307U,
	0x02BAU, 0x09B9U, 0x095AU, 0x0FA3U, 0x02ACU, 0x08C1U, 0x0956U, 0x1C38U,
	0x13D0U, 0x0810U, 0x1285U, 0x0697U, 0x1AB9U, 0x01E2U, 0x1D11U, 0x04D3U,
	0x084EU, 0x1286U, 0x0AF2U, 0x1670U, 0x188FU, 0x1345U, 0x02BBU, 0x0E14U,
	0x0511U, 0x084FU, 0x16E1U, 0x06A9U, 0x0F1CU, 0x0EC3U, 0x112DU, 0x0881U,
	0x009FU, 0x026EU, 0x08C0U, 0x04FBU, 0x0280U, 0x1B24U, 0x11DCU, 0x149DU,
	0x00D1U, 0x0A2DU, 0x0485U, 0x1CA0U, 0x16B9U, 0x0C77U, 0x067EU, 0x07D9U,
	0x1300U, 0x023EU, 0x09B7U, 0x00A4U, 0x1835U, 0x1154U, 0x1C59U, 0x0D86U,
	0x10ACU, 0x10B9U, 0x0D56U, 0x11A3U, 0x0C62U, 0x050AU, 0x07D3U, 0x16DFU,
	0x1BF4U, 0x17AEU, 0x1D6BU, 0x06C4U, 0x0CB1U, 0x1314U, 0x1D58U, 0x0E06U,
	0x0419U, 0x084BU, 0x0575U, 0x17CDU, 0x0E6BU, 0x17F2U, 0x198DU, 0x0F6AU,
	0x1872U, 0x0CFAU, 0x06FCU, 0x1091U, 0x1324U, 0x0905U, 0x0578U, 0x06DDU,
	0x0190U, 0x01F6U, 0x1A2AU, 0x0922U, 0x0BC3U, 0x029CU, 0x1D14U, 0x11E4U,
	0x1974U, 0x1A8BU, 0x0B8FU, 0x1028U, 0x0BE0U, 0x08E7U, 0x18D3U, 0x0F67U,
	0x0B61U, 0x19D5U, 0x1CF8U, 0x0FF4U, 0x196CU, 0x15B4U, 0x0FD6U, 0x0EC6U,
	0x003DU, 0x19A7U, 0x08A4U, 0x030BU, 0x0278U, 0x164DU, 0x1623U, 0x133BU,
	0x132FU, 0x1AEDU, 0x1257U, 0x1044U, 0x0DD0U, 0x08EFU, 0x1DAAU, 0x0B20U,
	0x0CC3U, 0x0777U, 0x0C38U, 0x0222U, 0x07C7U, 0x009CU, 0x135EU, 0x159BU,
	0x1AF7U, 0x01E3U, 0x036BU, 0x008AU, 0x00FAU, 0x08BAU, 0x08DAU, 0x1C36U,
	0x0B1AU, 0x10A2U, 0x032CU, 0x1A2FU, 0x00E8U, 0x1457U, 0x19FAU, 0x0A19U,
	0x076CU, 0x1851U, 0x1344U, 0x1C61U, 0x125DU, 0x0C65U, 0x121BU, 0x18F9U,
	0x00E3U, 0x1C91U, 0x1166U, 0x10BCU, 0x1A67U, 0x04C8U, 0x1467U, 0x05A7U,
	0x018BU, 0x0A30U, 0x1196U, 0x0FC5U, 0x00BDU, 0x0D14U, 0x0036U, 0x192BU,
	0x08A2U, 0x1856U, 0x0B0AU, 0x06F4U, 0x0BBAU, 0x176BU, 0x07A3U, 0x17D6U,
	0x179DU, 0x0F62U, 0x139BU, 0x1141U, 0x059AU, 0x04EEU, 0x05E3U, 0x16D7U,
	0x171DU, 0x1BF5U, 0x1C09U, 0x1922U, 0x1D71U, 0x02E5U, 0x10FCU, 0x051DU,
	0x0091U, 0x0176U, 0x08BCU, 0x1190U, 0x13A4U, 0x1A73U, 0x1B0BU, 0x1CFDU,
	0x07BAU, 0x03FFU, 0x0F11U, 0x1ADCU, 0x044EU, 0x1D1BU, 0x1260U, 0x1976U,
	0x0540U, 0x02FDU, 0x0180U, 0x1649U, 0x04B7U, 0x065EU, 0x127EU, 0x061BU,
	0x1AB7U, 0x172DU, 0x07A2U, 0x137BU, 0x1BE6U, 0x16B6U, 0x1D67U, 0x1359U,
	0x1DD5U, 0x1263U, 0x0886U, 0x1666U, 0x0B02U, 0x021DU, 0x1001U, 0x1609U
};

//~~~Public Functions~~~//

void MLWEQ7681N256::Decrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
{
	const size_t K = (CipherText.size() - (3 * MLWEQ7681N256::MLWE_SEED_SIZE)) / MLWEQ7681N256::MLWE_PUBPOLY_SIZE;
	std::vector<std::array<ushort, MLWE_N>> bp(K);
	std::vector<std::array<ushort, MLWE_N>> skpv(K);
	std::array<ushort, MLWE_N> mp;
	std::array<ushort, MLWE_N> v;

	UnpackCiphertext(bp, v, CipherText);
	UnpackSecretKey(skpv, PrivateKey);

	PolyVecNTT(bp);
	PolyVecPointwiseAcc(mp, skpv, bp);
	InvNTT(mp);
	PolySub(mp, mp, v);
	PolyToMsg(Secret, mp);
}

void MLWEQ7681N256::Encrypt(std::vector<byte> &CipherText, const std::vector<byte> &Message, const std::vector<byte> &PublicKey, const std::vector<byte> &Seed)
{
	const size_t K = (CipherText.size() - (3 * MLWEQ7681N256::MLWE_SEED_SIZE)) / MLWEQ7681N256::MLWE_PUBPOLY_SIZE;
	std::vector<std::vector<std::array<ushort, MLWE_N>>> at(K, std::vector<std::array<ushort, MLWE_N>>(K));
	std::vector<byte> seed(MLWE_SEED_SIZE);
	std::vector<std::array<ushort, MLWE_N>> bp(K);
	std::vector<std::array<ushort, MLWE_N>> ep(K);
	std::vector<std::array<ushort, MLWE_N>> pkpv(K);
	std::vector<std::array<ushort, MLWE_N>> sp(K);
	std::array<ushort, MLWE_N> epp;
	std::array<ushort, MLWE_N> k;
	std::array<ushort, MLWE_N> v;
	size_t i;
	size_t eta;
	ushort nonce;

	UnpackPublicKey(pkpv, seed, PublicKey);
	PolyFromMessage(k, Message);
	PolyVecNTT(pkpv);

	GenerateMatrix(at, seed, true);
	eta = (K == 3) ? 4 : (K == 4) ? 3 : 5;
	nonce = 1;

	for (i = 0; i < K; i++)
	{
		PolyGetNoise(sp[i], eta, Seed, nonce);
		++nonce;
	}

	PolyVecNTT(sp);

	for (i = 0; i < K; i++)
	{
		PolyGetNoise(ep[i], eta, Seed, nonce);
		++nonce;
	}

	for (i = 0; i < K; i++)
	{
		PolyVecPointwiseAcc(bp[i], sp, at[i]);
	}

	PolyVecInvNTT(bp);
	PolyVecAdd(bp, bp, ep);
	PolyVecPointwiseAcc(v, pkpv, sp);
	InvNTT(v);
	PolyGetNoise(epp, eta, Seed, nonce);
	PolyAdd(v, v, epp);
	PolyAdd(v, v, k);

	PackCiphertext(CipherText, bp, v);
}

void MLWEQ7681N256::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	const size_t K = (PublicKey.size() - MLWEQ7681N256::MLWE_SEED_SIZE) / MLWEQ7681N256::MLWE_PUBPOLY_SIZE;
	std::vector<std::vector<std::array<ushort, MLWE_N>>> a(K, std::vector<std::array<ushort, MLWE_N>>(K));
	std::vector<std::array<ushort, MLWE_N>> e(K);
	std::vector<std::array<ushort, MLWE_N>> pkpv(K);
	std::vector<std::array<ushort, MLWE_N>> skpv(K);
	std::vector<byte> noise(MLWE_SEED_SIZE);
	std::vector<byte> seed(MLWE_SEED_SIZE);
	size_t eta;
	size_t i;

	Rng->Generate(seed);
	Rng->Generate(noise);

	GenerateMatrix(a, seed, false);

	Drbg::BCG* gen = new Drbg::BCG(Enumeration::BlockCiphers::AES);
	gen->Initialize(noise);
	std::unique_ptr<Drbg::BCG> genP(gen);
	eta = (K == 3) ? 4 : (K == 4) ? 3 : 5;

	for (i = 0; i < K; i++)
	{
		GetNoise(skpv[i], eta, Rng);
	}

	PolyVecNTT(skpv);

	for (i = 0; i < K; i++)
	{
		GetNoise(e[i], eta, Rng);
	}

	// matrix-vector multiplication
	for (i = 0; i < K; i++)
	{
		PolyVecPointwiseAcc(pkpv[i], skpv, a[i]);
	}

	PolyVecInvNTT(pkpv);
	PolyVecAdd(pkpv, pkpv, e);
	PackSecretKey(PrivateKey, skpv);
	PackPublicKey(PublicKey, pkpv, seed);

	for (i = 0; i < ((K * MLWE_PUBPOLY_SIZE) + MLWE_SEED_SIZE); i++)
	{
		PrivateKey[i + (K * MLWE_PRIPOLY_SIZE)] = PublicKey[i];
	}
}

//~~~Static~~~//

void MLWEQ7681N256::GenerateMatrix(std::vector<std::vector<std::array<ushort, MLWE_N>>> &A, const std::vector<byte> &Seed, bool Transposed)
{
	std::vector<byte> buf(Keccak::KECCAK_RATE128_SIZE * 4);
	std::vector<byte> tmpK(Seed.size() + 2);
	byte i;
	byte j;
	ushort val;
	size_t ctr;
	size_t pos;

	Utility::MemoryTools::Copy(Seed, 0, tmpK, 0, Seed.size());

	for (i = 0; i < A.size(); i++)
	{
		for (j = 0; j < A.size(); j++)
		{
			ctr = 0;
			pos = 0;

			if (Transposed)
			{
				tmpK[Seed.size()] = i;
				tmpK[Seed.size() + 1] = j;
			}
			else
			{
				tmpK[Seed.size() + 1] = i;
				tmpK[Seed.size()] = j;
			}

			XOF(tmpK, 0, tmpK.size(), buf, 0, buf.size(), Keccak::KECCAK_RATE128_SIZE);

			while (ctr < MLWE_N)
			{
				val = (buf[pos] | ((static_cast<ushort>(buf[pos + 1]) << 8) & 0x1FFF));

				if (val < MLWE_Q)
				{
					A[i][j][ctr] = val;
					++ctr;
				}

				pos += 2;

				if (pos > buf.size() - 2)
				{
					XOF(tmpK, 0, tmpK.size(), buf, 0, buf.size(), Keccak::KECCAK_RATE128_SIZE);
					pos = 0;
				}
			}
		}
	}
}

void MLWEQ7681N256::GetNoise(std::array<ushort, MLWE_N> &R, size_t Eta, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<byte> buf((Eta * MLWE_N) / 4);
	Rng->Generate(buf);

	Cbd(R, buf, Eta);
}

void MLWEQ7681N256::PolyGetNoise(std::array<ushort, MLWE_N> &R, size_t Eta, const std::vector<byte> &Seed, ushort Nonce)
{
	std::vector<byte> buf((Eta * MLWE_N) / 4);
	std::vector<byte> cust(8);
	// simple cshake
	cust[0] = 0x01;
	cust[1] = 0x88;
	cust[2] = 0x01;
	cust[3] = 0x00;
	cust[4] = 0x01;
	cust[5] = 0x10;
	cust[6] = static_cast<byte>(Nonce & 0xFF);
	cust[7] = static_cast<byte>(Nonce >> 8);

	XOF(Seed, 0, Seed.size(), buf, 0, buf.size(), Keccak::KECCAK_RATE256_SIZE);

	Cbd(R, buf, Eta);
}

void MLWEQ7681N256::InvNTT(std::array<ushort, MLWE_N> &P)
{
	// TODO: vectorize
	ushort level;
	ushort tmp;
	ushort W;
	uint j;
	uint jTwiddle;
	uint start;
	uint t;
	ushort tpos;

	for (level = 0; level < 8; level++)
	{
		for (start = 0; start < (1U << level); start++)
		{
			jTwiddle = 0;

			for (j = start; j < MLWE_N - 1; j += 2 * (1U << level))
			{
				W = OmegasInvMontgomery[jTwiddle];
				++jTwiddle;
				tmp = P[j];
				tpos = j + (1U << level);

				if (level & 1U)
				{
					P[j] = BarrettReduce(tmp + P[tpos]);
				}
				else
				{
					P[j] = (tmp + P[tpos]);
				}

				t = static_cast<uint>(W) * (tmp + ((4 * MLWE_Q) - P[tpos]));
				P[tpos] = MontgomeryReduce(t);
			}
		}
	}

	for (j = 0; j < MLWE_N; j++)
	{
		P[j] = MontgomeryReduce(static_cast<uint>(P[j]) * PsisInvMontgomery[j]);
	}
}

void MLWEQ7681N256::FwdNTT(std::array<ushort, MLWE_N> &P)
{
	// TODO: vectorize
	short level;
	ushort start;
	ushort t;
	ushort tpos;
	uint j;
	uint k;
	uint zeta;

	j = 0;
	k = 1;

	for (level = 7; level >= 0; level--)
	{
		for (start = 0; start < MLWE_N; start = j + (1U << level))
		{
			zeta = Zetas[k];
			++k;

			for (j = start; j < start + (1U << level); ++j)
			{
				tpos = j + (1U << level);
				t = MontgomeryReduce(zeta * P[tpos]);

				P[tpos] = BarrettReduce(P[j] + ((4 * MLWE_Q) - t));

				if (level & 1U)
				{
					P[j] = P[j] + t;
				}
				else
				{
					P[j] = BarrettReduce(P[j] + t);
				}
			}
		}
	}
}

void MLWEQ7681N256::Cbd(std::array<ushort, MLWE_N> &R, const std::vector<byte> &Buffer, size_t Eta)
{
	// TODO: vectorize
	size_t i;
	size_t j;

	if (Eta == 3)
	{
		std::array<ushort, 4> a;
		std::array<ushort, 4> b;
		uint d;
		uint t;

		for (i = 0; i < MLWE_N / 4; i++)
		{
			t = LeBytesTo32(Buffer, 3 * i, 3);
			d = 0;

			for (j = 0; j < 3; j++)
			{
				d += (t >> j) & 0x249249UL;
			}

			a[0] = (d & 0x7);
			b[0] = ((d >> 3) & 0x7);
			a[1] = ((d >> 6) & 0x7);
			b[1] = ((d >> 9) & 0x7);
			a[2] = ((d >> 12) & 0x7);
			b[2] = ((d >> 15) & 0x7);
			a[3] = ((d >> 18) & 0x7);
			b[3] = (d >> 21);

			R[4 * i] = a[0] + (MLWE_Q - b[0]);
			R[(4 * i) + 1] = a[1] + (MLWE_Q - b[1]);
			R[(4 * i) + 2] = a[2] + (MLWE_Q - b[2]);
			R[(4 * i) + 3] = a[3] + (MLWE_Q - b[3]);
		}
	}
	else if (Eta == 4)
	{
		std::array<ushort, 4> a;
		std::array<ushort, 4> b;
		uint d;
		uint t;

		for (i = 0; i < MLWE_N / 4; i++)
		{
			t = LeBytesTo32(Buffer, 4 * i, 4);
			d = 0;

			for (j = 0; j < 4; j++)
			{
				d += (t >> j) & 0x11111111UL;
			}

			a[0] = (d & 0xF);
			b[0] = ((d >> 4) & 0xF);
			a[1] = ((d >> 8) & 0xF);
			b[1] = ((d >> 12) & 0xF);
			a[2] = ((d >> 16) & 0xF);
			b[2] = ((d >> 20) & 0xF);
			a[3] = ((d >> 24) & 0xF);
			b[3] = (d >> 28);

			R[4 * i] = a[0] + (MLWE_Q - b[0]);
			R[(4 * i) + 1] = a[1] + (MLWE_Q - b[1]);
			R[(4 * i) + 2] = a[2] + (MLWE_Q - b[2]);
			R[(4 * i) + 3] = a[3] + (MLWE_Q - b[3]);
		}
	}
	else
	{
		std::array<uint, 4> a;
		std::array<uint, 4> b;
		ulong d;
		ulong t;

		for (i = 0; i < MLWE_N / 4; i++)
		{
			t = LeBytesTo64(Buffer, (5 * i), 5);
			d = 0;

			for (j = 0; j < 5; j++)
			{
				d += (t >> j) & 0x0842108421ULL;
			}

			a[0] = (d & 0x1F);
			b[0] = ((d >> 5) & 0x1F);
			a[1] = ((d >> 10) & 0x1F);
			b[1] = ((d >> 15) & 0x1F);
			a[2] = ((d >> 20) & 0x1F);
			b[2] = ((d >> 25) & 0x1F);
			a[3] = ((d >> 30) & 0x1F);
			b[3] = (d >> 35);

			R[4 * i] = a[0] + (MLWE_Q - b[0]);
			R[(4 * i) + 1] = a[1] + (MLWE_Q - b[1]);
			R[(4 * i) + 2] = a[2] + (MLWE_Q - b[2]);
			R[(4 * i) + 3] = a[3] + (MLWE_Q - b[3]);
		}
	}
}

void MLWEQ7681N256::PackCiphertext(std::vector<byte> &R, const std::vector<std::array<ushort, MLWE_N>> &B, const std::array<ushort, MLWE_N> &V)
{
	PolyVecCompress(R, B);
	PolyCompress(R, (B.size() * MLWE_PUBPOLY_SIZE), V);
}

void MLWEQ7681N256::PackPublicKey(std::vector<byte> &R, const std::vector<std::array<ushort, MLWE_N>> &Pk, const std::vector<byte> &Seed)
{
	size_t i;

	PolyVecCompress(R, 0, Pk);

	for (i = 0; i < MLWE_SEED_SIZE; i++)
	{
		R[i + (Pk.size() * MLWE_PUBPOLY_SIZE)] = Seed[i];
	}
}

void MLWEQ7681N256::PackSecretKey(std::vector<byte> &R, const std::vector<std::array<ushort, MLWE_N>> &Sk)
{
	PolyVecToBytes(R, Sk);
}

void MLWEQ7681N256::PolyAdd(std::array<ushort, MLWE_N> &R, const std::array<ushort, MLWE_N> &A, const std::array<ushort, MLWE_N> &B)
{
	size_t i;

	for (i = 0; i < MLWE_N; i++)
	{
		R[i] = BarrettReduce(A[i] + B[i]);
	}
}

void MLWEQ7681N256::PolyCompress(std::vector<byte> &R, size_t Offset, const std::array<ushort, MLWE_N> &A)
{
	std::array<uint, 8> t;
	size_t i;
	size_t j;
	size_t k;

	k = 0;

	for (i = 0; i < MLWE_N; i += 8)
	{
		for (j = 0; j < 8; j++)
		{
			t[j] = ((((Freeze(A[i + j]) << 3) + (MLWE_Q / 2)) / MLWE_Q) & 7);
		}

		R[Offset + k] = t[0] | (t[1] << 3) | (t[2] << 6);
		R[Offset + k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		R[Offset + k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);

		k += 3;
	}
}

void MLWEQ7681N256::PolyDecompress(std::array<ushort, MLWE_N> &R, const std::vector<byte> &A, size_t Offset)
{
	size_t i;
	size_t pos;

	pos = Offset;

	for (i = 0; i < MLWE_N; i += 8)
	{
		R[i] = ((((A[pos] & 7) * MLWE_Q) + 4) >> 3);
		R[i + 1] = (((((A[pos] >> 3) & 7) * MLWE_Q) + 4) >> 3);
		R[i + 2] = (((((A[pos] >> 6) | ((A[pos + 1] << 2) & 4)) * MLWE_Q) + 4) >> 3);
		R[i + 3] = (((((A[pos + 1] >> 1) & 7) * MLWE_Q) + 4) >> 3);
		R[i + 4] = (((((A[pos + 1] >> 4) & 7) * MLWE_Q) + 4) >> 3);
		R[i + 5] = (((((A[pos + 1] >> 7) | ((A[pos + 2] << 1) & 6)) * MLWE_Q) + 4) >> 3);
		R[i + 6] = (((((A[pos + 2] >> 2) & 7) * MLWE_Q) + 4) >> 3);
		R[i + 7] = (((((A[pos + 2] >> 5)) * MLWE_Q) + 4) >> 3);
		pos += 3;
	}
}

void MLWEQ7681N256::PolyFrombytes(std::array<ushort, MLWE_N> &R, const std::vector<byte> &A, size_t Offset)
{
	size_t i;

	for (i = 0; i < MLWE_N / 8; i++)
	{
		R[8 * i] = (A[Offset + (13 * i)] | ((static_cast<ushort>(A[Offset + (13 * i) + 1]) & 0x1F) << 8));
		R[(8 * i) + 1] = ((A[Offset + (13 * i) + 1] >> 5) | ((static_cast<ushort>(A[Offset + (13 * i) + 2])) << 3) | ((static_cast<ushort>(A[Offset + (13 * i) + 3]) & 0x03) << 11));
		R[(8 * i) + 2] = ((A[Offset + (13 * i) + 3] >> 2) | ((static_cast<ushort>(A[Offset + (13 * i) + 4]) & 0x7F) << 6));
		R[(8 * i) + 3] = ((A[Offset + (13 * i) + 4] >> 7) | ((static_cast<ushort>(A[Offset + (13 * i) + 5])) << 1) | ((static_cast<ushort>(A[Offset + (13 * i) + 6]) & 0x0F) << 9));
		R[(8 * i) + 4] = ((A[Offset + (13 * i) + 6] >> 4) | ((static_cast<ushort>(A[Offset + (13 * i) + 7])) << 4) | ((static_cast<ushort>(A[Offset + (13 * i) + 8]) & 0x01) << 12));
		R[(8 * i) + 5] = ((A[Offset + (13 * i) + 8] >> 1) | ((static_cast<ushort>(A[Offset + (13 * i) + 9]) & 0x3F) << 7));
		R[(8 * i) + 6] = ((A[Offset + (13 * i) + 9] >> 6) | ((static_cast<ushort>(A[Offset + (13 * i) + 10])) << 2) | ((static_cast<ushort>(A[Offset + (13 * i) + 11]) & 0x07) << 10));
		R[(8 * i) + 7] = ((A[Offset + (13 * i) + 11] >> 3) | ((static_cast<ushort>(A[Offset + (13 * i) + 12])) << 5));
	}
}

void MLWEQ7681N256::PolySub(std::array<ushort, MLWE_N> &R, const std::array<ushort, MLWE_N> &A, const std::array<ushort, MLWE_N> &B)
{
	size_t i;

	for (i = 0; i < MLWE_N; i++)
	{
		R[i] = BarrettReduce(A[i] + ((3 * MLWE_Q) - B[i]));
	}
}

void MLWEQ7681N256::PolyToBytes(std::vector<byte> &R, size_t Offset, const std::array<ushort, MLWE_N> &A)
{
	ushort t[8];
	size_t i;
	size_t j;

	for (i = 0; i < MLWE_N / 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			t[j] = Freeze(A[(8 * i) + j]);
		}

		R[Offset + (13 * i)] = (t[0] & 0xFF);
		R[Offset + (13 * i) + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5));
		R[Offset + (13 * i) + 2] = ((t[1] >> 3) & 0xFF);
		R[Offset + (13 * i) + 3] = ((t[1] >> 11) | ((t[2] & 0x3F) << 2));
		R[Offset + (13 * i) + 4] = ((t[2] >> 6) | ((t[3] & 0x01) << 7));
		R[Offset + (13 * i) + 5] = ((t[3] >> 1) & 0xFF);
		R[Offset + (13 * i) + 6] = ((t[3] >> 9) | ((t[4] & 0x0F) << 4));
		R[Offset + (13 * i) + 7] = ((t[4] >> 4) & 0xFF);
		R[Offset + (13 * i) + 8] = ((t[4] >> 12) | ((t[5] & 0x7F) << 1));
		R[Offset + (13 * i) + 9] = ((t[5] >> 7) | ((t[6] & 0x03) << 6));
		R[Offset + (13 * i) + 10] = ((t[6] >> 2) & 0xFF);
		R[Offset + (13 * i) + 11] = ((t[6] >> 10) | ((t[7] & 0x1F) << 3));
		R[Offset + (13 * i) + 12] = (t[7] >> 5);
	}

}

void MLWEQ7681N256::PolyToMsg(std::vector<byte> &Message, const std::array<ushort, MLWE_N> &A)
{
	size_t i;
	size_t j;
	ushort t;

	for (i = 0; i < MLWE_SEED_SIZE; i++)
	{
		Message[i] = 0;

		for (j = 0; j < 8; j++)
		{
			t = ((((Freeze(A[(8 * i) + j]) << 1) + MLWE_Q / 2) / MLWE_Q) & 1);
			Message[i] |= (t << j);
		}
	}
}

void MLWEQ7681N256::PolyVecAdd(std::vector<std::array<ushort, MLWE_N>> &R, const std::vector<std::array<ushort, MLWE_N>> &A, const std::vector<std::array<ushort, MLWE_N>> &B)
{
	size_t i;

	for (i = 0; i < R.size(); i++)
	{
		PolyAdd(R[i], A[i], B[i]);
	}
}

void MLWEQ7681N256::PolyVecCompress(std::vector<byte> &R, size_t Offset, const std::vector<std::array<ushort, MLWE_N>> &A)
{
	ushort t[8];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	pos = Offset;

	for (i = 0; i < A.size(); i++)
	{
		for (j = 0; j < MLWE_N / 8; j++)
		{
			for (k = 0; k < 8; k++)
			{
				t[k] = (((static_cast<uint>(Freeze(A[i][(8 * j) + k])) << 11) + MLWE_Q / 2) / MLWE_Q) & 0x7FF;
			}

			R[pos + (11 * j)] = (t[0] & 0xFF);
			R[pos + (11 * j) + 1] = ((t[0] >> 8) | ((t[1] & 0x1F) << 3));
			R[pos + (11 * j) + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6));
			R[pos + (11 * j) + 3] = ((t[2] >> 2) & 0xFF);
			R[pos + (11 * j) + 4] = ((t[2] >> 10) | ((t[3] & 0x7F) << 1));
			R[pos + (11 * j) + 5] = ((t[3] >> 7) | ((t[4] & 0x0F) << 4));
			R[pos + (11 * j) + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7));
			R[pos + (11 * j) + 7] = ((t[5] >> 1) & 0xFF);
			R[pos + (11 * j) + 8] = ((t[5] >> 9) | ((t[6] & 0x3F) << 2));
			R[pos + (11 * j) + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5));
			R[pos + (11 * j) + 10] = (t[7] >> 3);
		}
		pos += MLWE_PUBPOLY_SIZE;
	}
}

void MLWEQ7681N256::PolyFromMessage(std::array<ushort, MLWE_N> &R, const std::vector<byte> &Message)
{
	size_t i;
	size_t j;
	ushort mask;

	for (i = 0; i < MLWE_SEED_SIZE; i++)
	{
		for (j = 0; j < 8; j++)
		{
			mask = ~((Message[i] >> j) & 1) + 1;
			R[(8 * i) + j] = (mask & ((MLWE_Q + 1) / 2));
		}
	}
}

void MLWEQ7681N256::PolyVecCompress(std::vector<byte> &R, const std::vector<std::array<ushort, MLWE_N>> &A)
{
	ushort t[8];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	pos = 0;

	for (i = 0; i < A.size(); i++)
	{
		for (j = 0; j < MLWE_N / 8; j++)
		{
			for (k = 0; k < 8; k++)
			{
				t[k] = (((static_cast<uint>(Freeze(A[i][(8 * j) + k])) << 11) + MLWE_Q / 2) / MLWE_Q) & 0x7FF;
			}

			R[pos + (11 * j)] = (t[0] & 0xFF);
			R[pos + (11 * j) + 1] = ((t[0] >> 8) | ((t[1] & 0x1F) << 3));
			R[pos + (11 * j) + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6));
			R[pos + (11 * j) + 3] = ((t[2] >> 2) & 0xFF);
			R[pos + (11 * j) + 4] = ((t[2] >> 10) | ((t[3] & 0x7F) << 1));
			R[pos + (11 * j) + 5] = ((t[3] >> 7) | ((t[4] & 0x0F) << 4));
			R[pos + (11 * j) + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7));
			R[pos + (11 * j) + 7] = ((t[5] >> 1) & 0xFF);
			R[pos + (11 * j) + 8] = ((t[5] >> 9) | ((t[6] & 0x3F) << 2));
			R[pos + (11 * j) + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5));
			R[pos + (11 * j) + 10] = (t[7] >> 3);
		}
		pos += MLWE_PUBPOLY_SIZE;
	}
}

void MLWEQ7681N256::PolyVecDecompress(std::vector<std::array<ushort, MLWE_N>> &R, const std::vector<byte> &A)
{
	size_t i;
	size_t j;
	size_t pos;

	pos = 0;
	for (i = 0; i < R.size(); i++)
	{
		for (j = 0; j < MLWE_N / 8; j++)
		{
			R[i][8 * j] = ((((A[pos + (11 * j)] | ((static_cast<uint>(A[pos + (11 * j) + 1]) & 0x07) << 8)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 1] = (((((A[pos + (11 * j) + 1] >> 3) | ((static_cast<uint>(A[pos + (11 * j) + 2]) & 0x3F) << 5)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 2] = (((((A[pos + (11 * j) + 2] >> 6) | ((static_cast<uint>(A[pos + (11 * j) + 3]) & 0xFF) << 2) | ((static_cast<uint>(A[pos + (11 * j) + 4]) & 0x01) << 10)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 3] = (((((A[pos + (11 * j) + 4] >> 1) | ((static_cast<uint>(A[pos + (11 * j) + 5]) & 0x0F) << 7)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 4] = (((((A[pos + (11 * j) + 5] >> 4) | ((static_cast<uint>(A[pos + (11 * j) + 6]) & 0x7F) << 4)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 5] = (((((A[pos + (11 * j) + 6] >> 7) | ((static_cast<uint>(A[pos + (11 * j) + 7]) & 0xFF) << 1) | ((static_cast<uint>(A[pos + (11 * j) + 8]) & 0x03) << 9)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 6] = (((((A[pos + (11 * j) + 8] >> 2) | ((static_cast<uint>(A[pos + (11 * j) + 9]) & 0x1F) << 6)) * MLWE_Q) + 1024) >> 11);
			R[i][(8 * j) + 7] = (((((A[pos + (11 * j) + 9] >> 5) | ((static_cast<uint>(A[pos + (11 * j) + 10]) & 0xFF) << 3)) * MLWE_Q) + 1024) >> 11);
		}
		pos += MLWE_PUBPOLY_SIZE;
	}
}

void MLWEQ7681N256::PolyVecFrombytes(std::vector<std::array<ushort, MLWE_N>> &R, const std::vector<byte> &A)
{
	size_t i;

	for (i = 0; i < R.size(); i++)
	{
		PolyFrombytes(R[i], A, (i * MLWE_PRIPOLY_SIZE));
	}
}

void MLWEQ7681N256::PolyVecInvNTT(std::vector<std::array<ushort, MLWE_N>> &R)
{
	size_t i;

	for (i = 0; i < R.size(); i++)
	{
		InvNTT(R[i]);
	}
}

void MLWEQ7681N256::PolyVecNTT(std::vector<std::array<ushort, MLWE_N>> &R)
{
	size_t i;

	for (i = 0; i < R.size(); i++)
	{
		FwdNTT(R[i]);
	}
}

void MLWEQ7681N256::PolyVecPointwiseAcc(std::array<ushort, MLWE_N> &R, const std::vector<std::array<ushort, MLWE_N>> &A, const std::vector<std::array<ushort, MLWE_N>> &B)
{
	// TODO: vectorize
	size_t i;
	size_t j;
	ushort t;

	for (j = 0; j < MLWE_N; j++)
	{
		t = MontgomeryReduce(0x1205UL * static_cast<uint>(B[0][j]));
		R[j] = MontgomeryReduce(A[0][j] * t);

		for (i = 1; i < A.size(); i++)
		{
			t = MontgomeryReduce(0x1205UL * static_cast<uint>(B[i][j]));
			R[j] += MontgomeryReduce(A[i][j] * t);
		}

		R[j] = BarrettReduce(R[j]);
	}
}

void MLWEQ7681N256::PolyVecToBytes(std::vector<byte> &R, const std::vector<std::array<ushort, MLWE_N>> &A)
{
	size_t i;

	for (i = 0; i < A.size(); i++)
	{
		PolyToBytes(R, (i * MLWE_PRIPOLY_SIZE), A[i]);
	}
}

void MLWEQ7681N256::UnpackCiphertext(std::vector<std::array<ushort, MLWE_N>> &B, std::array<ushort, MLWE_N> &V, const std::vector<byte> &C)
{
	PolyVecDecompress(B, C);
	PolyDecompress(V, C, B.size() * MLWE_PUBPOLY_SIZE);

}

void MLWEQ7681N256::UnpackPublicKey(std::vector<std::array<ushort, MLWE_N>> &Pk, std::vector<byte> &Seed, const std::vector<byte> &PackedPk)
{
	size_t i;

	PolyVecDecompress(Pk, PackedPk);

	for (i = 0; i < MLWE_SEED_SIZE; i++)
	{
		Seed[i] = PackedPk[i + (Pk.size() * MLWE_PUBPOLY_SIZE)];
	}
}

void MLWEQ7681N256::UnpackSecretKey(std::vector<std::array<ushort, MLWE_N>> &Sk, const std::vector<byte> &PackedSk)
{
	PolyVecFrombytes(Sk, PackedSk);
}

void MLWEQ7681N256::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
#if defined(CEX_SHAKE_STRONG)
	Keccak::XOFR48P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#else
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#endif
}

NAMESPACE_MODULELWEEND
