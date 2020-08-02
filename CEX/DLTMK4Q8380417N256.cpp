#include "DLTMK4Q8380417N256.h"
#include "DLTMPolyMath.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "DLTMPolyMath.h"

NAMESPACE_DILITHIUM

using Digest::Keccak;
using Tools::MemoryTools;

void DLTMK4Q8380417N256::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<byte> key(DILITHIUM_SEED_SIZE);
	std::vector<byte> rho(DILITHIUM_SEED_SIZE);
	std::vector<byte> rhoprime(DILITHIUM_SEED_SIZE);
	std::vector<byte> sbuf(3 * DILITHIUM_SEED_SIZE);
	std::vector<byte> tr(DILITHIUM_CRH_SIZE);
	std::vector<std::vector<std::array<uint, 256>>> mat(DILITHIUM_K, std::vector<std::array<uint, 256>>(DILITHIUM_L));
	std::vector<std::array<uint, 256>> s1(DILITHIUM_L);
	std::vector<std::array<uint, 256>> s1hat(DILITHIUM_L);
	std::vector<std::array<uint, 256>> s2(DILITHIUM_K);
	std::vector<std::array<uint, 256>> t(DILITHIUM_K);
	std::vector<std::array<uint, 256>> t0(DILITHIUM_K);
	std::vector<std::array<uint, 256>> t1(DILITHIUM_K);
	size_t i;
	ushort nonce;

	// expand 32 bytes of randomness into rho, rhoprime and key 
	Rng->Generate(sbuf, 0, 3 * DILITHIUM_SEED_SIZE);

	MemoryTools::Copy(sbuf, 0, rho, 0, rho.size());
	MemoryTools::Copy(sbuf, DILITHIUM_SEED_SIZE, rhoprime, 0, rhoprime.size());
	MemoryTools::Copy(sbuf, (2 * DILITHIUM_SEED_SIZE), key, 0, key.size());
	
	// expand matrix 
	DLTMPolyMath::ExpandMat(mat, rho);
	nonce = 0;

	// sample short vectors s1 and s2 
	for (i = 0; i < DILITHIUM_L; ++i)
	{
		DLTMPolyMath::PolyUniformEta(s1[i], rhoprime, nonce, DILITHIUM_ETA, DILITHIUM_SETABITS);
		++nonce;
	}

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		DLTMPolyMath::PolyUniformEta(s2[i], rhoprime, nonce, DILITHIUM_ETA, DILITHIUM_SETABITS);
		++nonce;
	}

	// matrix-vector multiplication 
	s1hat = s1;
	DLTMPolyMath::PolyVecNtt(s1hat);

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		DLTMPolyMath::PolyVecPointwiseAccInvMontgomery(t[i], mat[i], s1hat);
		DLTMPolyMath::PolyReduce(t[i]);
		DLTMPolyMath::PolyInvNttMontgomery(t[i]);
	}

	// add error vector s2 
	DLTMPolyMath::PolyVecAdd(t, t, s2);

	// extract t1 and write public key 
	DLTMPolyMath::PolyVecFreeze(t);
	DLTMPolyMath::PolyVecPower2Round(t1, t0, t);
	DLTMPolyMath::PackPk(PublicKey, rho, t1, DILITHIUM_POLT1_SIZE_PACKED);

	// compute CRH(rho, t1) and write secret key 
	XOF(PublicKey, 0, DILITHIUM_PUBLICKEY_SIZE, tr, 0, tr.size(), Keccak::KECCAK256_RATE_SIZE);
	DLTMPolyMath::PackSk(PrivateKey, rho, key, tr, s1, s2, t0, DILITHIUM_ETA, DILITHIUM_POLETA_SIZE_PACKED, DILITHIUM_POLT0_SIZE_PACKED);
}

void DLTMK4Q8380417N256::Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<byte> rho(DILITHIUM_SEED_SIZE);
	std::vector<byte> tr(DILITHIUM_CRH_SIZE);
	std::vector<byte> key(DILITHIUM_SEED_SIZE);
	std::vector<byte> mu(DILITHIUM_CRH_SIZE);
	std::vector<byte> rhoprime(DILITHIUM_CRH_SIZE);
	std::vector<byte> sbuf(0);
	std::array<uint, 256> c;
	std::array<uint, 256> chat;
	std::vector<std::vector<std::array<uint, 256>>> mat(DILITHIUM_K, std::vector<std::array<uint, 256>>(DILITHIUM_L));
	std::vector<std::array<uint, 256>> s1(DILITHIUM_L);
	std::vector<std::array<uint, 256>> y(DILITHIUM_L);
	std::vector<std::array<uint, 256>> yhat(DILITHIUM_L);
	std::vector<std::array<uint, 256>> z(DILITHIUM_L);
	std::vector<std::array<uint, 256>> t0(DILITHIUM_K);
	std::vector<std::array<uint, 256>> s2(DILITHIUM_K);
	std::vector<std::array<uint, 256>> w(DILITHIUM_K);
	std::vector<std::array<uint, 256>> w0(DILITHIUM_K);
	std::vector<std::array<uint, 256>> w1(DILITHIUM_K);
	std::vector<std::array<uint, 256>> h(DILITHIUM_K);
	std::vector<std::array<uint, 256>> cs2(DILITHIUM_K);
	std::vector<std::array<uint, 256>> ct0(DILITHIUM_K);
	size_t i;
	uint n;
	ushort nonce;

	nonce = 0;
	DLTMPolyMath::UnpackSk(rho, key, tr, s1, s2, t0, PrivateKey, DILITHIUM_ETA, DILITHIUM_POLETA_SIZE_PACKED, DILITHIUM_POLT0_SIZE_PACKED);

	// copy tr and message into the signedmsg buffer,
	// backwards since message and signedmsg can be equal in SUPERCOP API 
	for (i = 1; i <= Message.size(); ++i)
	{
		Signature[DILITHIUM_SIGNATURE_SIZE + Message.size() - i] = Message[Message.size() - i];
	}

	for (i = 0; i < DILITHIUM_CRH_SIZE; ++i)
	{
		Signature[DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE + i] = tr[i];
	}

	// compute CRH(tr, msg) 
	XOF(Signature, DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE, DILITHIUM_CRH_SIZE + Message.size(), mu, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);

#ifdef DILITHIUM_RANDOMIZED_SIGNING

	Rng->Generate(rhoprime, 0, DILITHIUM_CRH_SIZE);

#else

	sbuf.resize(DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE);
	MemoryTools::Copy(key, 0, sbuf, 0, key.size());
	MemoryTools::Copy(mu, 0, sbuf, key.size(), mu.size());
	XOF(sbuf, 0, DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE, rhoprime, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);

#endif

	// expand matrix and transform vectors 
	DLTMPolyMath::ExpandMat(mat, rho);
	DLTMPolyMath::PolyVecNtt(s1);
	DLTMPolyMath::PolyVecNtt(s2);
	DLTMPolyMath::PolyVecNtt(t0);

	while (true)
	{
		// sample intermediate vector y 
		for (i = 0; i < DILITHIUM_L; ++i)
		{
			DLTMPolyMath::PolyUniformGamma1M1(y[i], rhoprime, nonce);
			++nonce;
		}

		// matrix-vector multiplication 
		yhat = y;
		DLTMPolyMath::PolyVecNtt(yhat);

		for (i = 0; i < DILITHIUM_K; ++i)
		{
			DLTMPolyMath::PolyVecPointwiseAccInvMontgomery(w[i], mat[i], yhat);
			DLTMPolyMath::PolyReduce(w[i]);
			DLTMPolyMath::PolyInvNttMontgomery(w[i]);
		}

		// decompose w and call the random oracle 
		DLTMPolyMath::PolyVecCSubQ(w);
		DLTMPolyMath::PolyVecDecompose(w1, w0, w);
		DLTMPolyMath::Challenge(c, mu, w1);
		chat = c;
		DLTMPolyMath::PolyNtt(chat);

		// check that subtracting cs2 does not change high bits of w and low bits
		// do not reveal secret information 
		for (i = 0; i < DILITHIUM_K; ++i)
		{
			DLTMPolyMath::PolyPointwiseInvMontgomery(cs2[i], chat, s2[i]);
			DLTMPolyMath::PolyInvNttMontgomery(cs2[i]);
		}

		DLTMPolyMath::PolyVecSub(w0, w0, cs2);
		DLTMPolyMath::PolyVecFreeze(w0);

		if (DLTMPolyMath::PolyVecChkNorm(w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA) != 0)
		{
			continue;
		}

		// compute z, reject if it reveals secret 
		for (i = 0; i < DILITHIUM_L; ++i)
		{
			DLTMPolyMath::PolyPointwiseInvMontgomery(z[i], chat, s1[i]);
			DLTMPolyMath::PolyInvNttMontgomery(z[i]);
		}

		DLTMPolyMath::PolyVecAdd(z, z, y);
		DLTMPolyMath::PolyVecFreeze(z);

		if (DLTMPolyMath::PolyVecChkNorm(z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) != 0)
		{
			continue;
		}

		// compute hints for w1 
		for (i = 0; i < DILITHIUM_K; ++i)
		{
			DLTMPolyMath::PolyPointwiseInvMontgomery(ct0[i], chat, t0[i]);
			DLTMPolyMath::PolyInvNttMontgomery(ct0[i]);
		}

		DLTMPolyMath::PolyVecCSubQ(ct0);

		if (DLTMPolyMath::PolyVecChkNorm(ct0, DILITHIUM_GAMMA2) != 0)
		{
			continue;
		}

		DLTMPolyMath::PolyVecAdd(w0, w0, ct0);
		DLTMPolyMath::PolyVecCSubQ(w0);
		n = DLTMPolyMath::PolyVecMakeHint(h, w0, w1);

		if (n > DILITHIUM_OMEGA)
		{
			continue;
		}

		// write signature 
		DLTMPolyMath::PackSig(Signature, z, h, c, DILITHIUM_OMEGA, DILITHIUM_POLZ_SIZE_PACKED);

		break;
	}
}

bool DLTMK4Q8380417N256::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey)
{
	std::vector<std::vector<std::array<uint, 256>>> mat(DILITHIUM_K, std::vector<std::array<uint, 256>>(DILITHIUM_L));
	std::vector<std::array<uint, 256>> t1(DILITHIUM_K);
	std::vector<std::array<uint, 256>> w1(DILITHIUM_K);
	std::vector<std::array<uint, 256>> h(DILITHIUM_K);
	std::vector<std::array<uint, 256>> tmp1(DILITHIUM_K);
	std::vector<std::array<uint, 256>> tmp2(DILITHIUM_K);
	std::array<uint, 256> c;
	std::array<uint, 256> chat;
	std::array<uint, 256> cp;
	size_t i;
	int32_t bsig;
	size_t msglen;

	bsig = 0;

	if (Signature.size() < DILITHIUM_SIGNATURE_SIZE)
	{
		bsig = -1;
	}

	if (bsig == 0)
	{
		std::vector<byte> rho(DILITHIUM_SEED_SIZE);
		std::vector<std::array<uint, 256>> z(DILITHIUM_L);

		msglen = Signature.size() - DILITHIUM_SIGNATURE_SIZE;
		DLTMPolyMath::UnpackPk(rho, t1, PublicKey, DILITHIUM_POLT1_SIZE_PACKED);

		if (DLTMPolyMath::UnpackSig(z, h, c, Signature, DILITHIUM_OMEGA, DILITHIUM_POLZ_SIZE_PACKED) != 0)
		{
			bsig = -1;
		}

		if (bsig == 0)
		{
			if (DLTMPolyMath::PolyVecChkNorm(z, DILITHIUM_GAMMA1 - DILITHIUM_BETA) != 0)
			{
				bsig = -1;
			}

			if (bsig == 0)
			{
				std::vector<byte> mu(DILITHIUM_CRH_SIZE);

				// compute CRH(CRH(rho, t1), msg) using message as "playground" buffer 
				if (Signature != Message)
				{
					for (i = 0; i < msglen; ++i)
					{
						Message[DILITHIUM_SIGNATURE_SIZE + i] = Signature[DILITHIUM_SIGNATURE_SIZE + i];
					}
				}

				XOF(PublicKey, 0, DILITHIUM_PUBLICKEY_SIZE, Message, DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);
				XOF(Message, (DILITHIUM_SIGNATURE_SIZE - DILITHIUM_CRH_SIZE), DILITHIUM_CRH_SIZE + msglen, mu, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);

				// matrix-vector multiplication; compute Az-c2^dt1 
				DLTMPolyMath::ExpandMat(mat, rho);
				DLTMPolyMath::PolyVecNtt(z);

				for (i = 0; i < DILITHIUM_K; ++i)
				{
					DLTMPolyMath::PolyVecPointwiseAccInvMontgomery(tmp1[i], mat[i], z);
				}

				chat = c;
				DLTMPolyMath::PolyNtt(chat);
				DLTMPolyMath::PolyVecShiftL(t1);
				DLTMPolyMath::PolyVecNtt(t1);

				for (i = 0; i < DILITHIUM_K; ++i)
				{
					DLTMPolyMath::PolyPointwiseInvMontgomery(tmp2[i], chat, t1[i]);
				}

				DLTMPolyMath::PolyVecSub(tmp1, tmp1, tmp2);
				DLTMPolyMath::PolyVecReduce(tmp1);
				DLTMPolyMath::PolyVecInvNttMontgomery(tmp1);

				// reconstruct w1 
				DLTMPolyMath::PolyVecCSubQ(tmp1);
				DLTMPolyMath::PolyVecUseHint(w1, tmp1, h);

				// call random oracle and verify challenge 
				DLTMPolyMath::Challenge(cp, mu, w1);

				for (i = 0; i < DILITHIUM_N; ++i)
				{
					if (c[i] != cp[i])
					{
						bsig = -1;
						break;
					}
				}

				if (bsig == 0)
				{
					// all good, copy msg, return 0 
					for (i = 0; i < msglen; ++i)
					{
						Message[i] = Signature[DILITHIUM_SIGNATURE_SIZE + i];
					}
				}
			}
		}
	}

	if (bsig != 0)
	{
		msglen = 0;

		for (i = 0; i < Message.size(); ++i)
		{
			Message[i] = 0;
		}
	}

	return (bsig == 0);
}

void DLTMK4Q8380417N256::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
}

NAMESPACE_DILITHIUMEND