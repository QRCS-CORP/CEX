#include "FFTQ40961N1024.h"
#include "BCG.h"
#include <future>
#include "MemUtils.h"
#include "PolyMath.h"
#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_RINGLWE

void FFTQ40961N1024::TestKem()
{
	/*Exclusively For Alice*/
	uint16_t s_alice[2 * M]; /* Alice's Private Key */
	uint64_t mu_alice[MUWORDS]; /* Alice's recovered mu */

								/*Exclusively For Bob*/
	uint64_t mu_bob[MUWORDS]; /* Bob's version of mu */

							  /*Information that gets shared by Alice and Bob*/
	uint16_t b_alice[M]; /* Alice's Public Key */
	uint16_t u[M]; /* Bob's Ring Element from Encapsulation */
	uint64_t cr_v[MUWORDS]; /* Cross Rounding of v */

	KEM1_Generate(s_alice, b_alice);

	KEM1_Encapsulate(u, cr_v, mu_bob, b_alice);

	KEM1_Decapsulate(mu_alice, u, s_alice + M, cr_v);


	int i, flag = 1;
	for (i = 0; i < MUWORDS; ++i)
		flag &= (mu_alice[i] == mu_bob[i]);

	if (flag)
	{
		printf("Successful Key Agreement!\n");
	}
	else
	{
		printf("Failure in Key Agreement :-(\n");
	}
}

NAMESPACE_RINGLWEEND
