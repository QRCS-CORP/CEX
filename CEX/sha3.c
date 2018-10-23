/********************************************************************************************
* SHA3-derived functions: SHA3-256, SHA3-512, SHAKE, and cSHAKE
*
* Based on the public domain implementation in crypto_hash/keccakc512/simple/
* from http://bench.cr.yp.to/supercop.html by Ronny Van Keer
* and the public domain "TweetFips202" implementation from https://twitter.com/tweetfips202
* by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe
*
* See NIST Special Publication 800-185 for more information:
* http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
*
* Updated by John Underhill, December 24, 2017
*********************************************************************************************/

#include "sha3.h"

/* Internal */

static void clear8(uint8_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

static void clear64(uint64_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

static size_t left_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	for (v = value, n = 0; v && (n < sizeof(size_t)); ++n, v >>= 8);

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[0] = (uint8_t)n;

	return (size_t)n + 1;
}

static uint64_t load64(const uint8_t* a)
{
	uint64_t r = 0;
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		r |= (uint64_t)a[i] << (8 * i);
	}

	return r;
}

static size_t right_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	for (v = value, n = 0; v && (n < sizeof(size_t)); ++n, v >>= 8);

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		buffer[i - 1] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return (size_t)n + 1;
}

static uint64_t rotl64(const uint64_t x, uint32_t shift)
{
	return (x << shift) | (x >> (64 - shift));
}

static void store64(uint8_t* a, uint64_t x)
{
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		a[i] = x & 0xFF;
		x >>= 8;
	}
}

static void keccak_absorb(uint64_t* state, size_t rate, const uint8_t* input, size_t inplen, uint8_t domain)
{
	uint8_t msg[200];
	size_t i;

	while (inplen >= rate)
	{
		for (i = 0; i < rate / 8; ++i)
		{
			state[i] ^= load64(input + (8 * i));
		}

		keccak_permute(state);

		inplen -= rate;
		input += rate;
	}

	for (i = 0; i < inplen; ++i)
	{
		msg[i] = input[i];
	}

	msg[inplen] = domain;

	for (i = inplen + 1; i < rate; ++i)
	{
		msg[i] = 0;
	}

	msg[rate - 1] |= 128;

	for (i = 0; i < rate / 8; ++i)
	{
		state[i] ^= load64(msg + (8 * i));
	}
}

static void keccak_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks, size_t rate)
{
	size_t i;

	while (nblocks > 0)
	{
		keccak_permute(state);

		for (i = 0; i < (rate >> 3); i++)
		{
			store64(output + 8 * i, state[i]);
		}

		output += rate;
		nblocks--;
	}
}

/* SHA3 */

void keccak_permute(uint64_t* state)
{
	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t Ca;
	uint64_t Ce;
	uint64_t Ci;
	uint64_t Co;
	uint64_t Cu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	/* round 1 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000000000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 2 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000008082ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 3 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x800000000000808AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 4 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008000ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 5 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 6 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000080000001ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 7 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 8 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008009ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 9 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000008AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 10 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000000088ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 11 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080008009ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 12 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x000000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 13 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000008000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 14 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000000000008BULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 15 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008089ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 16 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008003ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 17 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008002ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 18 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000000080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 19 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000800AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 20 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 21 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 22 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 23 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 24 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008008ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);

	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

void sha3_compute256(uint8_t* output, const uint8_t* message, size_t messagelen)
{
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHA3_256_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);
	keccak_absorb(state, SHA3_256_RATE, message, messagelen, SHA3_DOMAIN);
	keccak_squeezeblocks(state, hash, 1, SHA3_256_RATE);

	for (i = 0; i < 32; i++)
	{
		output[i] = hash[i];
	}
}

void sha3_compute512(uint8_t* output, const uint8_t* message, size_t messagelen)
{
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHA3_512_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);
	keccak_absorb(state, SHA3_512_RATE, message, messagelen, SHA3_DOMAIN);
	keccak_squeezeblocks(state, hash, 1, SHA3_512_RATE);

	for (i = 0; i < 64; i++)
	{
		output[i] = hash[i];
	}
}

void sha3_blockupdate(uint64_t* state, size_t rate, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < rate / 8; ++i)
		{
			state[i] ^= load64(message + (8 * i));
		}

		keccak_permute(state);
		message += rate;
		--nblocks;
	}
}

void sha3_finalize(uint64_t* state, size_t rate, const uint8_t* message, size_t messagelen, uint8_t* output)
{
	uint8_t msg[200];
	size_t i;

	if (messagelen >= rate)
	{
		sha3_blockupdate(state, rate, message, messagelen / rate);
		message += (messagelen / rate) * rate;
		messagelen = (messagelen % rate);
	}

	for (i = 0; i < messagelen; ++i)
	{
		msg[i] = message[i];
	}

	msg[messagelen] = SHA3_DOMAIN;

	for (i = messagelen + 1; i < rate; ++i)
	{
		msg[i] = 0;
	}

	msg[rate - 1] |= 128;

	for (i = 0; i < rate / 8; ++i)
	{
		state[i] ^= load64(msg + (8 * i));
	}

	keccak_permute(state);
	messagelen = (((200 - rate) / 2) / 8);

	for (i = 0; i < messagelen; i++)
	{
		store64(output, state[i]);
		output += 8;
	}
}

/* SHAKE */

void shake128(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outputlen / SHAKE128_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHAKE128_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);
	shake128_initialize(state, seed, seedlen);
	shake128_squeezeblocks(state, output, nblocks);

	output += (nblocks * SHAKE128_RATE);
	outputlen -= (nblocks * SHAKE128_RATE);

	if (outputlen != 0)
	{
		shake128_squeezeblocks(state, hash, 1);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void shake128_initialize(uint64_t* state, const uint8_t* seed, size_t seedlen)
{
	keccak_absorb(state, SHAKE128_RATE, seed, seedlen, SHAKE_DOMAIN);
}

void shake128_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state, output, nblocks, SHAKE128_RATE);
}

void shake256(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outputlen / SHAKE256_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHAKE256_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);
	shake256_initialize(state, seed, seedlen);
	shake256_squeezeblocks(state, output, nblocks);

	output += (nblocks * SHAKE256_RATE);
	outputlen -= (nblocks * SHAKE256_RATE);

	if (outputlen != 0)
	{
		shake256_squeezeblocks(state, hash, 1);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void shake256_initialize(uint64_t* state, const uint8_t* seed, size_t seedlen)
{
	keccak_absorb(state, SHAKE256_RATE, seed, seedlen, SHAKE_DOMAIN);
}

void shake256_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state, output, nblocks, SHAKE256_RATE);
}

/* cSHAKE */

void cshake128(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	size_t nblocks = outputlen / CSHAKE128_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[CSHAKE128_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);

	if (customlen + namelen != 0)
	{
		cshake128_initialize(state, name, namelen, custom, customlen);
		cshake128_update(state, seed, seedlen);
	}
	else
	{
		shake128_initialize(state, seed, seedlen);
	}

	cshake128_squeezeblocks(state, output, nblocks);

	output += (nblocks * CSHAKE128_RATE);
	outputlen -= (nblocks * CSHAKE128_RATE);

	if (outputlen != 0)
	{
		cshake128_squeezeblocks(state, hash, 1);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void cshake128_finalize(uint64_t* state, uint8_t* output, size_t outputlen)
{
	size_t i;

	while (outputlen >= CSHAKE128_RATE)
	{
		keccak_permute(state);

		for (i = 0; i < CSHAKE128_RATE / 8; i++)
		{
			store64(output + (8 * i), state[i]);
		}

		outputlen -= CSHAKE128_RATE;
		output += CSHAKE128_RATE;
	}

	if (outputlen != 0)
	{
		uint8_t tmp[CSHAKE128_RATE];

		keccak_permute(state);

		for (i = 0; i < (outputlen / 8) + 1; i++)
		{
			store64(tmp + 8 * i, state[i]);
		}

		for (i = 0; i < outputlen; i++)
		{
			output[i] = tmp[i];
		}
	}
}

void cshake128_initialize(uint64_t* state, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[CSHAKE128_RATE];
	size_t i;
	size_t j;
	size_t offset;

	offset = 0;
	offset = left_encode(pad, CSHAKE128_RATE);
	offset += left_encode(pad + offset, namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; i++)
		{
			if (offset == CSHAKE128_RATE)
			{
				for (j = 0; j < CSHAKE128_RATE / 8; j++)
				{
					state[j] ^= load64(pad + (j * 8));
				}

				keccak_permute(state);
				offset = 0;
			}

			pad[offset] = name[i];
			++offset;
		}
	}

	offset += left_encode(pad + offset, customlen * 8);

	if (customlen != 0)
	{
		for (i = 0; i < customlen; i++)
		{
			if (offset == CSHAKE128_RATE)
			{
				for (j = 0; j < CSHAKE128_RATE / 8; j++)
				{
					state[j] ^= load64(pad + (j * 8));
				}

				keccak_permute(state);
				offset = 0;
			}

			pad[offset] = custom[i];
			++offset;
		}
	}

	clear8(pad + offset, CSHAKE128_RATE - offset);

	for (i = 0; i < CSHAKE128_RATE / 8; i++)
	{
		state[i] ^= load64(pad + (i * 8));
	}

	/* transform the domain string */
	keccak_permute(state);
}

void cshake128_update(uint64_t* state, const uint8_t* seed, size_t seedlen)
{
	keccak_absorb(state, CSHAKE128_RATE, seed, seedlen, CSHAKE_DOMAIN);
}

void cshake128_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state, output, nblocks, CSHAKE128_RATE);
}

void cshake256(uint8_t* output, size_t outputlen, const uint8_t* seed, size_t seedlen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	size_t nblocks = outputlen / CSHAKE256_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[CSHAKE256_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);

	if (customlen + namelen != 0)
	{
		cshake256_initialize(state, name, namelen, custom, customlen);
		cshake256_update(state, seed, seedlen);
	}
	else
	{
		shake256_initialize(state, seed, seedlen);
	}

	cshake256_squeezeblocks(state, output, nblocks);

	output += (nblocks * CSHAKE256_RATE);
	outputlen -= (nblocks * CSHAKE256_RATE);

	if (outputlen != 0)
	{
		cshake256_squeezeblocks(state, hash, 1);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void cshake256_finalize(uint64_t* state, uint8_t* output, size_t outputlen)
{
	size_t i;

	while (outputlen >= CSHAKE256_RATE)
	{
		keccak_permute(state);

		for (i = 0; i < CSHAKE256_RATE / 8; i++)
		{
			store64(output + (8 * i), state[i]);
		}

		outputlen -= CSHAKE256_RATE;
		output += CSHAKE256_RATE;
	}

	if (outputlen != 0)
	{
		uint8_t tmp[CSHAKE256_RATE];

		keccak_permute(state);

		for (i = 0; i < (outputlen / 8) + 1; i++)
		{
			store64(tmp + 8 * i, state[i]);
		}

		for (i = 0; i < outputlen; i++)
		{
			output[i] = tmp[i];
		}
	}
}

void cshake256_initialize(uint64_t* state, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[CSHAKE256_RATE];
	size_t i;
	size_t j;
	size_t offset;

	offset = left_encode(pad, CSHAKE256_RATE);
	offset += left_encode(pad + offset, namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; i++)
		{
			if (offset == CSHAKE256_RATE)
			{
				for (j = 0; j < CSHAKE256_RATE / 8; j++)
				{
					state[j] ^= load64(pad + (j * 8));
				}

				keccak_permute(state);
				offset = 0;
			}

			pad[offset] = name[i];
			++offset;
		}
	}

	offset += left_encode(pad + offset, customlen * 8);

	if (customlen != 0)
	{
		for (i = 0; i < customlen; i++)
		{
			if (offset == CSHAKE256_RATE)
			{
				for (j = 0; j < CSHAKE256_RATE / 8; j++)
				{
					state[j] ^= load64(pad + (j * 8));
				}

				keccak_permute(state);
				offset = 0;
			}

			pad[offset] = custom[i];
			++offset;
		}
	}

	clear8(pad + offset, CSHAKE256_RATE - offset);

	for (i = 0; i < CSHAKE256_RATE / 8; i++)
	{
		state[i] ^= load64(pad + (i * 8));
	}

	/* transform the domain string */
	keccak_permute(state);
}

void cshake256_update(uint64_t* state, const uint8_t* seed, size_t seedlen)
{
	keccak_absorb(state, CSHAKE256_RATE, seed, seedlen, CSHAKE_DOMAIN);
}

void cshake256_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state, output, nblocks, CSHAKE256_RATE);
}

/* Simple cSHAKE */

void cshake128_simple(uint8_t* output, size_t outputlen, uint16_t custom, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outputlen / CSHAKE128_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[CSHAKE128_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);
	cshake128_simple_initialize(state, custom, seed, seedlen);
	cshake128_simple_squeezeblocks(state, output, nblocks);

	output += (nblocks * CSHAKE128_RATE);
	outputlen -= (nblocks * CSHAKE128_RATE);

	if (outputlen != 0)
	{
		cshake128_simple_squeezeblocks(state, hash, 1);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void cshake128_simple_initialize(uint64_t* state, uint16_t custom, const uint8_t* seed, size_t seedlen)
{
	/* Note: This function doesn't align exactly to cSHAKE (SP800-185 3.2), which should produce
	SHAKE output if S and N = zero (sort of a customized custom-SHAKE function).
	Padding is hard-coded as the first 32 bits, plus 16 bits of fixed N, and 16 bits of counter C.
	The short integer optimizes this function for a digest counter configuration */

	uint8_t sep[8];
	sep[0] = 0x01;			/* rate len */
	sep[1] = 0xA8;			/* rate */
	sep[2] = 0x01;			/* name len */
	sep[3] = 0x00;			/* name */
	sep[4] = 0x01;			/* name */
	sep[5] = 0x10;			/* custom len */
	sep[6] = custom & 0xFF;	/* custom */
	sep[7] = custom >> 8;		/* custom */

	state[0] = load64(sep);

	/* transform the domain string */
	keccak_permute(state);
	/* absorb the seed */
	keccak_absorb(state, CSHAKE128_RATE, seed, seedlen, CSHAKE_DOMAIN);
}

void cshake128_simple_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state, output, nblocks, CSHAKE128_RATE);
}

void cshake256_simple(uint8_t* output, size_t outputlen, uint16_t custom, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outputlen / CSHAKE256_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[CSHAKE256_RATE];
	size_t i;

	clear64(state, SHA3_STATESIZE);
	cshake256_simple_initialize(state, custom, seed, seedlen);
	cshake256_simple_squeezeblocks(state, output, nblocks);

	output += (nblocks * CSHAKE256_RATE);
	outputlen -= (nblocks * CSHAKE256_RATE);

	if (outputlen != 0)
	{
		cshake256_simple_squeezeblocks(state, hash, 1);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void cshake256_simple_initialize(uint64_t* state, uint16_t custom, const uint8_t* seed, size_t seedlen)
{
	uint8_t sep[8];
	sep[0] = 0x01; /* bytepad */
	sep[1] = 0x88;
	sep[2] = 0x01;
	sep[3] = 0x00;
	sep[4] = 0x01;
	sep[5] = 0x10; /* bitlen of custom */
	sep[6] = custom & 0xFF;
	sep[7] = custom >> 8;

	state[0] = load64(sep);

	/* transform the domain string */
	keccak_permute(state);

	/* absorb the state */
	keccak_absorb(state, CSHAKE256_RATE, seed, seedlen, CSHAKE_DOMAIN);
}

void cshake256_simple_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state, output, nblocks, CSHAKE256_RATE);
}

/* KMAC */

void kmac128(uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint64_t state[SHA3_STATESIZE];

	kmac128_initialize(state, key, keylen, custom, customlen);

	if (messagelen > CSHAKE128_RATE)
	{
		size_t rndlen = (messagelen / CSHAKE128_RATE) * CSHAKE128_RATE;
		kmac128_blockupdate(state, message, rndlen / CSHAKE128_RATE);
		messagelen = messagelen - rndlen;
		message += rndlen;
	}

	kmac128_finalize(state, output, outputlen, message, messagelen);
}

void kmac128_initialize(uint64_t* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[CSHAKE128_RATE];
	uint8_t name[] = { 75, 77, 65, 67 };
	size_t offset;
	size_t i;

	clear64(state, SHA3_STATESIZE);
	clear8(pad, CSHAKE128_RATE);

	/* stage 1: name + custom */

	offset = left_encode(pad, CSHAKE128_RATE);
	offset += left_encode(pad + offset, 4 * 8);

	for (i = 0; i < 4; i++)
	{
		pad[offset + i] = name[i];
	}

	offset += 4;
	offset += left_encode(pad + offset, customlen * 8);

	for (i = 0; i < customlen; i++)
	{
		pad[offset + i] = custom[i];
	}

	for (i = 0; i < CSHAKE128_RATE / 8; i++)
	{
		state[i] = load64(pad + (i * 8));
	}

	keccak_permute(state);

	/* stage 2: key */

	clear8(pad, CSHAKE128_RATE);
	offset = left_encode(pad, CSHAKE128_RATE);
	offset += left_encode(pad + offset, keylen * 8);

	for (i = 0; i < keylen; i++)
	{
		pad[offset + i] = key[i];
	}

	for (i = 0; i < CSHAKE128_RATE / 8; i++)
	{
		state[i] ^= load64(pad + (i * 8));
	}

	keccak_permute(state);
}

void kmac128_blockupdate(uint64_t* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < CSHAKE128_RATE / 8; ++i)
		{
			state[i] ^= load64(message + (8 * i));
		}

		keccak_permute(state);

		--nblocks;
		message += CSHAKE128_RATE;
	}
}

void kmac128_finalize(uint64_t* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen)
{
	uint8_t buf[sizeof(size_t) + 1];
	uint8_t pad[CSHAKE128_RATE];
	size_t outbitlen;
	size_t i;

	clear8(pad, CSHAKE128_RATE);

	for (i = 0; i < messagelen; i++)
	{
		pad[i] = message[i];
	}

	outbitlen = right_encode(buf, outputlen * 8);

	for (i = 0; i < outbitlen; i++)
	{
		pad[messagelen + i] = buf[i];
	}

	pad[messagelen + outbitlen] = CSHAKE_DOMAIN;
	pad[CSHAKE128_RATE - 1] |= 128;

	for (i = 0; i < CSHAKE128_RATE / 8; i++)
	{
		state[i] ^= load64(pad + (i * 8));
	}

	while (outputlen >= CSHAKE128_RATE)
	{
		keccak_squeezeblocks(state, pad, 1, CSHAKE128_RATE);

		for (i = 0; i < CSHAKE128_RATE; i++)
		{
			output[i] = pad[i];
		}

		output += CSHAKE128_RATE;
		outputlen -= CSHAKE128_RATE;
	}

	if (outputlen > 0)
	{
		keccak_squeezeblocks(state, pad, 1, CSHAKE128_RATE);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = pad[i];
		}
	}
}

void kmac256(uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint64_t state[SHA3_STATESIZE];

	kmac256_initialize(state, key, keylen, custom, customlen);

	if (messagelen > CSHAKE256_RATE)
	{
		size_t rndlen = (messagelen / CSHAKE256_RATE) * CSHAKE256_RATE;
		kmac256_blockupdate(state, message, rndlen / CSHAKE256_RATE);
		messagelen = messagelen - rndlen;
		message += rndlen;
	}

	kmac256_finalize(state, output, outputlen, message, messagelen);
}

void kmac256_initialize(uint64_t* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[CSHAKE256_RATE];
	uint8_t name[] = { 75, 77, 65, 67 };
	size_t offset;
	size_t i;

	clear64(state, SHA3_STATESIZE);
	clear8(pad, CSHAKE256_RATE);

	/* stage 1: name + custom */

	offset = left_encode(pad, CSHAKE256_RATE);
	offset += left_encode(pad + offset, 4 * 8);

	for (i = 0; i < 4; i++)
	{
		pad[offset + i] = name[i];
	}

	offset += 4;
	offset += left_encode(pad + offset, customlen * 8);

	for (i = 0; i < customlen; i++)
	{
		pad[offset + i] = custom[i];
	}

	for (i = 0; i < CSHAKE256_RATE / 8; i++)
	{
		state[i] = load64(pad + (i * 8));
	}

	keccak_permute(state);

	/* stage 2: key */

	clear8(pad, CSHAKE256_RATE);
	offset = left_encode(pad, CSHAKE256_RATE);
	offset += left_encode(pad + offset, keylen * 8);

	for (i = 0; i < keylen; i++)
	{
		pad[offset + i] = key[i];
	}

	for (i = 0; i < CSHAKE256_RATE / 8; i++)
	{
		state[i] ^= load64(pad + (i * 8));
	}

	keccak_permute(state);
}

void kmac256_blockupdate(uint64_t* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < CSHAKE256_RATE / 8; ++i)
		{
			state[i] ^= load64(message + (8 * i));
		}

		keccak_permute(state);

		--nblocks;
		message += CSHAKE256_RATE;
	}
}

void kmac256_finalize(uint64_t* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t messagelen)
{
	uint8_t buf[sizeof(size_t) + 1];
	uint8_t pad[CSHAKE256_RATE];
	size_t outbitlen;
	size_t i;

	clear8(pad, CSHAKE256_RATE);

	for (i = 0; i < messagelen; i++)
	{
		pad[i] = message[i];
	}

	outbitlen = right_encode(buf, outputlen * 8);

	for (i = 0; i < outbitlen; i++)
	{
		pad[messagelen + i] = buf[i];
	}

	pad[messagelen + outbitlen] = CSHAKE_DOMAIN;
	pad[CSHAKE256_RATE - 1] |= 128;

	for (i = 0; i < CSHAKE256_RATE / 8; i++)
	{
		state[i] ^= load64(pad + (i * 8));
	}

	while (outputlen >= CSHAKE256_RATE)
	{
		keccak_squeezeblocks(state, pad, 1, CSHAKE256_RATE);

		for (i = 0; i < CSHAKE256_RATE; i++)
		{
			output[i] = pad[i];
		}

		output += CSHAKE256_RATE;
		outputlen -= CSHAKE256_RATE;
	}

	if (outputlen > 0)
	{
		keccak_squeezeblocks(state, pad, 1, CSHAKE256_RATE);

		for (i = 0; i < outputlen; i++)
		{
			output[i] = pad[i];
		}
	}
}
