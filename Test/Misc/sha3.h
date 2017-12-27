/**
* \file sha3.h
* \brief Header defining the API for OQS SHA3
* \author John Underhill
* \date December 27, 2017
*
* \remarks For usage examples, see sha3.test.h
*/

#ifndef OQS_SHA3_H
#define OQS_SHA3_H

#include <stdint.h>

#define OQS_SHA3_CSHAKE_DOMAIN 0x04
#define OQS_SHA3_CSHAKE128_RATE 168
#define OQS_SHA3_CSHAKE256_RATE 136
#define OQS_SHA3_SHA3_DOMAIN 0x06
#define OQS_SHA3_SHA3_256_RATE 136
#define OQS_SHA3_SHA3_512_RATE 72
#define OQS_SHA3_SHAKE_DOMAIN 0x1F
#define OQS_SHA3_SHAKE128_RATE 168
#define OQS_SHA3_SHAKE256_RATE 136
#define OQS_SHA3_STATESIZE 25

/* SHA3 */

/**
* \brief Process a message with SHA3-256 and return the hash code in the output byte array.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output The output byte array
* \param input The message input byte array
* \param inplen The number of message bytes to process
*/
void OQS_SHA3_sha3256(uint8_t* output, const uint8_t* input, size_t inplen);

/**
* \brief Process a message with SHA3-512 and return the hash code in the output byte array.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output The output byte array
* \param input The message input byte array
* \param inplen The number of message bytes to process
*/
void OQS_SHA3_sha3512(uint8_t* output, const uint8_t* input, size_t inplen);

/**
* \brief The Keccak absorb function.
* Absorb an input message array directly into the state.
*
* \warning Finalizes the message state, can not be used in consecutive calls.
*
* \param state The function state; must be initialized
* \param rate The rate of absorbsion, in bytes
* \param input The input message byte array
* \param inplen The number of message bytes to process
* \param domain The domain seperation code (0x06 for SHA3, 0x1F for SHAKE)
*/
void OQS_SHA3_keccak_absorb(uint64_t* state, size_t rate, const uint8_t* input, size_t inplen, uint8_t domain);

/**
* \brief The Keccak permute function.
* Permutes the state array, can be used in conjunction with the keccak_absorb function.
*
* \param state The function state; must be initialized
*/
void OQS_SHA3_keccak_permute(uint64_t* state);

/**
* \brief The Keccak squeeze function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param output The output byte array
* \param nblocks The number of blocks to extract
* \param state The function state; must be initialized, and for increased security non-zero
* \param rate The rate of absorbsion, in bytes
*/
void OQS_SHA3_keccak_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state, size_t rate);

/* SHAKE */

/**
* \brief Seed a SHAKE-128 instance, and generate an array of pseudo-random bytes.
*
* \warning The output array length must not be zero.
*
* \param output The output byte array
* \param outlen The number of pseudo-random output bytes to generate
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_shake128(uint8_t* output, size_t outlen, const uint8_t* input, size_t inplen);

/**
* \brief The SHAKE-128 absorb function.
* Absorb and finalize an input seed byte array.
* Should be used in conjunction with the shake128_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls.
*
* \param state The function state; must be initialized, and for increased security non-zero
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_shake128_absorb(uint64_t* state, const uint8_t* input, size_t inplen);

/**
* \brief The SHAKE-128 squeeze function.
* Permutes and extracts the state to an output byte array.
* Should be used in conjunction with the shake128_absorb function.
*
* \warning Output array must be initialized to at a multiple of the byte rate.
*
* \param output The output byte array
* \param nblocks The number of blocks to extract
* \param state The function state; must be initialized
*/
void OQS_SHA3_shake128_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state);

/**
* \brief Seed a SHAKE-256 instance, and generate an array of pseudo-random bytes.
*
* \warning The output array length must not be zero.
*
* \param output The output byte array
* \param outlen The number of pseudo-random output bytes to generate
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_shake256(uint8_t* output, size_t outlen, const uint8_t* input, size_t inplen);

/**
* \brief The SHAKE-256 absorb function.
* Absorb and finalize an input seed byte array.
* Should be used in conjunction with the shake256_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls.
*
* \param state The function state; must be initialized, and for increased security non-zero
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_shake256_absorb(uint64_t* state, const uint8_t* input, size_t inplen);

/**
* \brief The SHAKE-256 squeeze function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param output The output byte array
* \param nblocks The number of blocks to extract
* \param state The function state; must be initialized
*/
void OQS_SHA3_shake256_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state);

/* cSHAKE */

/**
* \brief Seed a cSHAKE-128 instance and generate pseudo-random output.
* Permutes and extracts the state to an output byte array.
*
* \warning This function has a counter period of 2^16
*
* \param output The output byte array
* \param outlen The number of pseudo-random output bytes to generate
* \param cstm The customization bit string
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake128_simple(uint8_t* output, size_t outlen, uint16_t cstm, const uint8_t* input, size_t inplen);

/**
* \brief The cSHAKE-128 simple absorb function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake128_simple_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls.
*
* \param state The function state; must be initialized
* \param cstm The custom domain string
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake128_simple_absorb(uint64_t* state, uint16_t cstm, const uint8_t* input, size_t inplen);

/**
* \brief The cSHAKE-128 simple squeeze function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param output The output byte array
* \param nblocks The number of blocks to extract
* \param state The function state; must be initialized, and for increased security non-zero
*/
void OQS_SHA3_cshake128_simple_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state);

/**
* \brief Seed a cSHAKE-256 instance and generate pseudo-random output.
* Permutes and extracts the state to an output byte array.
*
* \warning This function has a counter period of 2^16
*
* \param output The output byte array
* \param outlen The number of pseudo-random output bytes to generate
* \param cstm The customization bit string
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake256_simple(uint8_t* output, size_t outlen, uint16_t cstm, const uint8_t* input, size_t inplen);

/**
* \brief The cSHAKE-256 simple absorb function.
* Absorb and finalize an input seed directly into the state.
* Should be used in conjunction with the cshake256_simple_squeezeblocks function.
*
* \warning Finalizes the seed state, should not be used in consecutive calls.
*
* \param state The function state; must be initialized
* \param cstm The custom domain string
* \param input The input seed byte array
* \param inplen The number of seed bytes to process
*/
void OQS_SHA3_cshake256_simple_absorb(uint64_t* state, uint16_t cstm, const uint8_t* input, size_t inplen);

/**
* \brief The cSHAKE-256 simple squeeze function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param output The output byte array
* \param nblocks The number of blocks to extract
* \param state The function state; must be initialized, and for increased security non-zero
*/
void OQS_SHA3_cshake256_simple_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state);

#endif
