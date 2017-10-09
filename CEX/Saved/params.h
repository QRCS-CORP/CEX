#define GFBITS 12									// m=12
#define SYS_T 62									// t=62

#define PK_NROWS (SYS_T * GFBITS)					// 744 (M * T)
#define PK_NCOLS ((1 << GFBITS) - SYS_T * GFBITS)	// 3352 (1 << M) - (M * T)

#define IRR_BYTES (GFBITS * 8)						// 96
#define COND_BYTES (736 * 8)						// 5888 (736? PK_NROWS + 8) * 8
#define SYND_BYTES (PK_NROWS / 8)					// 93

/*
#define CRYPTO_SECRETKEYBYTES						// 5984 (IRR_BYTES + COND_BYTES)
#define CRYPTO_PUBLICKEYBYTES						// 311736
#define CRYPTO_BYTES								// 109
*/