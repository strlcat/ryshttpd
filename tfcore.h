#ifndef _THREEFISH_CIPHER_CORE_HEADER
#define _THREEFISH_CIPHER_CORE_HEADER

#ifndef _THREEFISH_CIPHER_DEFINITIONS_HEADER
#error Threefish definitions header is required! Include tfdef.h first.
#endif

#define ROL(x, s, max) ((x << s) | (x >> (-s & (max-1))))
#define ROR(x, s, max) ((x >> s) | (x << (-s & (max-1))))

#define KE_MIX(x, y, k1, k2, sl)				\
	do {							\
		x += k1;					\
		y += x;						\
		y += k2;					\
		x = ROL(x, sl, TF_UNIT_BITS);			\
		x ^= y;						\
	} while (0)

#define BE_MIX(x, y, sl)					\
	do {							\
		x += y;						\
		y = ROL(y, sl, TF_UNIT_BITS);			\
		y ^= x;						\
	} while (0)

#define KD_MIX(x, y, k1, k2, sr)				\
	do {							\
		x ^= y;						\
		x = ROR(x, sr, TF_UNIT_BITS);			\
		y -= x;						\
		y -= k2;					\
		x -= k1;					\
	} while (0)

#define BD_MIX(x, y, sr)					\
	do {							\
		y ^= x;						\
		y = ROR(y, sr, TF_UNIT_BITS);			\
		x -= y;						\
	} while (0)

#define THREEFISH_CONST 0x1bd11bdaa9fc1a22ULL

#ifdef __cplusplus
extern "C" {
#endif

enum tf_rotations {
	TFS_KS01 = 46, TFS_KS02 = 36, TFS_KS03 = 19, TFS_KS04 = 37,
	TFS_KS05 = 39, TFS_KS06 = 30, TFS_KS07 = 34, TFS_KS08 = 24,
	TFS_BS01 = 33, TFS_BS02 = 27, TFS_BS03 = 14, TFS_BS04 = 42,
	TFS_BS05 = 17, TFS_BS06 = 49, TFS_BS07 = 36, TFS_BS08 = 39,
	TFS_BS09 = 44, TFS_BS10 =  9, TFS_BS11 = 54, TFS_BS12 = 56,
	TFS_BS13 = 13, TFS_BS14 = 50, TFS_BS15 = 10, TFS_BS16 = 17,
	TFS_BS17 = 25, TFS_BS18 = 29, TFS_BS19 = 39, TFS_BS20 = 43,
	TFS_BS21 =  8, TFS_BS22 = 35, TFS_BS23 = 56, TFS_BS24 = 22,
};

#ifdef __cplusplus
}
#endif

#endif
