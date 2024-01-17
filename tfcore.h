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
	TFS_KS01 = 14, TFS_KS02 = 16, TFS_KS03 = 25, TFS_KS04 = 33,
	TFS_BS01 = 52, TFS_BS02 = 57, TFS_BS03 = 23, TFS_BS04 = 40,
	TFS_BS05 =  5, TFS_BS06 = 37, TFS_BS07 = 46, TFS_BS08 = 12,
	TFS_BS09 = 58, TFS_BS10 = 22, TFS_BS11 = 32, TFS_BS12 = 32,
};


#ifdef __cplusplus
}
#endif

#endif
