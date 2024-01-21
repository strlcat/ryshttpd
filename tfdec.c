/*
 * ryshttpd -- simple filesharing http server.
 *
 * ryshttpd is copyrighted:
 * Copyright (C) 2018 Andrey Rys. All rights reserved.
 *
 * ryshttpd is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "tfdef.h"
#include "tfcore.h"

#define PROCESS_BLOCKP(x,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10)				\
	do {										\
		BD_MIX(E, T, TFS_BS12); BD_MIX(Z, W, TFS_BS11);				\
		BD_MIX(X, N, TFS_BS10); BD_MIX(V, Y, TFS_BS09);				\
		BD_MIX(Z, N, TFS_BS08); BD_MIX(X, W, TFS_BS07);				\
		BD_MIX(V, T, TFS_BS06); BD_MIX(E, Y, TFS_BS05);				\
		BD_MIX(X, T, TFS_BS04); BD_MIX(V, W, TFS_BS03);				\
		BD_MIX(E, N, TFS_BS02); BD_MIX(Z, Y, TFS_BS01);				\
											\
		KD_MIX(N, V, k8 + x, k9 + k10, TFS_KS04);				\
		KD_MIX(W, E, k5 + k6, k7, TFS_KS03);					\
		KD_MIX(T, Z, k3, k4, TFS_KS02); KD_MIX(Y, X, k1, k2, TFS_KS01);		\
	} while (0)

#define PROCESS_BLOCKN(x,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10)				\
	do {										\
		BD_MIX(E, T, TFS_BS24); BD_MIX(Z, W, TFS_BS23);				\
		BD_MIX(X, N, TFS_BS22); BD_MIX(V, Y, TFS_BS21);				\
		BD_MIX(Z, N, TFS_BS20); BD_MIX(X, W, TFS_BS19);				\
		BD_MIX(V, T, TFS_BS18); BD_MIX(E, Y, TFS_BS17);				\
		BD_MIX(X, T, TFS_BS16); BD_MIX(V, W, TFS_BS15);				\
		BD_MIX(E, N, TFS_BS14); BD_MIX(Z, Y, TFS_BS13);				\
											\
		KD_MIX(N, V, k8 + x, k9 + k10, TFS_KS08);				\
		KD_MIX(W, E, k5 + k6, k7, TFS_KS07);					\
		KD_MIX(T, Z, k3, k4, TFS_KS06); KD_MIX(Y, X, k1, k2, TFS_KS05);		\
	} while (0)

void tf_decrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K)
{
	TF_UNIT_TYPE X, Y, Z, T;
	TF_UNIT_TYPE E, W, V, N;
	TF_UNIT_TYPE K0, K1, K2, K3;
	TF_UNIT_TYPE K4, K5, K6, K7;
	TF_UNIT_TYPE K8, T0, T1, T2;

	X = I[0]; Y = I[1]; Z = I[2]; T = I[3];
	E = I[4]; W = I[5]; V = I[6]; N = I[7];

	K0 = K[ 0]; K1 = K[ 1]; K2 = K[ 2]; K3 = K[ 3];
	K4 = K[ 4]; K5 = K[ 5]; K6 = K[ 6]; K7 = K[ 7];
	K8 = K[ 8]; T0 = K[ 9]; T1 = K[10]; T2 = K[11];

	X -= K0; Y -= K1; Z -= K2; T -= K3;
	E -= K4; W -= K5 + T0; V -= K6 + T1; N -= K7 + 18;

	PROCESS_BLOCKN(17,K0,K8,K2,K1,K4,T2,K3,K6,K5,T0);
	PROCESS_BLOCKP(16,K8,K7,K1,K0,K3,T1,K2,K5,K4,T2);

	PROCESS_BLOCKN(15,K7,K6,K0,K8,K2,T0,K1,K4,K3,T1);
	PROCESS_BLOCKP(14,K6,K5,K8,K7,K1,T2,K0,K3,K2,T0);
	PROCESS_BLOCKN(13,K5,K4,K7,K6,K0,T1,K8,K2,K1,T2);
	PROCESS_BLOCKP(12,K4,K3,K6,K5,K8,T0,K7,K1,K0,T1);

	PROCESS_BLOCKN(11,K3,K2,K5,K4,K7,T2,K6,K0,K8,T0);
	PROCESS_BLOCKP(10,K2,K1,K4,K3,K6,T1,K5,K8,K7,T2);
	PROCESS_BLOCKN( 9,K1,K0,K3,K2,K5,T0,K4,K7,K6,T1);
	PROCESS_BLOCKP( 8,K0,K8,K2,K1,K4,T2,K3,K6,K5,T0);

	PROCESS_BLOCKN( 7,K8,K7,K1,K0,K3,T1,K2,K5,K4,T2);
	PROCESS_BLOCKP( 6,K7,K6,K0,K8,K2,T0,K1,K4,K3,T1);
	PROCESS_BLOCKN( 5,K6,K5,K8,K7,K1,T2,K0,K3,K2,T0);
	PROCESS_BLOCKP( 4,K5,K4,K7,K6,K0,T1,K8,K2,K1,T2);

	PROCESS_BLOCKN( 3,K4,K3,K6,K5,K8,T0,K7,K1,K0,T1);
	PROCESS_BLOCKP( 2,K3,K2,K5,K4,K7,T2,K6,K0,K8,T0);
	PROCESS_BLOCKN( 1,K2,K1,K4,K3,K6,T1,K5,K8,K7,T2);
	PROCESS_BLOCKP( 0,K1,K0,K3,K2,K5,T0,K4,K7,K6,T1);

	O[0] = X; O[1] = Y; O[2] = Z; O[3] = T;
	O[4] = E; O[5] = W; O[6] = V; O[7] = N;
}
