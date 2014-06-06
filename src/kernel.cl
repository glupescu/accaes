/*
 * 	Copyright (C) 2013-2014  Lupescu Grigore, grigore.lupescu@gmail.com
 * 	ACCAES - AES encryption on commodity hardware (CPU AESNI, GPGPU)
 *
 *	This file is part of ACCAES.
 *
 *	ACCAES is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	ACCAES is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with ACCAES.  If not, see <http://www.gnu.org/licenses/>.
 */

/*******************************************************
*	Function: SubBytes
*******************************************************/
inline uchar16 SubBytes(uchar16 state, __local uchar AES_SBox[])
{
	return (uchar16)(
		AES_SBox[state.s0],
		AES_SBox[state.s1],
		AES_SBox[state.s2],
		AES_SBox[state.s3],
		AES_SBox[state.s4],
		AES_SBox[state.s5],
		AES_SBox[state.s6],
		AES_SBox[state.s7],
		AES_SBox[state.s8],
		AES_SBox[state.s9],
		AES_SBox[state.sA],
		AES_SBox[state.sB],
		AES_SBox[state.sC],
		AES_SBox[state.sD],
		AES_SBox[state.sE],
		AES_SBox[state.sF]
		);
}

/*******************************************************
*	Function: InverseSubBytes
*******************************************************/
inline uchar16 InverseSubBytes(uchar16 state)
{
	return state;
}

/*******************************************************
*	Function: ShiftRows
*******************************************************/
inline uchar16 ShiftRows(uchar16 state)
{
	return	state.s05AF49E38D27C16B;
}

/*******************************************************
*	Function: InverseShiftRows
*******************************************************/
inline uchar16 InverseShiftRows(uchar16 state)
{
	return	state.s0DA741EB852FC963;
}

/*******************************************************
*	Function: MixColumn
*******************************************************/
inline uchar4 MixColumn (uchar4 state)
{
	uchar4 a;
	uchar4 b;
	uchar4 h;
	
	a = state;
	
    b.s0 = state.s0 << 1; 
	h.s0 = ((state.s0 & 0x80) == 0x80) ? 0xFF : 0x00;
    b.s0 ^= 0x1B & h.s0;
	
	b.s1 = state.s1 << 1; 
	h.s1 = ((state.s1 & 0x80) == 0x80) ? 0xFF : 0x00;
    b.s1 ^= 0x1B & h.s1;
	
	b.s2 = state.s2 << 1;
	h.s2 = ((state.s2 & 0x80) == 0x80) ? 0xFF : 0x00;
    b.s2 ^= 0x1B & h.s2;
	
	b.s3 = state.s3 << 1;
	h.s3 = ((state.s3 & 0x80) == 0x80) ? 0xFF : 0x00;
    b.s3 ^= 0x1B & h.s3;
	
	state.s0 = b.s0 ^ a.s3 ^ a.s2 ^ b.s1 ^ a.s1;
	state.s1 = b.s1 ^ a.s0 ^ a.s3 ^ b.s2 ^ a.s2;
	state.s2 = b.s2 ^ a.s1 ^ a.s0 ^ b.s3 ^ a.s3;
	state.s3 = b.s3 ^ a.s2 ^ a.s1 ^ b.s0 ^ a.s0;

	return state;
}

/*******************************************************
*	Function: InverseMixColumn
*******************************************************/
inline uchar4 InverseMixColumn (uchar4 state)
{
	return state;
}

/*******************************************************
*	Function: MixColumns
*******************************************************/
inline uchar16 MixColumns(uchar16 state)
{
	return (uchar16)(
		MixColumn(state.s0123),
		MixColumn(state.s4567),
		MixColumn(state.s89AB),
		MixColumn(state.sCDEF)
		);
}

/*******************************************************
*	Function: InverseMixColumns
*******************************************************/
inline uchar16 InverseMixColumns(uchar16 state)
{
	return (uchar16)(
		// Each column is multiplied by a known matrix.
		InverseMixColumn(state.s0123),
		InverseMixColumn(state.s4567),
		InverseMixColumn(state.s89AB),
		InverseMixColumn(state.sCDEF)
		);
}

/*******************************************************
*	Function: AddRoundKey
*******************************************************/
inline uchar16 AddRoundKey(uchar16 state, uchar16 key)
{
	return state ^ key;
}

/*******************************************************
*	Function: AES128_Enc
*	Info: AES128 Encrypt
*******************************************************/
__kernel void AES128_Enc(__global uchar16* buf, __global uchar16* keys)
{
		int idx = get_global_id(0);
		__local uchar16 state;

		__local uchar SBox[256];
		SBox[  0]=0x63; SBox[  1]=0x7c; SBox[  2]=0x77; SBox[  3]=0x7b; 
		SBox[  4]=0xf2; SBox[  5]=0x6b; SBox[  6]=0x6f; SBox[  7]=0xc5; 
		SBox[  8]=0x30; SBox[  9]=0x01; SBox[ 10]=0x67; SBox[ 11]=0x2b; 
		SBox[ 12]=0xfe; SBox[ 13]=0xd7; SBox[ 14]=0xab; SBox[ 15]=0x76; 
		SBox[ 16]=0xca; SBox[ 17]=0x82; SBox[ 18]=0xc9; SBox[ 19]=0x7d; 
		SBox[ 20]=0xfa; SBox[ 21]=0x59; SBox[ 22]=0x47; SBox[ 23]=0xf0; 
		SBox[ 24]=0xad; SBox[ 25]=0xd4; SBox[ 26]=0xa2; SBox[ 27]=0xaf; 
		SBox[ 28]=0x9c; SBox[ 29]=0xa4; SBox[ 30]=0x72; SBox[ 31]=0xc0; 
		SBox[ 32]=0xb7; SBox[ 33]=0xfd; SBox[ 34]=0x93; SBox[ 35]=0x26; 
		SBox[ 36]=0x36; SBox[ 37]=0x3f; SBox[ 38]=0xf7; SBox[ 39]=0xcc; 
		SBox[ 40]=0x34; SBox[ 41]=0xa5; SBox[ 42]=0xe5; SBox[ 43]=0xf1; 
		SBox[ 44]=0x71; SBox[ 45]=0xd8; SBox[ 46]=0x31; SBox[ 47]=0x15; 
		SBox[ 48]=0x04; SBox[ 49]=0xc7; SBox[ 50]=0x23; SBox[ 51]=0xc3; 
		SBox[ 52]=0x18; SBox[ 53]=0x96; SBox[ 54]=0x05; SBox[ 55]=0x9a; 
		SBox[ 56]=0x07; SBox[ 57]=0x12; SBox[ 58]=0x80; SBox[ 59]=0xe2; 
		SBox[ 60]=0xeb; SBox[ 61]=0x27; SBox[ 62]=0xb2; SBox[ 63]=0x75; 
		SBox[ 64]=0x09; SBox[ 65]=0x83; SBox[ 66]=0x2c; SBox[ 67]=0x1a; 
		SBox[ 68]=0x1b; SBox[ 69]=0x6e; SBox[ 70]=0x5a; SBox[ 71]=0xa0; 
		SBox[ 72]=0x52; SBox[ 73]=0x3b; SBox[ 74]=0xd6; SBox[ 75]=0xb3; 
		SBox[ 76]=0x29; SBox[ 77]=0xe3; SBox[ 78]=0x2f; SBox[ 79]=0x84; 
		SBox[ 80]=0x53; SBox[ 81]=0xd1; SBox[ 82]=0x00; SBox[ 83]=0xed; 
		SBox[ 84]=0x20; SBox[ 85]=0xfc; SBox[ 86]=0xb1; SBox[ 87]=0x5b; 
		SBox[ 88]=0x6a; SBox[ 89]=0xcb; SBox[ 90]=0xbe; SBox[ 91]=0x39; 
		SBox[ 92]=0x4a; SBox[ 93]=0x4c; SBox[ 94]=0x58; SBox[ 95]=0xcf; 
		SBox[ 96]=0xd0; SBox[ 97]=0xef; SBox[ 98]=0xaa; SBox[ 99]=0xfb; 
		SBox[100]=0x43; SBox[101]=0x4d; SBox[102]=0x33; SBox[103]=0x85; 
		SBox[104]=0x45; SBox[105]=0xf9; SBox[106]=0x02; SBox[107]=0x7f; 
		SBox[108]=0x50; SBox[109]=0x3c; SBox[110]=0x9f; SBox[111]=0xa8; 
		SBox[112]=0x51; SBox[113]=0xa3; SBox[114]=0x40; SBox[115]=0x8f; 
		SBox[116]=0x92; SBox[117]=0x9d; SBox[118]=0x38; SBox[119]=0xf5; 
		SBox[120]=0xbc; SBox[121]=0xb6; SBox[122]=0xda; SBox[123]=0x21; 
		SBox[124]=0x10; SBox[125]=0xff; SBox[126]=0xf3; SBox[127]=0xd2; 
		SBox[128]=0xcd; SBox[129]=0x0c; SBox[130]=0x13; SBox[131]=0xec; 
		SBox[132]=0x5f; SBox[133]=0x97; SBox[134]=0x44; SBox[135]=0x17; 
		SBox[136]=0xc4; SBox[137]=0xa7; SBox[138]=0x7e; SBox[139]=0x3d; 
		SBox[140]=0x64; SBox[141]=0x5d; SBox[142]=0x19; SBox[143]=0x73; 
		SBox[144]=0x60; SBox[145]=0x81; SBox[146]=0x4f; SBox[147]=0xdc; 
		SBox[148]=0x22; SBox[149]=0x2a; SBox[150]=0x90; SBox[151]=0x88; 
		SBox[152]=0x46; SBox[153]=0xee; SBox[154]=0xb8; SBox[155]=0x14; 
		SBox[156]=0xde; SBox[157]=0x5e; SBox[158]=0x0b; SBox[159]=0xdb; 
		SBox[160]=0xe0; SBox[161]=0x32; SBox[162]=0x3a; SBox[163]=0x0a; 
		SBox[164]=0x49; SBox[165]=0x06; SBox[166]=0x24; SBox[167]=0x5c; 
		SBox[168]=0xc2; SBox[169]=0xd3; SBox[170]=0xac; SBox[171]=0x62; 
		SBox[172]=0x91; SBox[173]=0x95; SBox[174]=0xe4; SBox[175]=0x79; 
		SBox[176]=0xe7; SBox[177]=0xc8; SBox[178]=0x37; SBox[179]=0x6d; 
		SBox[180]=0x8d; SBox[181]=0xd5; SBox[182]=0x4e; SBox[183]=0xa9; 
		SBox[184]=0x6c; SBox[185]=0x56; SBox[186]=0xf4; SBox[187]=0xea; 
		SBox[188]=0x65; SBox[189]=0x7a; SBox[190]=0xae; SBox[191]=0x08; 
		SBox[192]=0xba; SBox[193]=0x78; SBox[194]=0x25; SBox[195]=0x2e; 
		SBox[196]=0x1c; SBox[197]=0xa6; SBox[198]=0xb4; SBox[199]=0xc6; 
		SBox[200]=0xe8; SBox[201]=0xdd; SBox[202]=0x74; SBox[203]=0x1f; 
		SBox[204]=0x4b; SBox[205]=0xbd; SBox[206]=0x8b; SBox[207]=0x8a; 
		SBox[208]=0x70; SBox[209]=0x3e; SBox[210]=0xb5; SBox[211]=0x66; 
		SBox[212]=0x48; SBox[213]=0x03; SBox[214]=0xf6; SBox[215]=0x0e; 
		SBox[216]=0x61; SBox[217]=0x35; SBox[218]=0x57; SBox[219]=0xb9; 
		SBox[220]=0x86; SBox[221]=0xc1; SBox[222]=0x1d; SBox[223]=0x9e; 
		SBox[224]=0xe1; SBox[225]=0xf8; SBox[226]=0x98; SBox[227]=0x11; 
		SBox[228]=0x69; SBox[229]=0xd9; SBox[230]=0x8e; SBox[231]=0x94; 
		SBox[232]=0x9b; SBox[233]=0x1e; SBox[234]=0x87; SBox[235]=0xe9; 
		SBox[236]=0xce; SBox[237]=0x55; SBox[238]=0x28; SBox[239]=0xdf; 
		SBox[240]=0x8c; SBox[241]=0xa1; SBox[242]=0x89; SBox[243]=0x0d; 
		SBox[244]=0xbf; SBox[245]=0xe6; SBox[246]=0x42; SBox[247]=0x68; 
		SBox[248]=0x41; SBox[249]=0x99; SBox[250]=0x2d; SBox[251]=0x0f; 
		SBox[252]=0xb0; SBox[253]=0x54; SBox[254]=0xbb; SBox[255]=0x16;

		state = buf[idx];
		state = AddRoundKey(state, keys[0]);

		for (int i = 1; i < 10; i++)
		{
			state = SubBytes(state, SBox);
			state = ShiftRows(state);
			state = MixColumns(state);
			state = AddRoundKey(state, keys[i]);
		}

		state = SubBytes(state, SBox);
		state = ShiftRows(state);
		state = AddRoundKey(state, keys[10]);
		
		buf[idx] = state;
}

/*******************************************************
*	Function: AES128_Dec
*	Info: AES128 Decrypt
*******************************************************/
__kernel void AES128_Dec(__global uchar16* in, __global uchar16* out,
	__global uchar16* keys)
{
		/* TODO */
}

/*******************************************************
*	Function: AES256_Enc
*	Info: AES256 Encrypt
*******************************************************/
__kernel void AES256_Enc(__global uchar16* buf, __global uchar16* keys)
{
		int idx = get_global_id(0);
		__local uchar16 state;

		__local uchar SBox[256];
		SBox[  0]=0x63; SBox[  1]=0x7c; SBox[  2]=0x77; SBox[  3]=0x7b; 
		SBox[  4]=0xf2; SBox[  5]=0x6b; SBox[  6]=0x6f; SBox[  7]=0xc5; 
		SBox[  8]=0x30; SBox[  9]=0x01; SBox[ 10]=0x67; SBox[ 11]=0x2b; 
		SBox[ 12]=0xfe; SBox[ 13]=0xd7; SBox[ 14]=0xab; SBox[ 15]=0x76; 
		SBox[ 16]=0xca; SBox[ 17]=0x82; SBox[ 18]=0xc9; SBox[ 19]=0x7d; 
		SBox[ 20]=0xfa; SBox[ 21]=0x59; SBox[ 22]=0x47; SBox[ 23]=0xf0; 
		SBox[ 24]=0xad; SBox[ 25]=0xd4; SBox[ 26]=0xa2; SBox[ 27]=0xaf; 
		SBox[ 28]=0x9c; SBox[ 29]=0xa4; SBox[ 30]=0x72; SBox[ 31]=0xc0; 
		SBox[ 32]=0xb7; SBox[ 33]=0xfd; SBox[ 34]=0x93; SBox[ 35]=0x26; 
		SBox[ 36]=0x36; SBox[ 37]=0x3f; SBox[ 38]=0xf7; SBox[ 39]=0xcc; 
		SBox[ 40]=0x34; SBox[ 41]=0xa5; SBox[ 42]=0xe5; SBox[ 43]=0xf1; 
		SBox[ 44]=0x71; SBox[ 45]=0xd8; SBox[ 46]=0x31; SBox[ 47]=0x15; 
		SBox[ 48]=0x04; SBox[ 49]=0xc7; SBox[ 50]=0x23; SBox[ 51]=0xc3; 
		SBox[ 52]=0x18; SBox[ 53]=0x96; SBox[ 54]=0x05; SBox[ 55]=0x9a; 
		SBox[ 56]=0x07; SBox[ 57]=0x12; SBox[ 58]=0x80; SBox[ 59]=0xe2; 
		SBox[ 60]=0xeb; SBox[ 61]=0x27; SBox[ 62]=0xb2; SBox[ 63]=0x75; 
		SBox[ 64]=0x09; SBox[ 65]=0x83; SBox[ 66]=0x2c; SBox[ 67]=0x1a; 
		SBox[ 68]=0x1b; SBox[ 69]=0x6e; SBox[ 70]=0x5a; SBox[ 71]=0xa0; 
		SBox[ 72]=0x52; SBox[ 73]=0x3b; SBox[ 74]=0xd6; SBox[ 75]=0xb3; 
		SBox[ 76]=0x29; SBox[ 77]=0xe3; SBox[ 78]=0x2f; SBox[ 79]=0x84; 
		SBox[ 80]=0x53; SBox[ 81]=0xd1; SBox[ 82]=0x00; SBox[ 83]=0xed; 
		SBox[ 84]=0x20; SBox[ 85]=0xfc; SBox[ 86]=0xb1; SBox[ 87]=0x5b; 
		SBox[ 88]=0x6a; SBox[ 89]=0xcb; SBox[ 90]=0xbe; SBox[ 91]=0x39; 
		SBox[ 92]=0x4a; SBox[ 93]=0x4c; SBox[ 94]=0x58; SBox[ 95]=0xcf; 
		SBox[ 96]=0xd0; SBox[ 97]=0xef; SBox[ 98]=0xaa; SBox[ 99]=0xfb; 
		SBox[100]=0x43; SBox[101]=0x4d; SBox[102]=0x33; SBox[103]=0x85; 
		SBox[104]=0x45; SBox[105]=0xf9; SBox[106]=0x02; SBox[107]=0x7f; 
		SBox[108]=0x50; SBox[109]=0x3c; SBox[110]=0x9f; SBox[111]=0xa8; 
		SBox[112]=0x51; SBox[113]=0xa3; SBox[114]=0x40; SBox[115]=0x8f; 
		SBox[116]=0x92; SBox[117]=0x9d; SBox[118]=0x38; SBox[119]=0xf5; 
		SBox[120]=0xbc; SBox[121]=0xb6; SBox[122]=0xda; SBox[123]=0x21; 
		SBox[124]=0x10; SBox[125]=0xff; SBox[126]=0xf3; SBox[127]=0xd2; 
		SBox[128]=0xcd; SBox[129]=0x0c; SBox[130]=0x13; SBox[131]=0xec; 
		SBox[132]=0x5f; SBox[133]=0x97; SBox[134]=0x44; SBox[135]=0x17; 
		SBox[136]=0xc4; SBox[137]=0xa7; SBox[138]=0x7e; SBox[139]=0x3d; 
		SBox[140]=0x64; SBox[141]=0x5d; SBox[142]=0x19; SBox[143]=0x73; 
		SBox[144]=0x60; SBox[145]=0x81; SBox[146]=0x4f; SBox[147]=0xdc; 
		SBox[148]=0x22; SBox[149]=0x2a; SBox[150]=0x90; SBox[151]=0x88; 
		SBox[152]=0x46; SBox[153]=0xee; SBox[154]=0xb8; SBox[155]=0x14; 
		SBox[156]=0xde; SBox[157]=0x5e; SBox[158]=0x0b; SBox[159]=0xdb; 
		SBox[160]=0xe0; SBox[161]=0x32; SBox[162]=0x3a; SBox[163]=0x0a; 
		SBox[164]=0x49; SBox[165]=0x06; SBox[166]=0x24; SBox[167]=0x5c; 
		SBox[168]=0xc2; SBox[169]=0xd3; SBox[170]=0xac; SBox[171]=0x62; 
		SBox[172]=0x91; SBox[173]=0x95; SBox[174]=0xe4; SBox[175]=0x79; 
		SBox[176]=0xe7; SBox[177]=0xc8; SBox[178]=0x37; SBox[179]=0x6d; 
		SBox[180]=0x8d; SBox[181]=0xd5; SBox[182]=0x4e; SBox[183]=0xa9; 
		SBox[184]=0x6c; SBox[185]=0x56; SBox[186]=0xf4; SBox[187]=0xea; 
		SBox[188]=0x65; SBox[189]=0x7a; SBox[190]=0xae; SBox[191]=0x08; 
		SBox[192]=0xba; SBox[193]=0x78; SBox[194]=0x25; SBox[195]=0x2e; 
		SBox[196]=0x1c; SBox[197]=0xa6; SBox[198]=0xb4; SBox[199]=0xc6; 
		SBox[200]=0xe8; SBox[201]=0xdd; SBox[202]=0x74; SBox[203]=0x1f; 
		SBox[204]=0x4b; SBox[205]=0xbd; SBox[206]=0x8b; SBox[207]=0x8a; 
		SBox[208]=0x70; SBox[209]=0x3e; SBox[210]=0xb5; SBox[211]=0x66; 
		SBox[212]=0x48; SBox[213]=0x03; SBox[214]=0xf6; SBox[215]=0x0e; 
		SBox[216]=0x61; SBox[217]=0x35; SBox[218]=0x57; SBox[219]=0xb9; 
		SBox[220]=0x86; SBox[221]=0xc1; SBox[222]=0x1d; SBox[223]=0x9e; 
		SBox[224]=0xe1; SBox[225]=0xf8; SBox[226]=0x98; SBox[227]=0x11; 
		SBox[228]=0x69; SBox[229]=0xd9; SBox[230]=0x8e; SBox[231]=0x94; 
		SBox[232]=0x9b; SBox[233]=0x1e; SBox[234]=0x87; SBox[235]=0xe9; 
		SBox[236]=0xce; SBox[237]=0x55; SBox[238]=0x28; SBox[239]=0xdf; 
		SBox[240]=0x8c; SBox[241]=0xa1; SBox[242]=0x89; SBox[243]=0x0d; 
		SBox[244]=0xbf; SBox[245]=0xe6; SBox[246]=0x42; SBox[247]=0x68; 
		SBox[248]=0x41; SBox[249]=0x99; SBox[250]=0x2d; SBox[251]=0x0f; 
		SBox[252]=0xb0; SBox[253]=0x54; SBox[254]=0xbb; SBox[255]=0x16;

		state = buf[idx];
		state = AddRoundKey(state, keys[0]);

		for (int i = 1; i < 14; i++)
		{
			state = SubBytes(state, SBox);
			state = ShiftRows(state);
			state = MixColumns(state);
			state = AddRoundKey(state, keys[i]);
		}

		state = SubBytes(state, SBox);
		state = ShiftRows(state);
		state = AddRoundKey(state, keys[14]);
		
		buf[idx] = state;
}


/*******************************************************
*	Function: AES256_Dec
*	Info: AES256 Decrypt
*******************************************************/
__kernel void AES256_Dec(__global uchar16* in, __global uchar16* out,
	__global uchar16* keys)
{
		/* TODO */
}
