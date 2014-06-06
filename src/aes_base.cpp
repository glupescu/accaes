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

#include "main.h"

/*******************************************************
*	CLASS AES_BENCH - to be inherited
*******************************************************/

AES_BASE::AES_BASE(){ /* base does no initialization */ }

AES_BASE::AES_BASE(uchar* buf_in, uchar* buf_out, uint buf_len,
		uchar* key, uint key_len, string aes_method){

	/* init params */
	this->buf_in	= buf_in;
	this->buf_out	= buf_out;
	this->key		= key;
	this->key_len	= key_len;
	this->buf_len	= buf_len;
	this->aes_method = aes_method;
}
