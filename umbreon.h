/**
 * The UMBREON forkcipher mode of operation.
 * 
 * @file umbreon.h
 * Modification of the original code of PAEF from the @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef UMBREON_H
#define UMBREON_H 

int umbreon_encrypt(
	unsigned char *c,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k, unsigned char *adTweakey, unsigned char *msgTweakey
	); 


int umbreon_decrypt(
	unsigned char *m,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
	); 

void printState(unsigned char *state, char *name, size_t size);

#endif /* ifndef PAEF_H */
