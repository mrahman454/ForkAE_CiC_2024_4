#include<stdio.h>
#include<stdint.h>
#include "paef.h"
#include "forkskinny.h"

//gcc main.c paef.c forkskinny.c helpers.c skinny_round.c -o a.out   //run config    
int main(){

    unsigned char c[100]; // Adjust the size of c as needed
    unsigned char m[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Message array
    unsigned long long mlen = sizeof(m); // Length of message array
    
    unsigned char ad[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}; // Associated data array
    unsigned long long adlen = sizeof(ad); // Length of associated data array
    
    unsigned char npub[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}; // Nonce (6 bytes)
    
    unsigned char k[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // Key array (16 bytes)

    unsigned char adTweakey[24];
    unsigned char msgTweakey[24];


    paef_encrypt(c,m,mlen,ad,adlen,npub,k,adTweakey, msgTweakey);

    printf("\n----------------------------------------------------------------------------------------");
    printf("\nFirst Set");
    printf("\n----------------------------------------------------------------------------------------");
    printState(k, "key1",16);
    printState(npub, "nonce",6);
    printState(ad, "AD1", 8);
    printState(m, "M1", 8);
    printState(c, "CT-Tag", 16);
    printf("\n----------------------------------------------------------------------------------------");
    printf("\n----------------------------------------------------------------------------------------\n");


    

    unsigned char tempC[100];

    unsigned char k2[] = {0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}; // Key array (16 bytes)
    paef_encrypt(tempC,m,mlen,ad,adlen,npub,k2,adTweakey, msgTweakey);


    unsigned char runningTag[8];
    unsigned char c_out[8];
    unsigned char m_out[8];
    unsigned char tag[8];
    unsigned char ciphertext[8];

    unsigned char newMsg[8];
    unsigned char newAD[8];

    for(int i=0;i<8;i++){
        tag[i]=c[8+i];
        ciphertext[i]=c[i];
    }
    
    forkInvert(newMsg,c_out,tag,msgTweakey,1,INV_BOTH);

    for(int i=0;i<8;i++){
        runningTag[i]=c_out[i]^c[i];
    }

    forkInvert(newAD,c_out,runningTag,adTweakey,1,INV_BOTH);

        unsigned char c2[100];
    paef_encrypt(c2,newMsg, mlen,newAD,adlen,npub,k2,adTweakey,msgTweakey);

    printf("\n----------------------------------------------------------------------------------------");
    printf("\nSecond Set");
    printf("\n----------------------------------------------------------------------------------------");
    printState(k2, "key2",16);
    printState(npub, "nonce",6);
    printState(newAD, "AD2", 8);
    printState(newMsg, "M2", 8);
    printState(c2, "CT-Tag", 16);
    printf("\n----------------------------------------------------------------------------------------");
    printf("\n----------------------------------------------------------------------------------------\n");


}