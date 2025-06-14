#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<time.h>

//#include "dtype.h"
#include "1_aes_and_inv_aes.h"


/* Length in bytes
 */
#define KEYLEN 16
#define IVLEN  16
#define ADLEN  16
#define MLEN   96
#define TAGLEN 16

////============================================================================

byte const0[16] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62};
byte const1[16] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd};

////=============================================================================

void stateupdate128(byte *S, byte *M){
    ull i,j;
    byte temp[80] , A[16] , B[16];
    
    for(i = 0; i < 80; i++)   temp[i] = S[i];
    
    for(i = 0; i < 16; i++){
        A[i] = temp[64 + i];
        B[i] = temp[i] ^ M[i];
    }

    aesRound(A, B);

    for(i = 0; i < 16; i++)   S[i] = A[i];

    for(j = 0; j < 4; j++)
    {
        for(i = 0; i < 16; i++){
            A[i] = temp[16*j + i];
            B[i] = temp[16*(j+1)+i];
        }
        aesRound(A, B);
        for(i = 0; i < 16; i++)   S[16*(j+1)+i] = A[i];
    }
}

////=================================================================================

void aegis_initialization(byte *S, byte *key, byte *IV){
    ull i,j;
    byte M[16];
    for(i = 0; i < 16; i++){
        S[i]    = key[i] ^ IV[i];
        S[16+i] = const1[i];
        S[32+i] = const0[i];
        S[48+i] = key[i] ^ const0[i];
        S[64+i] = key[i] ^ const1[i];
    }

    for(i = 0; i < 10; i++)
    {
        if(i%2 == 0){
            for(j = 0; j < 16; j++) M[j] = key[j] ; 
            stateupdate128(S, M);
        }
        else{
            for(j = 0; j < 16; j++) M[j] = key[j] ^ IV[j] ; 
            stateupdate128(S, M);
        }
    }
}

////==================================================================================

void adata(byte *S, byte *ad, ull adlen){
    byte M[16];
    ull i,j;
    if(adlen != 0)
    {
        for(i = 0; i < adlen/128 ; i++){
            for(j = 0; j < 16; j++)   M[j] = ad[16*i + j];
            stateupdate128(S,M);
        }
    }
}


////=================================================================================

void encryption(byte *S, byte *P, byte *C, ull msglen){
    ull i,j;
    byte M[16];
    if(msglen != 0)
    {
        for(i = 0; i < msglen/128 ; i++)
        {
            for(j = 0; j < 16; j++){
                C[16*i + j] = P[16*i + j] ^ S[16 + j] ^ S[64 + j] ^ (S[32 + j] & S[48 + j]) ;
                M[j] = P[16*i + j];
            }
            stateupdate128(S,M);
        }
    }
}


////==================================================================================

void finalization(byte *S, byte *tag, ull adlen, ull msglen, ull taglen){

    byte ADlen[8] , MSGlen[8] , temp[16];
    ull i;



    for(i = 0; i < 8; i++){
        ADlen[i] = (adlen >> (8*(7-i))) & 0xff;
        MSGlen[i] = (msglen >> (8*(7-i))) & 0xff;
    }  
    




    for(i = 0; i < 8; i++){
        temp[i] = ADlen[i] ;
        temp[8+i] = MSGlen[i];
    }


    for(i = 0; i < 16; i++)     temp[i] = S[48+i] ^ temp[i];

    //printf("\n temp: "); for(i = 0; i < KEYLEN; i++) printf("%02x ", temp[i]);

    for(i = 0; i <= 6; i++)     stateupdate128(S,temp);

    //printf("\n temp: "); for(i = 0; i < KEYLEN; i++) printf("%02x ", temp[i]);

    for(i = 0; i < 16; i++)     tag[i] = S[i] ^ S[16+i] ^ S[32+i] ^ S[48+i] ^ S[64+i];
    
}


////===============================================================================

void get_key_iv_ad_P(byte *key, byte *iv, byte *ad, byte *P){

    byte KEY[KEYLEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    byte IV[IVLEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    
    byte AD[ADLEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 

    byte PT[MLEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};





//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    int i;
            
    for(i = 0; i < KEYLEN; i++) key[i] = KEY[i];
    for(i = 0; i < IVLEN; i++)  iv[i]  = IV[i];
    for(i = 0; i < ADLEN; i++)  ad[i]  = AD[i];
    for(i = 0; i < MLEN; i++)   P[i]  = PT[i];

}
////==================================================================================

void aegis(byte *key, byte *iv, byte *ad, ull adlen, byte *P, ull msglen, byte *C, byte *tag, ull taglen){

    byte S[80];

    aegis_initialization(S, key, iv);
    adata(S, ad, adlen);
    encryption(S, P, C, msglen);
    finalization(S, tag, adlen, msglen, taglen);


}

/////===============================================================================

int main(int argc, char const *argv[]){

    byte key[KEYLEN], iv[IVLEN], ad[ADLEN], P[MLEN],P_copy[MLEN];
    ull msglen, adlen;
    byte C[MLEN], tag[TAGLEN],C_copy[MLEN];
    ull taglen;

    ull i,j,k,loop,cnt,sum = 0;

	int max_loop = 0, min_loop = 100;
	int flag;
	int l;
	byte M[16],M_copy[16],delta[16];

	byte Z[16];
	byte S[80],S_copy[80];
	byte secret_state[6][80];
	byte recover_state[6][80],temp[16],sub_key[16];

	srand(time(NULL));
            
//    get_key_iv_ad_P(key, iv, ad, P);

	for(cnt = 0; cnt < 1000; cnt++){
		for(i = 0; i < 80; i++)
			for(j = 3; j < 6; j++)
				recover_state[j][i] = 0x00;

		for(i = 0; i < KEYLEN; i++) key[i] = rand()&0xff;
		for(i = 0; i < IVLEN; i++)  iv[i]  = rand()&0xff;
		for(i = 0; i < ADLEN; i++)  ad[i]  = rand()&0xff;
		for(i = 0; i < MLEN; i++)   P[i]  = rand()&0xff;


	//	for(i = 0; i < MLEN; i++)
	//		printf("%.2x",P[i]);
	//	printf("\n");
		
		msglen = MLEN * 8;
	   	adlen = ADLEN * 8;
		aegis_initialization(S, key, iv);
//		adata(S, ad, adlen);
		for(i = 0; i < 80; i++)	S_copy[i] = S[i];

		

		

//		for(i = 0; i < 16; i++)
//			recover_state[i] = 0x00;

		


		for(i = 0; i < msglen/128 ; i++){
			for(j = 0; j < 80; j++)
				secret_state[i][j] = S[j]; 
			for(j = 0; j < 16; j++){
			    C[16*i + j] = P[16*i + j] ^ S[16 + j] ^ S[64 + j] ^ (S[32 + j] & S[48 + j]) ;
			    M[j] = P[16*i + j];
				}
			if((i+1) < (msglen/128))
				stateupdate128(S,M);
			}

//		printf("\nSecret State = ");
//		for(j = 0; j < 80; j++){
//			if(j%16 == 0)
//				printf(" ");
//			printf("%x",secret_state[3][j]);
//			}
//		printState(secret_state,"Secret_state");
//		for(k = 0; k < 5; k++){ 
//			for(j = 0; j < 16; j++) 
//				printf("%.2x",S[16*k+j]);
//			printf("\n");
//			}



		for(i = 0; i < 80; i++)	S[i] = S_copy[i];

		for(loop = 1; loop < 20 ;loop++){
//			printf("\n%lld",loop);
			flag = 0;
			for(l = 3;l < 6; l++){
				for(i = 0; i < 80; i++)	S_copy[i] = S[i];
				for(i = 0; i < MLEN; i++) P_copy[i] = P[i];
				for(i = 0; i < 16; i++){
					delta[i] = rand()&0xff;
					P_copy[i+16*(l-3)] = P_copy[i+16*(l-3)] ^ delta[i];
					P_copy[16*(l-2)+i] = P_copy[16*(l-2)+i] ^ delta[i];
					}
				for(i = 0; i < msglen/128 ; i++){
					for(j = 0; j < 16; j++){
						C_copy[16*i + j] = P_copy[16*i + j] ^ S_copy[16 + j] ^ S_copy[64 + j] ^ (S_copy[32 + j] & S_copy[48 + j]) ;
						M_copy[j] = P_copy[16*i + j];
						}
					if((i+1) < (msglen/128))
						stateupdate128(S_copy,M_copy);
					}

		/*		for(k = 0; k < 5; k++){ 
					for(j = 0; j < 16; j++) 
						printf("%.2x",S_copy[16*k+j]^S[16*k+j]);
					printf("\n");
					}

		*/		for(k = 0; k < 4; k++){
					for(j = 0; j < 4; j++){
						Z[4*k+j] = C[16*l+4*k+j] ^ C_copy[16*l+4*k+j] ^ C[16*(l-1)+4*k+j] ^ C_copy[16*(l-1)+4*k+j];
						recover_state[l][48+4*k+j] = recover_state[l][48+4*k+j] | Z[4*k+j];
						}
					}
				}
				

/////   state recover...............................................................................................................

			for(i = 0; i < 16; i++){
				temp[i] = recover_state[5][48+i];
				sub_key[i] = recover_state[4][48+i];
				}

			invAesRound(temp,sub_key);
			for(i = 0; i < 16; i++){
				recover_state[4][32+i] = temp[i];
				temp[i] = recover_state[4][48+i];
				sub_key[i] = recover_state[3][48+i];
				}
			invAesRound(temp,sub_key);
			for(i = 0; i < 16; i++){
				recover_state[3][32+i] = temp[i];
				temp[i] = recover_state[4][32+i];
				sub_key[i] = recover_state[3][32+i];
				}
			invAesRound(temp,sub_key);
			for(i = 0; i < 16; i++)
				recover_state[3][16+i] = temp[i];

			for(i = 0; i < 16; i++) 
				recover_state[3][64+i] = recover_state[3][16+i] ^ (recover_state[3][32+i] & recover_state[3][48+i]) ^ P[16*3+i] ^ C[16*3+i];

			for(i = 0; i < 16; i++){
				temp[i] = recover_state[3][48+i];
				sub_key[i] = recover_state[3][64+i];
				}

			aesRound(temp,sub_key);
			for(i = 0; i < 16; i++)
				recover_state[4][64+i] = temp[i];

			for(i = 0; i < 16; i++) 
				recover_state[4][16+i] = recover_state[4][64+i] ^ (recover_state[4][32+i] & recover_state[4][48+i]) ^ P[16*4+i] ^ C[16*4+i];

			for(i = 0; i < 16; i++){
				temp[i] = recover_state[4][16+i];
				sub_key[i] = recover_state[3][16+i];
				}
			invAesRound(temp,sub_key);

			for(i = 0; i < 16; i++)
				recover_state[3][i] = temp[i];



//verify.............................................................................................................................

			for( i = 0; i < 80; i++)
				S_copy[i] = recover_state[3][i];
			for(i = 3; i < msglen/128 ; i++){
				for(j = 0; j < 16; j++){
					C_copy[16*i + j] = P[16*i + j] ^ S_copy[16 + j] ^ S_copy[64 + j] ^ (S_copy[32 + j] & S_copy[48 + j]) ;
					M[j] = P[16*i + j];
					}
				if((i+1) < (msglen/128))
					stateupdate128(S_copy,M);
				}
			for(i = 48; i < 96; i++)
				if(C[i] != C_copy[i])
					flag = 1;
			if(flag == 0)
				break;
			}



		sum = sum +loop;
		if(max_loop < loop)
			max_loop = loop;
		if(min_loop > loop)
			min_loop = loop;
		
	}

		printf("\n total experiment = %lld  \n max_re_key = %d \n min_re_key = %d \n average_re_key = %f \n ",cnt,3*max_loop,3*min_loop,3*(float)sum/(float)cnt);


		    
	return 0;
}


