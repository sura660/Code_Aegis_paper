#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<time.h>

#include "1_aes_and_inv_aes.h"


/* Length in bytes
 */
#define KEYLEN 16
#define IVLEN  16
#define ADLEN  0
#define MLEN   192
#define TAGLEN 16

////============================================================================

byte const0[16] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62};
byte const1[16] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd};

////=============================================================================

void stateupdate128l(byte *S, byte *M1, byte *M2){
    ull i,j;
    byte temp[128] , A[16] , B[16];
    
    for(i = 0; i < 128; i++)   temp[i] = S[i];
    
    for(i = 0; i < 16; i++){
        A[i] = temp[112 + i];
        B[i] = temp[i] ^ M1[i];
    }

    aesRound(A, B);

    for(i = 0; i < 16; i++)   S[i] = A[i];

    for(j = 0; j < 3; j++)
    {
        for(i = 0; i < 16; i++){
            A[i] = temp[16*j + i];
            B[i] = temp[16*(j+1)+i];
        }
        aesRound(A, B);
        for(i = 0; i < 16; i++)   S[16*(j+1)+i] = A[i];
    }


	for(i = 0; i < 16; i++){
        A[i] = temp[48 + i];
        B[i] = temp[64 + i] ^ M2[i];
    }

    aesRound(A, B);

    for(i = 0; i < 16; i++)   S[64+i] = A[i];

    for(j = 4; j < 7; j++)
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
    byte M1[16],M2[16];
    for(i = 0; i < 16; i++){
        S[i]    = key[i] ^ IV[i];
        S[16+i] = const1[i];
        S[32+i] = const0[i];
		S[48+i] = const1[i];
		S[64+i] = key[i] ^ IV[i];
        S[80+i] = key[i] ^ const0[i];
        S[96+i] = key[i] ^ const1[i];
		S[112+i] = key[i] ^ const0[i];
    }

    for(i = 0; i < 10; i++){
        for(j = 0; j < 16; j++){
			M1[j] = IV[j];
			M2[j] = key[j];	 
            stateupdate128l(S, M1,M2);
    	}
	}
}

////=================================================================================

void encryption(byte *S, byte *P, byte *C, ull msglen){
    ull i,j;
    byte M1[16],M2[16];
    if(msglen != 0)
    {
        for(i = 0; i < msglen/256 ; i++)
        {
            for(j = 0; j < 16; j++){
                C[32*i + j] = P[32*i + j] ^ S[16 + j] ^ S[96 + j] ^ (S[32 + j] & S[48 + j]) ;
				C[32*i + 16 +  j] = P[32*i + 16 + j] ^ S[32 + j] ^ S[80 + j] ^ (S[96 + j] & S[112 + j]) ;
                M1[j] = P[32*i + j];
				M2[j] = P[32*i + 16 + j];
            }
            stateupdate128l(S,M1,M2);
        }
    }
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
	byte M1[16],M2[16],M_copy[16],delta[16];

	byte Z[16];
	byte S[128],S_copy[128];
	byte secret_state[6][128];
	byte recover_state[6][128],temp[16],sub_key[16];

	srand(time(NULL));
            
//    get_key_iv_ad_P(key, iv, ad, P);

	for(cnt = 0; cnt < 1000; cnt++){
		for(i = 0; i < 128; i++)
			for(j = 3; j < 6; j++)
				recover_state[j][i] = 0x00;

		for(i = 0; i < KEYLEN; i++) key[i] = rand()&0xff;
		for(i = 0; i < IVLEN; i++)  iv[i]  = rand()&0xff;
//		for(i = 0; i < ADLEN; i++)  ad[i]  = rand()&0xff;
		for(i = 0; i < MLEN; i++)   P[i]  = rand()&0xff;


	//	for(i = 0; i < MLEN; i++)
	//		printf("%.2x",P[i]);
	//	printf("\n");
		
		msglen = MLEN * 8;
//	   	adlen = ADLEN * 8;
		aegis_initialization(S, key, iv);
//		adata(S, ad, adlen);
		for(i = 0; i < 128; i++)	S_copy[i] = S[i];

		

		

//		for(i = 0; i < 16; i++)
//			recover_state[i] = 0x00;

		


		for(i = 0; i < msglen/256 ; i++){
			for(j = 0; j < 128; j++)
				secret_state[i][j] = S[j]; 
			for(j = 0; j < 16; j++){
			    C[32*i + j] = P[32*i + j] ^ S[16 + j] ^ S[96 + j] ^ (S[32 + j] & S[48 + j]) ;
				C[32*i + 16 +  j] = P[32*i + 16 + j] ^ S[32 + j] ^ S[80 + j] ^ (S[96 + j] & S[112 + j]) ;
                M1[j] = P[32*i + j];
				M2[j] = P[32*i + 16 + j];
            	}
			if((i+1) < (msglen/256))
				stateupdate128l(S,M1,M2);
			}




		for(i = 0; i < 128; i++)	S[i] = S_copy[i];

		for(loop = 1; ;loop++){
			flag = 0;


			for(l = 3;l < 6; l++){
				for(i = 0; i < 128; i++)	S_copy[i] = S[i];
				for(i = 0; i < MLEN; i++) P_copy[i] = P[i];
				for(i = 0; i < 16; i++){
					delta[i] = rand()&0xff;
					P_copy[i+32*(l-3)] = P_copy[i+32*(l-3)] ^ delta[i];
					P_copy[32*(l-2)+i] = P_copy[32*(l-2)+i] ^ delta[i];
					}
				for(i = 0; i < msglen/256 ; i++){
					for(j = 0; j < 16; j++){
						C_copy[32*i + j] = P_copy[32*i + j] ^ S_copy[16 + j] ^ S_copy[96 + j] ^ (S_copy[32 + j] & S_copy[48 + j]) ;
						C_copy[32*i + 16 +  j] = P_copy[32*i + 16 + j] ^ S_copy[32 + j] ^ S_copy[80 + j] ^ (S_copy[96 + j] & S_copy[112 + j]) ;
                		M1[j] = P_copy[32*i + j];
						M2[j] = P_copy[32*i + 16 + j];
						}
					if((i+1) < (msglen/256))
						stateupdate128l(S_copy,M1,M2);
					}


				for(k = 0; k < 4; k++){
					for(j = 0; j < 4; j++){
						Z[4*k+j] = C[32*l+4*k+j] ^ C_copy[32*l+4*k+j] ^ C[32*(l-1)+4*k+j] ^ C_copy[32*(l-1)+4*k+j];
						recover_state[l][48+4*k+j] = recover_state[l][48+4*k+j] | Z[4*k+j];
						}
					}
				}
				
////////////////////////////// recover s7//////////////////////////////////
				l=3;
				for(i = 0; i < 128; i++)	S_copy[i] = S[i];
				for(i = 0; i < MLEN; i++) P_copy[i] = P[i];
				for(i = 0; i < 16; i++){
					delta[i] = rand()&0xff;
					P_copy[i+32*(l-3)+16] = P_copy[i+32*(l-3)+16] ^ delta[i];
					P_copy[32*(l-2)+i+16] = P_copy[32*(l-2)+i+16] ^ delta[i];
					}
				for(i = 0; i < msglen/256 ; i++){
					for(j = 0; j < 16; j++){
						C_copy[32*i + j] = P_copy[32*i + j] ^ S_copy[16 + j] ^ S_copy[96 + j] ^ (S_copy[32 + j] & S_copy[48 + j]) ;
						C_copy[32*i + 16 +  j] = P_copy[32*i + 16 + j] ^ S_copy[32 + j] ^ S_copy[80 + j] ^ (S_copy[96 + j] & S_copy[112 + j]) ;
                		M1[j] = P_copy[32*i + j];
						M2[j] = P_copy[32*i + 16 + j];
						}

					if((i+1) < (msglen/256))
						stateupdate128l(S_copy,M1,M2);
					}


				for(k = 0; k < 4; k++){
					for(j = 0; j < 4; j++){
						Z[4*k+j] = C[32*l+4*k+j+16] ^ C_copy[32*l+4*k+j+16] ^ C[32*(l-1)+4*k+j+16] ^ C_copy[32*(l-1)+4*k+j+16];
						recover_state[l][112+4*k+j] = recover_state[l][112+4*k+j] | Z[4*k+j];
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
				recover_state[3][96+i] = recover_state[3][16+i] ^ (recover_state[3][32+i] & recover_state[3][48+i]) ^ P[32*3+i] ^ C[32*3+i];

			for(i = 0; i < 16; i++) 
				recover_state[3][80+i] = recover_state[3][32+i] ^ (recover_state[3][96+i] & recover_state[3][112+i]) ^ P[32*3+i+16] ^ C[32*3+i+16];

			for(i = 0; i < 16; i++){
				temp[i] = recover_state[3][96+i];
				sub_key[i] = recover_state[3][112+i];
				}

			aesRound(temp,sub_key);
			for(i = 0; i < 16; i++){
				recover_state[4][112+i] = temp[i];
				temp[i] = recover_state[3][80+i];
				sub_key[i] = recover_state[3][96+i];
				}

			aesRound(temp,sub_key);
			for(i = 0; i < 16; i++)
				recover_state[4][96+i] = temp[i];


			for(i = 0; i < 16; i++) 
				recover_state[4][80+i] = recover_state[4][32+i] ^ (recover_state[4][96+i] & recover_state[4][112+i]) ^ P[32*4+i+16] ^ C[32*4+i+16];


			for(i = 0; i < 16; i++){
				temp[i] = recover_state[4][80+i];
				sub_key[i] = recover_state[3][80+i];
				}
			invAesRound(temp,sub_key);

			for(i = 0; i < 16; i++)
				recover_state[3][64+i] = temp[i];

			for(i = 0; i < 16; i++) 
				recover_state[4][16+i] = recover_state[4][96+i] ^ (recover_state[4][32+i] & recover_state[4][48+i]) ^ P[32*4+i] ^ C[32*4+i];


			for(i = 0; i < 16; i++){
				temp[i] = recover_state[4][16+i];
				sub_key[i] = recover_state[3][16+i];
				}
			invAesRound(temp,sub_key);

			for(i = 0; i < 16; i++)
				recover_state[3][i] = temp[i];


//verify.............................................................................................................................

			for( i = 0; i < 128; i++)
				S_copy[i] = recover_state[3][i];
			for(i = 3; i < msglen/256 ; i++){
				for(j = 0; j < 16; j++){
					C_copy[32*i + j] = P[32*i + j] ^ S_copy[16 + j] ^ S_copy[96 + j] ^ (S_copy[32 + j] & S_copy[48 + j]) ;
					C_copy[32*i + 16 +  j] = P[32*i + 16 + j] ^ S_copy[32 + j] ^ S_copy[80 + j] ^ (S_copy[96 + j] & S_copy[112 + j]) ;
               		M1[j] = P[32*i + j];
					M2[j] = P[32*i + 16 + j];
					}
				if((i+1) < (msglen/256))
					stateupdate128l(S_copy,M1,M2);
				}
			for(i = 48*2; i < 96*2; i++)
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

		printf("\n total experiment = %lld  \n max_re_key = %d \n min_re_key = %d \n average_re_key = %f \n ",cnt,4*max_loop,4*min_loop,4*(float)sum/(float)cnt);


		    
	return 0;
}

