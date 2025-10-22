This repository contains the source codes for the paper, '**{Some Results on the Aegis Family of ciphers} **'.

## Language Used for code
1. C-language

## Setup

1. To install gcc, use the following command:
	* `sudo apt update`
	* `sudo apt install build-essential`


## File Structure

1.  `1_aes_and_inv_aes.h`: Script for writing necessary functions for encryption and decryption of AES-128.

2.  `2_aegis_128.c`: Script to find the average number of nonce reuses required to recover an internal state of AEGIS-128.

3.  `3_aegis_128L.c`: Script to find the average number of nonce reuses required to recover an internal state of AEGIS-128L.

4.  `4_aegis_256.c`: Script to find the average number of nonce reuses required to recover an internal state of AEGIS-256.




## Usage
1. compile the programme: `gcc file_name.c `
2. run the file:           `./a.out`
