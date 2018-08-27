// Copyright 2018 Stichting Organism
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//External Crates
extern crate blake2_rfc;
extern crate subtle;

//
// PBKDF2 with blake2b
//

// Password-based key derivation as defined here is a function of a 
// password, a salt, and an iteration count, where the latter two quantities need not be kept secret.

// RFC -> https://tools.ietf.org/html/rfc2898

// Modified from:
//  - https://github.com/RustCrypto/password-hashing/blob/master/pbkdf2/src/lib.rs
//  - https://jbp.io/2015/08/11/pbkdf2-performance-matters.html
//  - https://github.com/briansmith/ring/blob/master/tests/pbkdf2_tests.rs
//  - https://github.com/briansmith/ring/blob/master/src/pbkdf2.rs
//  - https://github.com/brycx/orion/blob/master/src/hazardous/pbkdf2.rs


mod errors;

//Internally we use blake2b instead of HMAC-SHA512
use blake2_rfc::blake2b::{Blake2b, blake2b, Blake2bResult};
use self::errors::Error;
use subtle::ConstantTimeEq;


// The output size for the hash function blake2b.
pub const HASH_LEN: usize = 64;


//
//Helper functions
//

//helper that will fill given array with value
#[inline(always)]
fn fill(dest: &mut [u8], value: u8) {
    for d in dest {
        *d = value;
    }
}

//converts a unsigned 32bit integer to a big endien byte representation
#[inline(always)]
fn be_u8_from_u32(value: u32) -> [u8; 4] {
    [
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8
    ]
}

//https://github.com/brycx/orion/blob/master/src/utilities/util.rs
//Compare two equal length slices in constant time, using the
fn compare_ct(a: &[u8], b: &[u8]) -> Option<Error> {
    if a.len() != b.len() {
        return Some(Error::InvalidFormat);
    }

    if a.ct_eq(b).unwrap_u8() == 1 {
        None
    } else {
        return Some(Error::InvalidFormat);
    }
}

/*
From RFC:

PBKDF2 (P, S, c, dkLen)

Options: 
    PRF: underlying pseudorandom function (hLen denotes the length in octets of the pseudorandom function output)

INPUT:
    P: password, an octet string
    S: salt, an octet string
    c: iteration count, a positive integer
    dkLen: intended length in octets of the derived key, a positive integer, at most (2^32 - 1) * hLen

Output:         
    DK: derived key, a dkLen-octet string. The length of the derived key is implied by this.

    Output must be no larger than the digest length * (2**32 - 1), per the PBKDF2 specification.
*/

#[inline]
pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, result: &mut [u8]) -> Option<Error> {
    if iterations < 1 { return Some(Error::InvalidFormat); }
    //64 * (2**32 - 1) = 274877906880
    if result.len() > 274_877_906_880 { return Some(Error::InvalidFormat); }
    if result.is_empty() { return Some(Error::InvalidFormat); }

    //512 bit blake2b
    let output_len = HASH_LEN; 

    //clear output
    fill(result, 0);
    
    //counter
    let mut block_index: u32 = 0;
    
    //loop through on a fix block size basis
    for chunk in result.chunks_mut(output_len) {
        let chunk_len = chunk.len();
        //chunck length must be same as our output length
        if chunk_len < output_len { return Some(Error::InvalidFormat); }

        //guard against counter overlow, you can never be too safe 
        match block_index.checked_add(1) {
            Some(i) => block_index = i,
            None => return Some(Error::InvalidFormat)
        }

        //main body 
        pbkdf2_body(password, salt, iterations, block_index, chunk);

    }//main loop end 

    return None;
}


//function f from rfc spec: F (P, S, c, i)
//P: password
//S: salt
//c: iteration count
//i: block index to compute the block
// N.B.: || means concatenation, ^ means XOR
// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
// U_1 = PRF(password, salt || uint(i))

#[inline(always)]
fn pbkdf2_body(password: &[u8], salt: &[u8], iterations: u32, block_index: u32, out: &mut [u8]){
    // Using the state context, with a key.
    let mut hasher = Blake2b::with_key(HASH_LEN, password);

    //U_1 = PRF (P, S || INT (i)) 
    //sprinkle the salt
    hasher.update(salt);
    //First 4 bytes used for block index Big Endian conversion
    hasher.update(&be_u8_from_u32(block_index));

    //get the hash 
    let mut u_step: Blake2bResult = hasher.finalize();

    let mut remaining = iterations;

    //where the magic happens
    loop {
        for i in 0..out.len() {
            //xor 
            out[i] ^= u_step.as_bytes()[i];
        }

        //Check if it's the last iteration, if yes don't we out
        if remaining == 1 { break; }
        //decrment loop counter 
        remaining -= 1;

        //hash them block

        u_step = blake2b(HASH_LEN, password, &u_step.as_bytes());
    }
  
}


//Verify PBKDF2-BLAKE2b derived key in constant time.
pub fn verify(expected_dk: &[u8], password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Option<Error> {
    match pbkdf2(password, salt, iterations, out) {
        //no errors continue
        None => {
            //do we have a match
            match compare_ct(&out, expected_dk) {
                Some(_) => Some(Error::InvalidFormat),
                None => None
            }
        },
        
        Some(_) => Some(Error::InvalidFormat)
    }
}




#[cfg(test)]
mod tests {
    use errors::Error;
    use super::pbkdf2;

    #[test]
    fn zero_iterations_err() {
        let password = "password".as_bytes();
        let salt = "salt".as_bytes();
        let iterations: u32 = 0;
        let mut okm_out = [0u8; 15];

        assert_eq!(pbkdf2(password, salt, iterations, &mut okm_out), Some(Error::InvalidFormat));
    }

    #[test]
    fn zero_dklen_err() {
        let password = "password".as_bytes();
        let salt = "salt".as_bytes();
        let iterations: u32 = 1;
        let mut okm_out = [0u8; 0];

        assert_eq!(pbkdf2(password, salt, iterations, &mut okm_out), Some(Error::InvalidFormat));
    }


    //
    //Compare function
    //
    #[test]
    fn test_ct_eq_ok() {
        let buf_1 = [0x06; 10];
        let buf_2 = [0x06; 10];

        assert_eq!(super::compare_ct(&buf_1, &buf_2), None);
        assert_eq!(super::compare_ct(&buf_2, &buf_1), None);
    }

    #[test]
    fn test_ct_eq_diff_len() {
        let buf_1 = [0x06; 10];
        let buf_2 = [0x06; 5];

        assert_eq!(super::compare_ct(&buf_1, &buf_2), Some(Error::InvalidFormat));
        assert_eq!(super::compare_ct(&buf_2, &buf_1), Some(Error::InvalidFormat));
    }

    #[test]
    fn test_ct_ne() {
        let buf_1 = [0x06; 10];
        let buf_2 = [0x76; 10];

        assert_eq!(super::compare_ct(&buf_1, &buf_2), Some(Error::InvalidFormat));
        assert_eq!(super::compare_ct(&buf_2, &buf_1), Some(Error::InvalidFormat));
    }

    #[test]
    fn test_ct_ne_reg() {
        assert_eq!(super::compare_ct(&[0], &[0, 1]), Some(Error::InvalidFormat));
        assert_eq!(super::compare_ct(&[0, 1], &[0]),Some(Error::InvalidFormat));
    }

}
