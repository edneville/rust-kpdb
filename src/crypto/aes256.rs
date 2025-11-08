// Copyright (c) 2016-2017,2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::types::{MasterIV, MasterKey, Result};
use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

/// Decrypt the input using the key and initialization vector.
pub fn decrypt(key: &MasterKey, iv: &MasterIV, input: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcDec::new(&key.unsecure().into(), &iv.0.into());
    Ok(cipher.decrypt_padded_vec_mut::<Pkcs7>(input)?)
}

/// Encrypt the input using the key and initialization vector.
pub fn encrypt(key: &MasterKey, iv: &MasterIV, input: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcEnc::new(&key.unsecure().into(), &iv.0.into());
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(input))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::CompositeKey;
    use crate::types::MasterIV;
    use crate::types::MasterKey;
    use crate::types::MasterSeed;
    use crate::types::TransformRounds;
    use crate::types::TransformSeed;
    use crate::types::TransformedKey;

    quickcheck! {
        fn test_decrypt_inverses_encrypt(data: Vec<u8>) -> bool {
            let composite_key = CompositeKey::from_password("secret");
            let rounds = TransformRounds(10);
            let transform_seed = TransformSeed([1u8; 32]);
            let transformed_key = TransformedKey::new(&composite_key, &transform_seed, &rounds);
            let master_seed = MasterSeed([2u8; 32]);
            let master_key = MasterKey::new(&master_seed, &transformed_key);
            let master_iv = MasterIV([3u8; 16]);
            let encrypted = encrypt(&master_key, &master_iv, &data).unwrap();
            let decrypted = decrypt(&master_key, &master_iv, &encrypted).unwrap();
            decrypted == data
        }
    }
}
