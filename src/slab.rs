use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::bls;
use crate::net::{Ciphertext, CiphertextHash, InvMessage};

pub fn cipher_hash(ciphertext: &Ciphertext) -> CiphertextHash {
    let mut cipher_hash = [0u8; 32];
    let mut hasher = Sha256::new();
    for chunk in ciphertext.chunks(32) {
        hasher.input(chunk);
    }
    cipher_hash.copy_from_slice(&hasher.result());
    cipher_hash
}

// Slab data itself
#[derive(Clone)]
pub struct Slab {
    // Ephemeral key
    pub ephem_public: bls::G1Affine,
    // Hash of derived secret key
    pub scancode: [u8; 4],
    // Encrypted data
    pub ciphertext: Ciphertext,
}

impl Slab {
    pub fn cipher_hash(&self) -> CiphertextHash {
        cipher_hash(&self.ciphertext)
    }
}

// AKA blockchain
// In the future design, it will cost a token to put data
// in the blockchain. For now there is a simple put()
pub struct SlabsManager {
    slabs: Vec<Slab>,
    unsorted_invs: HashMap<u32, InvMessage>,
    ciphertext_pool: HashMap<CiphertextHash, Ciphertext>,
    notify_update: Vec<async_channel::Sender<(u32, Slab)>>,
}

pub type SlabsManagerSafe = async_dup::Arc<async_std::sync::Mutex<SlabsManager>>;

impl SlabsManager {
    pub fn new() -> SlabsManagerSafe {
        async_dup::Arc::new(async_std::sync::Mutex::new(SlabsManager {
            slabs: Vec::new(),
            unsorted_invs: HashMap::new(),
            ciphertext_pool: HashMap::new(),
            notify_update: Vec::new(),
        }))
    }

    pub fn subscribe(&mut self, notify: async_channel::Sender<(u32, Slab)>) {
        self.notify_update.push(notify);
    }

    // Used by the server only, append a new slab
    pub fn add(&mut self, slab: Slab) {
        let ciphertext = slab.ciphertext.clone();
        self.slabs.push(slab);
        self.put_ciphertext(ciphertext);
    }

    pub fn last_height(&self) -> u32 {
        self.slabs.len() as u32
    }

    pub fn has_unsorted_inv(&self, height: u32) -> bool {
        self.unsorted_invs.contains_key(&height)
    }

    pub fn put_unsorted_inv(&mut self, inv: InvMessage) {
        self.unsorted_invs.insert(inv.height, inv);
    }

    pub fn put_ciphertext(&mut self, ciphertext: Ciphertext) {
        self.ciphertext_pool
            .insert(cipher_hash(&ciphertext), ciphertext);
    }

    // This is a client function. Try to construct a slab
    // from the invs we have and append it to our store.
    // Although clients don't need all ciphertexts, we just
    // do this for now for simplicity sake.
    pub async fn organize(&mut self) {
        //debug!("organize() ...");
        while let Some(slab) = self.find_next() {
            let height = self.last_height() + 1;
            for notify_update in &self.notify_update {
                let _ = notify_update.send((height, slab.clone())).await;
            }
            self.slabs.push(slab);
            //debug!("Added slab {}", self.last_height());
        }
        //debug!("organize() [DONE]");
    }

    fn find_next(&mut self) -> Option<Slab> {
        // Height of next block
        let next_height = self.last_height() + 1;

        // Do we have the header?
        if !self.unsorted_invs.contains_key(&next_height) {
            return None;
        }

        let inv = &self.unsorted_invs[&next_height];
        assert!(inv.height > self.last_height());

        // Do we have the body?
        if !self.ciphertext_pool.contains_key(&inv.cipher_hash) {
            return None;
        }

        let inv = self.unsorted_invs.remove(&next_height).unwrap();
        let ciphertext = self.ciphertext_pool[&inv.cipher_hash].clone();

        // Put them together, return a new slab
        Some(Slab {
            ephem_public: inv.ephem_public,
            scancode: inv.scancode,
            ciphertext,
        })
    }

    pub fn inv(&self, height: u32) -> InvMessage {
        assert!(height > 0);
        let slab = &self.slabs[(height - 1) as usize];
        InvMessage {
            height,
            ephem_public: slab.ephem_public.clone(),
            scancode: slab.scancode.clone(),
            cipher_hash: slab.cipher_hash(),
        }
    }

    pub fn min_missing_inv_height(&self) -> u32 {
        *self.unsorted_invs.keys().min().unwrap()
    }
    pub fn invs_are_missing(&self) -> bool {
        match self.unsorted_invs.keys().min() {
            Some(height) => *height != self.last_height() + 1,
            None => false,
        }
    }

    pub fn has_cipher_hash(&self, cipher_hash: &CiphertextHash) -> bool {
        self.ciphertext_pool.contains_key(cipher_hash)
    }

    pub fn get_ciphertext(&self, cipher_hash: &CiphertextHash) -> Option<&Ciphertext> {
        self.ciphertext_pool.get(cipher_hash)
    }
}

#[test]
fn test_slabman() {
    smol::run(async {
        let mut slabman = SlabsManager {
            slabs: Vec::new(),
            unsorted_invs: HashMap::new(),
            ciphertext_pool: HashMap::new(),
            notify_update: Vec::new(),
        };

        fn make_slab(index: u32) -> (InvMessage, Ciphertext) {
            let slab = Slab {
                ephem_public: bls::G1Affine::identity(),
                scancode: [0u8; 4],
                ciphertext: vec![index as u8],
            };

            (
                InvMessage {
                    height: index,
                    ephem_public: slab.ephem_public,
                    scancode: slab.scancode,
                    cipher_hash: slab.cipher_hash(),
                },
                slab.ciphertext,
            )
        }

        let (inv1, ctxt1) = make_slab(1);
        println!("inv1 {}: {}", 1, hex::encode(inv1.cipher_hash));
        let (inv2, ctxt2) = make_slab(2);
        println!("inv2 {}: {}", 2, hex::encode(inv2.cipher_hash));
        let (inv3, ctxt3) = make_slab(3);
        println!("inv3 {}: {}", 3, hex::encode(inv3.cipher_hash));
        let (inv4, ctxt4) = make_slab(4);
        println!("inv4 {}: {}", 4, hex::encode(inv4.cipher_hash));
        let (inv5, ctxt5) = make_slab(5);
        println!("inv5 {}: {}", 5, hex::encode(inv5.cipher_hash));
        let (inv6, ctxt6) = make_slab(6);
        println!("inv6 {}: {}", 6, hex::encode(inv6.cipher_hash));

        assert_eq!(slabman.last_height(), 0);
        slabman.put_unsorted_inv(inv1);
        slabman.put_unsorted_inv(inv2);
        slabman.put_unsorted_inv(inv3);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 0);

        slabman.put_ciphertext(ctxt2);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 0);

        slabman.put_ciphertext(ctxt1);
        assert_eq!(slabman.last_height(), 0);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 2);

        slabman.put_unsorted_inv(inv4);
        slabman.put_unsorted_inv(inv5);
        slabman.put_ciphertext(ctxt4);
        slabman.put_ciphertext(ctxt5);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 2);

        slabman.put_ciphertext(ctxt3);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 5);

        slabman.put_ciphertext(ctxt6);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 5);

        slabman.put_unsorted_inv(inv6);
        slabman.organize().await;
        assert_eq!(slabman.last_height(), 6);
    });
}
