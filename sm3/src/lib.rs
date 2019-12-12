#[derive(Default)]
pub struct SM3 {
    digest: [u32; 8],
    length: u64,
    unhandle_msg: Vec<u8>,
}

impl SM3 {
    pub fn ff0(&self, x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    pub fn ff1(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    pub fn gg0(&self, x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    pub fn gg1(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    pub fn p0(&self, x: u32) -> u32 {
        x ^ self.left_rotate(x, 9) ^ self.left_rotate(x, 17)
    }

    pub fn p1(&self, x: u32) -> u32 {
        x ^ self.left_rotate(x, 15) ^ self.left_rotate(x, 23)
    }

    pub fn left_rotate(&self, x: u32, i: u32) -> u32 {
        x.rotate_left(i % 32) | x.rotate_right(32 - i % 32)
    }

    pub fn pad(&self) -> Vec<u8> {
        let mut msg = self.unhandle_msg.clone();
        msg.push(0x80);
        let blockSize = 64;
        while msg.len() % blockSize != 56 {
            msg.push(0x00);
        }
        msg.push((self.length >> 56 & 0xff) as u8);
        msg.push((self.length >> 48 & 0xff) as u8);
        msg.push((self.length >> 40 & 0xff) as u8);
        msg.push((self.length >> 32 & 0xff) as u8);
        msg.push((self.length >> 24 & 0xff) as u8);
        msg.push((self.length >> 16 & 0xff) as u8);
        msg.push((self.length >> 8 & 0xff) as u8);
        msg.push((self.length >> 0 & 0xff) as u8);

        if msg.len() % 64 != 0 {
            panic!("------SM3 Pad: error msgLen");
        }
        msg
    }

    pub fn update(&mut self, msg: Vec<u8>, nBlocks: i32) {
        let mut w = [0; 68];
        let mut w1 = [0; 64];
        let mut msg = msg;

        let mut a = self.digest[0];
        let mut b = self.digest[1];
        let mut c = self.digest[2];
        let mut d = self.digest[3];
        let mut e = self.digest[4];
        let mut f = self.digest[5];
        let mut g = self.digest[6];
        let mut h = self.digest[7];

        while msg.len() >= 64 {
            for i in 0..16 {
                w[i] = u32::from_be_bytes([msg[4*i], msg[4*i+1], msg[4*i+2], msg[4*i+3]]);
            }
            for i in 16..68 {
                w[i] = self.p1(w[i-16] ^ w[i-9] ^ self.left_rotate(w[i-3], 15)) ^ self.left_rotate(w[i-13], 7) ^ w[i-6];
            }
            for i in 0..64 {
                w1[i] = w[i] ^ w[i+4];
            }

            let mut A = a;
            let mut B = b;
            let mut C = c;
            let mut D = d;
            let mut E = e;
            let mut F = f;
            let mut G = g;
            let mut H = h;

            for i in 0..16 {
                let val1 = self.left_rotate(A, 12).wrapping_add(E).wrapping_add(self.left_rotate(0x79cc4519, i as u32));
                let SS1 = self.left_rotate(val1, 7);
                let SS2 = SS1 ^ self.left_rotate(A, 12);
                let TT1 = self.ff0(A, B, C).wrapping_add(D).wrapping_add(SS2).wrapping_add(w1[i]);
                let TT2 = self.gg0(E, F, G).wrapping_add(H).wrapping_add(SS1).wrapping_add(w[i]);

                D = C;
                C = self.left_rotate(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = self.left_rotate(F, 19);
                F = E;
                E = self.p0(TT2);
            }

            for i in 16..64 {
                let val1 = self.left_rotate(A, 12).wrapping_add(E).wrapping_add(self.left_rotate(0x7a879d8a, i as u32));
                let SS1 = self.left_rotate(val1, 7);
                let SS2 = SS1 ^ self.left_rotate(A, 12);
                let TT1 = self.ff1(A, B, C).wrapping_add(D).wrapping_add(SS2).wrapping_add(w1[i]);
                let TT2 = self.gg1(E, F, G).wrapping_add(H).wrapping_add(SS1).wrapping_add(w[i]);

                D = C;
                C = self.left_rotate(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = self.left_rotate(F, 19);
                F = E;
                E = self.p0(TT2);
            }

            a ^= A;
            b ^= B;
            c ^= C;
            d ^= D;
            e ^= E;
            f ^= F;
            g ^= G;
            h ^= H;
            msg = msg[64..].to_vec();
        }
        self.digest[0] = a;
        self.digest[1] = b;
        self.digest[2] = c;
        self.digest[3] = d;
        self.digest[4] = e;
        self.digest[5] = f;
        self.digest[6] = g;
        self.digest[7] = h;
    }
}

pub trait Hash {
    fn block_size(&self) -> usize;
    fn size(&self) -> usize;
    fn reset(&mut self);
    fn write(&mut self, input: Vec<u8>) -> i32; // TODO: error handling
    fn sum(&mut self, input: Vec<u8>) -> Vec<u8>;
}

impl Hash for SM3 {
    fn block_size(&self) -> usize {
        64
    }

    fn size(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.digest[0] = 0x7380166f;
        self.digest[1] = 0x4914b2b9;
        self.digest[2] = 0x172442d7;
        self.digest[3] = 0xda8a0600;
        self.digest[4] = 0xa96f30bc;
        self.digest[5] = 0x163138aa;
        self.digest[6] = 0xe38dee4d;
        self.digest[7] = 0xb0fb0e4e;

        self.length = 0;
        self.unhandle_msg = vec![];
    }

    fn write(&mut self, p: Vec<u8>) -> i32 {
        let toWrite = p.len();
        self.length += (p.len() * 8) as u64;

        let mut msg = vec![];
        msg.extend(&self.unhandle_msg);
        msg.extend(&p);

        let nBlocks = msg.len() / self.block_size();
        self.update(msg.clone(), nBlocks as i32);

        self.unhandle_msg = msg[nBlocks * self.block_size() ..].to_vec();
        return toWrite as i32;
    }

    fn sum(&mut self, input: Vec<u8>) -> Vec<u8> {
        let inputCap = input.capacity();
        let inputLen = input.len();
        let mut input = input.clone();
        self.write(input.clone());
        let msg = self.pad();
        let nBlocks = (msg.len() as i32) / (self.block_size() as i32);
        self.update(msg, nBlocks);

        let needed = self.size();
        
        if inputCap - inputLen < needed {
            let mut newIn = Vec::with_capacity(inputLen + needed);
            for i in 0..inputLen {
                newIn[i] = input[i];
            }
            input = newIn;
        }
        input.resize(32, 0);
        let out = &mut input[inputLen .. inputLen + needed];
        for i in 0..8 {
            // TODO: use to_be_bytes()?
            // self.digest[i] = u32::from_be_bytes([out[i*4], out[i*4+1], out[i*4+2], out[i*4+3]]);
            // let bts = self.digest[i].to_be_bytes();
            out[i*4] = (self.digest[i] >> 24) as u8;
            out[i*4+1] = (self.digest[i] >> 16) as u8;
            out[i*4+2] = (self.digest[i] >> 8) as u8;
            out[i*4+3] = self.digest[i] as u8;
        }
        out.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let mut hw = SM3::default();
        hw.reset();
        hw.write(String::from("helloworld").into_bytes());
        // let hash = hw.sum(String::from("hello").into_bytes());
        let hash = hw.sum(vec![]);
        let ss = hash.iter().map(|x| format!("{:02X}", x)).collect::<Vec<String>>().join("");
        assert_eq!("C70C5F73DA4E8B8B73478AF54241469566F6497E16C053A03A0170FA00078283", ss);
    }
}
