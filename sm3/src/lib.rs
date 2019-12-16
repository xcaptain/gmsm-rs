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
        let block_size = 64;
        while msg.len() % block_size != 56 {
            msg.push(0x00);
        }
        msg.push((self.length >> 56 & 0xff) as u8);
        msg.push((self.length >> 48 & 0xff) as u8);
        msg.push((self.length >> 40 & 0xff) as u8);
        msg.push((self.length >> 32 & 0xff) as u8);
        msg.push((self.length >> 24 & 0xff) as u8);
        msg.push((self.length >> 16 & 0xff) as u8);
        msg.push((self.length >> 8 & 0xff) as u8);
        msg.push(self.length as u8);

        if msg.len() % 64 != 0 {
            panic!("------SM3 Pad: error msgLen");
        }
        msg
    }

    pub fn update(&mut self, msg: Vec<u8>) {
        let mut ww = [0; 68];
        let mut w1 = [0; 64];
        let mut msg = msg;

        let mut a1 = self.digest[0];
        let mut b1 = self.digest[1];
        let mut c1 = self.digest[2];
        let mut d1 = self.digest[3];
        let mut e1 = self.digest[4];
        let mut f1 = self.digest[5];
        let mut g1 = self.digest[6];
        let mut h1 = self.digest[7];

        while msg.len() >= 64 {
            for i in 0..16 {
                ww[i] = u32::from_be_bytes([
                    msg[4 * i],
                    msg[4 * i + 1],
                    msg[4 * i + 2],
                    msg[4 * i + 3],
                ]);
            }
            for i in 16..68 {
                ww[i] = self.p1(ww[i - 16] ^ ww[i - 9] ^ self.left_rotate(ww[i - 3], 15))
                    ^ self.left_rotate(ww[i - 13], 7)
                    ^ ww[i - 6];
            }
            for i in 0..64 {
                w1[i] = ww[i] ^ ww[i + 4];
            }

            let mut aa = a1;
            let mut bb = b1;
            let mut cc = c1;
            let mut dd = d1;
            let mut ee = e1;
            let mut ff = f1;
            let mut gg = g1;
            let mut hh = h1;

            for i in 0..16 {
                let val1 = self
                    .left_rotate(aa, 12)
                    .wrapping_add(ee)
                    .wrapping_add(self.left_rotate(0x79cc_4519, i as u32));
                let ss1 = self.left_rotate(val1, 7);
                let ss2 = ss1 ^ self.left_rotate(aa, 12);
                let tt1 = self
                    .ff0(aa, bb, cc)
                    .wrapping_add(dd)
                    .wrapping_add(ss2)
                    .wrapping_add(w1[i]);
                let tt2 = self
                    .gg0(ee, ff, gg)
                    .wrapping_add(hh)
                    .wrapping_add(ss1)
                    .wrapping_add(ww[i]);

                dd = cc;
                cc = self.left_rotate(bb, 9);
                bb = aa;
                aa = tt1;
                hh = gg;
                gg = self.left_rotate(ff, 19);
                ff = ee;
                ee = self.p0(tt2);
            }

            for i in 16..64 {
                let val1 = self
                    .left_rotate(aa, 12)
                    .wrapping_add(ee)
                    .wrapping_add(self.left_rotate(0x7a87_9d8a, i as u32));
                let ss1 = self.left_rotate(val1, 7);
                let ss2 = ss1 ^ self.left_rotate(aa, 12);
                let tt1 = self
                    .ff1(aa, bb, cc)
                    .wrapping_add(dd)
                    .wrapping_add(ss2)
                    .wrapping_add(w1[i]);
                let tt2 = self
                    .gg1(ee, ff, gg)
                    .wrapping_add(hh)
                    .wrapping_add(ss1)
                    .wrapping_add(ww[i]);

                dd = cc;
                cc = self.left_rotate(bb, 9);
                bb = aa;
                aa = tt1;
                hh = gg;
                gg = self.left_rotate(ff, 19);
                ff = ee;
                ee = self.p0(tt2);
            }

            a1 ^= aa;
            b1 ^= bb;
            c1 ^= cc;
            d1 ^= dd;
            e1 ^= ee;
            f1 ^= ff;
            g1 ^= gg;
            h1 ^= hh;
            msg = msg[64..].to_vec();
        }
        self.digest[0] = a1;
        self.digest[1] = b1;
        self.digest[2] = c1;
        self.digest[3] = d1;
        self.digest[4] = e1;
        self.digest[5] = f1;
        self.digest[6] = g1;
        self.digest[7] = h1;
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
        self.digest[0] = 0x7380_166f;
        self.digest[1] = 0x4914_b2b9;
        self.digest[2] = 0x1724_42d7;
        self.digest[3] = 0xda8a_0600;
        self.digest[4] = 0xa96f_30bc;
        self.digest[5] = 0x1631_38aa;
        self.digest[6] = 0xe38d_ee4d;
        self.digest[7] = 0xb0fb_0e4e;

        self.length = 0;
        self.unhandle_msg = vec![];
    }

    fn write(&mut self, p: Vec<u8>) -> i32 {
        let to_write = p.len();
        self.length += (p.len() * 8) as u64;

        let mut msg = vec![];
        msg.extend(&self.unhandle_msg);
        msg.extend(&p);

        let nblocks = msg.len() / self.block_size();
        self.update(msg.clone());

        self.unhandle_msg = msg[nblocks * self.block_size()..].to_vec();
        to_write as i32
    }

    fn sum(&mut self, input: Vec<u8>) -> Vec<u8> {
        let input_cap = input.capacity();
        let input_len = input.len();
        let mut input = input.clone();
        self.write(input.clone());
        let msg = self.pad();
        self.update(msg);

        let needed = self.size();
        if input_cap - input_len < needed {
            let mut new_input = vec![0; input_len + needed];
            new_input[..input_len].clone_from_slice(&input[..input_len]);
            input = new_input;
        }

        let out = &mut input[input_len..input_len + needed];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].clone_from_slice(&self.digest[i].to_be_bytes());
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
        let hash = hw.sum(vec![]);
        let ss = hash
            .iter()
            .map(|x| format!("{:02X}", x))
            .collect::<Vec<String>>()
            .join("");
        assert_eq!(
            "C70C5F73DA4E8B8B73478AF54241469566F6497E16C053A03A0170FA00078283",
            ss
        );

        hw.reset();
        let hash2 = hw.sum(String::from("helloworld").into_bytes());
        let ss2 = hash2
            .iter()
            .map(|x| format!("{:02X}", x))
            .collect::<Vec<String>>()
            .join("");
        assert_eq!(
            "C70C5F73DA4E8B8B73478AF54241469566F6497E16C053A03A0170FA00078283",
            ss2
        );
    }
}
