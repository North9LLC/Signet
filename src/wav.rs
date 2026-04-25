// Minimal 16-bit PCM mono WAV reader/writer. No external crates.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub struct Wav {
    pub sample_rate: u32,
    pub samples: Vec<f32>, // normalized [-1.0, 1.0]
}

impl Wav {
    pub fn write<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let mut f = File::create(path)?;
        let n = self.samples.len() as u32;
        let byte_rate = self.sample_rate * 2;
        let data_size = n * 2;
        let file_size = 36 + data_size;

        f.write_all(b"RIFF")?;
        f.write_all(&file_size.to_le_bytes())?;
        f.write_all(b"WAVE")?;
        f.write_all(b"fmt ")?;
        f.write_all(&16u32.to_le_bytes())?; // subchunk1 size
        f.write_all(&1u16.to_le_bytes())?;  // PCM
        f.write_all(&1u16.to_le_bytes())?;  // mono
        f.write_all(&self.sample_rate.to_le_bytes())?;
        f.write_all(&byte_rate.to_le_bytes())?;
        f.write_all(&2u16.to_le_bytes())?;  // block align
        f.write_all(&16u16.to_le_bytes())?; // bits per sample
        f.write_all(b"data")?;
        f.write_all(&data_size.to_le_bytes())?;

        for &s in &self.samples {
            let v = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
            f.write_all(&v.to_le_bytes())?;
        }
        Ok(())
    }

    pub fn read<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mut f = File::open(path)?;
        let mut hdr = [0u8; 44];
        f.read_exact(&mut hdr)?;
        if &hdr[0..4] != b"RIFF" || &hdr[8..12] != b"WAVE" {
            return Err(std::io::Error::other("not a WAV file"));
        }
        let channels = u16::from_le_bytes([hdr[22], hdr[23]]);
        let sample_rate = u32::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
        let bits = u16::from_le_bytes([hdr[34], hdr[35]]);
        if channels != 1 || bits != 16 {
            return Err(std::io::Error::other("only 16-bit mono supported"));
        }
        let mut rest = Vec::new();
        f.read_to_end(&mut rest)?;
        let mut samples = Vec::with_capacity(rest.len() / 2);
        for ch in rest.chunks_exact(2) {
            let v = i16::from_le_bytes([ch[0], ch[1]]);
            samples.push(v as f32 / 32768.0);
        }
        Ok(Wav { sample_rate, samples })
    }
}
