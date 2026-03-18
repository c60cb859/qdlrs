use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::Path,
};
use xmltree::XMLNode;

use crate::firehose_xml_setup;

pub fn calc_hashes(xml_path: &Path, send_buffer_size: usize) -> Result<Vec<Vec<u8>>> {
    let program_file = fs::read(xml_path)?;
    let xml = xmltree::Element::parse(&program_file[..])?;

    let mut digests: Vec<Vec<u8>> = vec![];
    for node in xml.children.iter() {
        if let XMLNode::Element(e) = node {
            let args: Vec<(&str, &str)> = e
                .attributes
                .as_slice()
                .into_iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            let packet = firehose_xml_setup(&e.name.to_ascii_lowercase(), &args)?;

            let hash = Sha256::digest(packet);
            digests.push(hash.to_vec());

            // SAFETY: if the program file exists, it must have a parent dir
            let xml_dir = xml_path.parent().unwrap();
            if let Some(filename) = &e.attributes.get("filename") {
                let file_path = xml_dir.join(filename);

                if filename.is_empty() {
                    continue;
                } else {
                    if !file_path.exists() {
                        println!("WARNING: {filename} doesn't exist - assuming that's intended");
                        continue;
                    }

                    println!("Processing {filename}...");
                }
                let mut buf = vec![0u8; send_buffer_size];
                let mut br = BufReader::new(File::open(file_path)?);
                loop {
                    let n = br.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    digests.push(Sha256::digest(&buf[..n]).to_vec());
                }
            }
        }
    }

    Ok(digests)
}

fn make_elf_header(payload_size: u32) -> [u8; 232] {
    let mut hdr = [0u8; 232];
    let first_96: [u8; 96] = [
        0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    hdr[..96].copy_from_slice(&first_96);
    let sz = (payload_size as u64).to_le_bytes();
    hdr[96..104].copy_from_slice(&sz);
    hdr[104..112].copy_from_slice(&sz);
    hdr
}

const FIRST_TABLE_PAYLOAD_HASHES: usize = 53;
const DIGEST_SIZE: usize = 32;
const VIP_CHAINED_TABLE_SIZE: usize = 8192;
const CHAINED_DIGESTS_PER_TABLE: usize = VIP_CHAINED_TABLE_SIZE / DIGEST_SIZE - 1; // 255

pub fn gen_hash_tables(
    digests: Vec<Vec<u8>>,
    output_dir: &Path,
    _max_table_size: usize,
) -> Result<()> {
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    let num_digests = digests.len();
    let primary_digests: &[Vec<u8>] = if num_digests >= FIRST_TABLE_PAYLOAD_HASHES {
        &digests[..FIRST_TABLE_PAYLOAD_HASHES]
    } else {
        &digests[..]
    };

    let aux_digests: &[Vec<u8>] = if num_digests > FIRST_TABLE_PAYLOAD_HASHES {
        &digests[FIRST_TABLE_PAYLOAD_HASHES..]
    } else {
        &[]
    };

    // Build chained tables back-to-front to compute chain hashes
    let num_chained_tables = if num_digests >= FIRST_TABLE_PAYLOAD_HASHES {
        let extra = num_digests - FIRST_TABLE_PAYLOAD_HASHES;
        let full = extra / CHAINED_DIGESTS_PER_TABLE;
        let rem = extra % CHAINED_DIGESTS_PER_TABLE;
        if rem > 0 {
            full + 1
        } else if full > 0 {
            full
        } else {
            0
        }
    } else {
        0
    };

    let mut table_hashes: Vec<Vec<u8>> = vec![vec![0u8; DIGEST_SIZE]; num_chained_tables];
    let mut running_hash = vec![0u8; DIGEST_SIZE];

    for i in (0..num_chained_tables).rev() {
        let start = i * CHAINED_DIGESTS_PER_TABLE;
        let end = ((i + 1) * CHAINED_DIGESTS_PER_TABLE).min(aux_digests.len());
        let mut table_bytes: Vec<u8> = aux_digests[start..end].concat();
        let is_last = i == num_chained_tables - 1;
        if is_last {
            table_bytes.push(0x00);
        } else {
            table_bytes.extend_from_slice(&running_hash);
        }
        running_hash = Sha256::digest(&table_bytes).to_vec();
        table_hashes[i] = running_hash.clone();
    }

    let chain_head_hash: Vec<u8> = if num_chained_tables > 0 {
        table_hashes[0].clone()
    } else {
        vec![0u8; DIGEST_SIZE]
    };

    let first_table_size: u32 = if num_digests >= FIRST_TABLE_PAYLOAD_HASHES + 1 {
        (54 * DIGEST_SIZE) as u32
    } else {
        ((primary_digests.len() + 1) * DIGEST_SIZE) as u32
    };

    let elf_header = make_elf_header(first_table_size);
    let mut signme = File::create(output_dir.join("signme.elf"))?;
    signme.write_all(&elf_header)?;
    signme.write_all(&primary_digests.concat())?;
    signme.write_all(&chain_head_hash)?;

    println!(
        "signme.elf: {} hashes + chain-head hash, first_table_size={}",
        primary_digests.len(),
        first_table_size
    );

    if num_chained_tables > 0 {
        let mut tables = File::create(output_dir.join("tables.bin"))?;
        for i in 0..num_chained_tables {
            let start = i * CHAINED_DIGESTS_PER_TABLE;
            let end = ((i + 1) * CHAINED_DIGESTS_PER_TABLE).min(aux_digests.len());
            tables.write_all(&aux_digests[start..end].concat())?;
            let is_last = i == num_chained_tables - 1;
            if !is_last {
                tables.write_all(&table_hashes[i + 1])?;
            } else {
                tables.write_all(&[0x00])?;
            }
        }
        println!("tables.bin: {} chained table(s)", num_chained_tables);
    }

    Ok(())
}
