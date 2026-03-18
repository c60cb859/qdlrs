// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
use std::{
    fmt::Display,
    io::{BufRead, ErrorKind, Read, Write},
    str::FromStr,
};

use anyhow::{Error, bail};
use owo_colors::OwoColorize;

use sha2::{Digest, Sha256};

use crate::firehose_reset;

/// Common respones indicating success/failure respectively
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum FirehoseStatus {
    Ack = 0,
    Nak = 1,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QdlBackend {
    Serial,
    Usb,
}

impl FromStr for QdlBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "serial" => Ok(QdlBackend::Serial),
            "usb" => Ok(QdlBackend::Usb),
            _ => bail!("Unknown backend"),
        }
    }
}

impl Default for QdlBackend {
    fn default() -> Self {
        match cfg!(target_os = "windows") {
            true => QdlBackend::Serial,
            false => QdlBackend::Usb,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FirehoseConfiguration {
    // send/recv are from Host PoV
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub xml_buf_size: usize,

    pub storage_sector_size: usize,
    pub storage_type: FirehoseStorageType,

    pub bypass_storage: bool,
    pub hash_packets: bool,
    pub read_back_verify: bool,

    pub backend: QdlBackend,
    pub skip_firehose_log: bool,
    pub verbose_firehose: bool,

    pub dry_run: bool,
}

impl Default for FirehoseConfiguration {
    fn default() -> Self {
        Self {
            send_buffer_size: 1024 * 1024,
            recv_buffer_size: 4096,
            xml_buf_size: 4096,
            storage_sector_size: 512,
            storage_type: FirehoseStorageType::Emmc,
            bypass_storage: true,
            hash_packets: false,
            read_back_verify: false,
            backend: QdlBackend::default(),
            skip_firehose_log: true,
            verbose_firehose: false,
            dry_run: false,
        }
    }
}
pub trait QdlChan: BufRead + Write {
    fn fh_config(&self) -> &FirehoseConfiguration;
    fn mut_fh_config(&mut self) -> &mut FirehoseConfiguration;
    fn record_xml_command(&mut self, buf: &[u8]);
    fn record_data_command(&mut self, buf: &[u8]);
    fn increment_send_count(&mut self);
    fn get_send_count(&self) -> u64;
    fn next_digest_chunk(&mut self, chunk_size: usize) -> Option<&[u8]>;
}

pub trait QdlReadWrite: BufRead + Write + Send + Sync {}
impl<T> QdlReadWrite for &mut T where T: QdlReadWrite + ?Sized {}

pub struct QdlDevice<T>
where
    T: QdlReadWrite + ?Sized,
{
    pub rw: Box<T>,
    pub fh_cfg: FirehoseConfiguration,
    pub reset_on_drop: bool,
    pub digests: Vec<Vec<u8>>,
    pub vip_digest_table: Vec<u8>,
    pub vip_signed_mbn: Vec<u8>,
    pub send_counter: u64,
    pub vip_digest_offset: usize,
}

impl<T> Read for QdlDevice<T>
where
    T: QdlReadWrite + ?Sized,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.rw.read(buf)
    }
}

impl<T> Write for QdlDevice<T>
where
    T: QdlReadWrite + ?Sized,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.rw.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.rw.flush()
    }
}

impl<T> std::io::BufRead for QdlDevice<T>
where
    T: QdlReadWrite + ?Sized,
{
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.rw.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.rw.consume(amt);
    }
}

impl<T> QdlChan for QdlDevice<T>
where
    T: QdlReadWrite + ?Sized,
{
    fn fh_config(&self) -> &FirehoseConfiguration {
        &self.fh_cfg
    }

    fn mut_fh_config(&mut self) -> &mut FirehoseConfiguration {
        &mut self.fh_cfg
    }

    fn record_xml_command(&mut self, buf: &[u8]) {
        // let xml = String::from_utf8_lossy(&buf);
        let hash = Sha256::digest(buf).to_vec();
        // let hash_str: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        // println!("{} = {:?}", xml, hash_str);
        self.digests.push(hash);
    }

    fn record_data_command(&mut self, buf: &[u8]) {
        let hash = Sha256::digest(buf).to_vec();
        // let _hash_str: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        // println!("DATA = {}", hash_str);
        self.digests.push(hash);
    }

    fn increment_send_count(&mut self) {
        self.send_counter = self.send_counter + 1;
    }

    fn get_send_count(&self) -> u64 {
        self.send_counter
    }

    fn next_digest_chunk(&mut self, chunk_size: usize) -> Option<&[u8]> {
        let start = self.vip_digest_offset;
        if start >= self.vip_digest_table.len() {
            return None;
        }
        let end = (start + chunk_size).min(self.vip_digest_table.len());
        self.vip_digest_offset = end;
        Some(&self.vip_digest_table[start..end])
    }
}

impl<T> Drop for QdlDevice<T>
where
    T: QdlReadWrite + ?Sized,
{
    fn drop(&mut self) {
        // Avoid having the board be stuck in EDL limbo in case of errors
        // TODO: watch 'rawmode' and adjust accordingly
        if self.reset_on_drop {
            println!(
                "Firehose {}. Resetting the board to {}, try again.",
                "failed".bright_red(),
                "edl".bright_yellow()
            );
            let _ = firehose_reset(self, &FirehoseResetMode::ResetToEdl, 0);
        }
    }
}

/// Supported storage media types
#[derive(Clone, Copy, Debug)]
pub enum FirehoseStorageType {
    Emmc,
    Ufs,
    Nand,
    Nvme,
    Spinor,
}

impl FromStr for FirehoseStorageType {
    type Err = Error;

    fn from_str(input: &str) -> Result<FirehoseStorageType, Self::Err> {
        match input {
            "emmc" => Ok(FirehoseStorageType::Emmc),
            "ufs" => Ok(FirehoseStorageType::Ufs),
            "nand" => Ok(FirehoseStorageType::Nand),
            "nvme" => Ok(FirehoseStorageType::Nvme),
            "spinor" => Ok(FirehoseStorageType::Spinor),
            _ => bail!("Unknown storage type"),
        }
    }
}

impl Display for FirehoseStorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirehoseStorageType::Emmc => write!(f, "emmc"),
            FirehoseStorageType::Ufs => write!(f, "ufs"),
            FirehoseStorageType::Nand => write!(f, "nand"),
            FirehoseStorageType::Nvme => write!(f, "nvme"),
            FirehoseStorageType::Spinor => write!(f, "spinor"),
        }
    }
}

/// List of supported reboot modes, supplied to the \<reset\> command
pub enum FirehoseResetMode {
    ResetToEdl,
    Reset,
    Off,
}

impl FromStr for FirehoseResetMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "edl" => Ok(FirehoseResetMode::ResetToEdl),
            "system" => Ok(FirehoseResetMode::Reset),
            "off" => Ok(FirehoseResetMode::Off),
            _ => Err(std::io::Error::from(ErrorKind::InvalidInput).into()),
        }
    }
}

impl Display for FirehoseResetMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirehoseResetMode::ResetToEdl => write!(f, "edl"),
            FirehoseResetMode::Reset => write!(f, "system"),
            FirehoseResetMode::Off => write!(f, "off"),
        }
    }
}

pub struct NullChannel;

impl Read for NullChannel {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl Write for NullChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl BufRead for NullChannel {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(&[])
    }
    fn consume(&mut self, _amt: usize) {}
}

impl QdlReadWrite for NullChannel {}
