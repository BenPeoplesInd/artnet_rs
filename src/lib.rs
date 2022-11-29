use e1_20::Uid;
use serde::{Deserialize, Serialize};

pub fn art_serialize(op_code: OpCode) -> Result<Vec<u8>, OpError> {
    bincode::serialize(&op_code).or(Err(OpError {
        code: "Serialization error.".to_string(),
    }))
}

pub fn art_deserialize(bytes: &[u8]) -> Result<OpCode, OpError> {
    bincode::deserialize(bytes).or(Err(OpError {
        code: "Deserialization error.".to_string(),
    }))
}

#[derive(Serialize, Deserialize)]
pub enum OpCode {
    OpPoll,
    OpPollReply,
    OpTodRequest,
    OpTodData,
    OpTodControl,
    OpRdm,
    OpCommand,
    OpDmx,
    OpError,
}

#[derive(Serialize, Deserialize)]
pub struct OpPoll {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    flags: i8,
    diag_priority: i8,
}

#[derive(Serialize, Deserialize)]
pub struct OpPollReply {
    id: [i8; 8],
    op_code: OpCode,
    ip_address: [i8; 4],
    port: i16,
    vers_info_h: i8,
    vers_info_l: i8,
    net_switch: i8,
    sub_switch: i8,
    oem_hi: i8,
    oem: i8,
    ubea_version: i8,
    status1: i8,
}

#[derive(Serialize, Deserialize)]
pub struct OpTodRequest {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    filler_spare: [i8; 9],
    net: i8,
    command: i8,
    add_count: i8,
    address: i8,
}

#[derive(Serialize, Deserialize)]
pub struct OpTodData {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    rdm_ver: i8,
    port: i8,
    spare: [i8; 6],
    bind_index: i8,
    net: i8,
    command_response: i8,
    address: i8,
    uid_total_hi: i8,
    uid_total_lo: i8,
    block_count: i8,
    uid_count: i8,
    tod: Uid,
}

#[derive(Serialize, Deserialize)]
pub struct OpTodControl {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    filler_spare: [i8; 9],
    net: i8,
    command: i8,
    address: i8,
}

#[derive(Serialize, Deserialize)]
pub struct OpRdm {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    rdm_ver: i8,
    filler_spare: [i8; 8],
    net: i8,
    command: i8,
    address: i8,
    rdm_packet: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct OpCommand {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    esta_man_hi: i8,
    esta_man_lo: i8,
    length_hi: i8,
    length_lo: i8,
    data: i8,
}

#[derive(Serialize, Deserialize)]
pub struct OpDmx {
    id: [i8; 8],
    op_code: OpCode,
    prot_ver_hi: i8,
    prot_ver_lo: i8,
    sequence: i8,
    physical: i8,
    sub_uni: i8,
    net: i8,
    length_hi: i8,
    length_lo: i8,
    data: i8,
}

#[derive(Serialize, Deserialize)]
pub struct OpError {
    code: String,
}
