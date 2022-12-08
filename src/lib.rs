#![feature(cstr_from_bytes_until_nul)]

use e1_20::Uid;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use eui48::MacAddress;
use std::io::Cursor;
use std::io::Write;
use std::io::Read;
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};
use std::convert::TryInto;
use std::ffi::CStr;


const HEADER: [u8; 8] = [65, 114, 116, 45, 78, 101, 116, 0]; // "Art-Net"

#[derive(Debug)]
pub enum OpCodeValues {
    OpPoll = 0x2000,
    OpPollReply = 0x2100,
    OpTodRequest = 0x8000,
    OpTodData = 0x8100,
    OpTodControl = 0x8200,
    OpRdm = 0x8300,
    OpCommand = 0x2400,
    OpDmx = 0x5000,
    Unknown = 0,
}

impl TryFrom<u16> for OpCodeValues {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == OpCodeValues::OpPoll as u16 => Ok(OpCodeValues::OpPoll),
            x if x == OpCodeValues::OpPollReply as u16 => Ok(OpCodeValues::OpPollReply),
            x if x == OpCodeValues::OpTodRequest as u16 => Ok(OpCodeValues::OpTodRequest),
            x if x == OpCodeValues::OpTodData as u16 => Ok(OpCodeValues::OpTodData),
            x if x == OpCodeValues::OpTodControl as u16 => Ok(OpCodeValues::OpTodControl),
            x if x == OpCodeValues::OpRdm as u16 => Ok(OpCodeValues::OpRdm),
            x if x == OpCodeValues::OpCommand as u16 => Ok(OpCodeValues::OpCommand),
            x if x == OpCodeValues::OpDmx as u16 => Ok(OpCodeValues::OpDmx),
            x if x == OpCodeValues::Unknown as u16 => Ok(OpCodeValues::Unknown),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub enum ArtPkt {
    OpPoll(OpPoll),
    OpPollReply(OpPollReply),
    OpTodRequest(OpTodRequest),
    OpTodData(OpTodData),
    OpTodControl(OpTodControl),
    OpRdm(OpRdm),
    OpCommand(OpCommand),
    OpDmx(OpDmx),
    Unknown(String),
}

impl ArtPkt {
    pub fn new() -> ArtPkt {
        ArtPkt::Unknown("".to_string())
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            ArtPkt::OpPoll(data) => {
                return data.serialize();
            },
            ArtPkt::OpPollReply(data) => {
                return data.serialize();
            },
            ArtPkt::OpTodRequest(data) => {
                return data.serialize();
            },
            ArtPkt::OpTodData(data) => {
                return data.serialize();
            },
            ArtPkt::OpTodControl(data) => {
                return data.serialize();
            },
            ArtPkt::OpRdm(data) => {
                return data.serialize();
            },
            ArtPkt::OpCommand(data) => {
                return data.serialize();
            },
            ArtPkt::OpDmx(data) => {
                return data.serialize();
            },
            _ => return Vec::new()
        }
    }

    pub fn deserialize(data : &Vec<u8>) -> Option<ArtPkt> {

        // if packet is too short, return None
        if data.len() < 12 {
            return None;
        }

        // Does it say Art-Net at the top?
        if !data.starts_with(&HEADER) {
            return None;
        }

        // Check the opcode
        match u16::from_le_bytes(data[8..10].try_into().unwrap_or_default()).try_into() {
            Ok(OpCodeValues::OpPoll) => {   
                let inner : Option<OpPoll> = OpPoll::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpPoll(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpPollReply) => {
                let inner : Option<OpPollReply> = OpPollReply::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpPollReply(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpTodRequest) => {
                let inner : Option<OpTodRequest> = OpTodRequest::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpTodRequest(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpTodData) =>  {
                let inner : Option<OpTodData> = OpTodData::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpTodData(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpTodControl) =>  {
                let inner : Option<OpTodControl> = OpTodControl::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpTodControl(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpRdm) =>  {
                let inner : Option<OpRdm> = OpRdm::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpRdm(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpCommand) =>  {
                let inner : Option<OpCommand> = OpCommand::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpCommand(depkt)),
                    None => return None
                }
            },
            Ok(OpCodeValues::OpDmx) =>  {
                let inner : Option<OpDmx> = OpDmx::deserialize(data);
                match inner {
                    Some(depkt) => return Some(ArtPkt::OpDmx(depkt)),
                    None => return None
                }
            },
            Ok(_) => println!("No match, but OK"),
            Err(_) => println!("No match")
        }

        return None;


    }

}


#[derive(Debug)]
pub struct OpPoll {
    pub flags: u8,
    pub diag_priority: u8,
}

impl OpPoll {
    pub fn new() -> OpPoll {
        OpPoll { flags: 0, diag_priority: 0 }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpPoll as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        cursor.write_u8(self.flags).unwrap();
        cursor.write_u8(self.diag_priority).unwrap();

        cursor.write_all(&[0 as u8; 4]).unwrap();

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpPoll> {

        if data.len() < 14 {
            return None;
        }

        let mut rv = OpPoll::new();

        rv.flags = data[12];
        rv.diag_priority = data[13];

        return Some(rv);
    }

}

// Cannot derive SerDes here for MacAddress
#[derive(Debug)]
pub struct OpPollReply {
    pub ip_address: IpAddr,
    pub port: u16,
    pub vers_info: u16,
    pub universe_switch: u16,
    pub oem: u16,
    pub ubea_version: u8,
    pub status1: u8,
    pub esta_mfg: u16,
    pub short_name: String,
    pub long_name: String,
    pub node_report: String,
    pub num_ports: u16,
    pub port_types: [u8; 4],
    pub good_input: [u8; 4],
    pub good_output: [u8; 4],
    pub sw_in: [u8; 4],
    pub sw_out: [u8; 4],
    pub priority: u8,
    pub sw_macro: u8,
    pub sw_remote: u8,
    pub style: u8,
    pub mac: MacAddress,
    pub bind_ip: IpAddr,
    pub bind_index: u8,
    pub status2: u8,
    pub good_output_b: [u8; 4],
    pub status3: u8,
    pub default_responder: Uid,
}

impl OpPollReply {
    pub fn new() -> OpPollReply {
        OpPollReply { 
            ip_address: IpAddr::V4(Ipv4Addr::new(0,0,0,0)),
            port:0, 
            vers_info: 0, 
            universe_switch: 0, 
            oem: 0, 
            ubea_version: 0, 
            status1: 0, 
            esta_mfg: 0, 
            short_name: "".to_string(), 
            long_name: "".to_string(), 
            node_report: "".to_string(), 
            num_ports: 0, 
            port_types: [0; 4], 
            good_input: [0; 4], 
            good_output: [0; 4], 
            sw_in: [0; 4], 
            sw_out: [0; 4], 
            priority: 100, 
            sw_macro: 0, 
            sw_remote: 0, 
            style : 0,
            mac: MacAddress::new([0,0,0,0,0,0]), 
            bind_ip: IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 
            bind_index: 0, 
            status2: 0, 
            good_output_b: [0; 4], 
            status3: 0, 
            default_responder: Uid::new(0,0) 
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpPollReply as u16).unwrap();
        

        let ip_bytes = match self.ip_address {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(_) => [0, 0, 0, 0],
        };
        cursor.write_all(&ip_bytes).unwrap();
        // Write port
        cursor.write_u16::<LittleEndian>(self.port).unwrap();
        // Write vers info
        cursor.write_u16::<LittleEndian>(self.vers_info).unwrap();
        // Write universe switch
        cursor.write_u16::<LittleEndian>(self.universe_switch).unwrap();
        // Write oem
        cursor.write_u16::<LittleEndian>(self.oem).unwrap();
        // Write ubea version
        cursor.write_u8(self.ubea_version).unwrap();
        // Write status1
        cursor.write_u8(self.status1).unwrap();
        // Write esta mfg
        cursor.write_u16::<LittleEndian>(self.esta_mfg).unwrap();
        // Write short name
        let short_name_bytes = self.short_name.as_bytes();

        let mut short_name_array : [u8; 18] = [0; 18];

        let mut index = 0;

        for c in short_name_bytes {
            short_name_array[index] = *c;
            index += 1;
            if index > 16 {
                break;
            }
        }

        cursor.write_all(&short_name_array).unwrap();
        // Write long name
        let long_name_bytes = self.long_name.as_bytes();

        let mut long_name_array : [u8; 64] = [0; 64];

        let mut index = 0;

        for c in long_name_bytes {
            long_name_array[index] = *c;
            index += 1;
            if index > 62 {
                break;
            }
        }

        cursor.write_all(&long_name_array).unwrap();
        // Write node report

        let node_report_bytes = self.node_report.as_bytes();

        let mut node_report_array : [u8; 64] = [0; 64];

        let mut index = 0;

        for c in node_report_bytes {
            node_report_array[index] = *c;
            index += 1;
            if index > 62 {
                break;
            }
        }

        cursor.write_all(&node_report_array).unwrap();
        // Write number of ports
        cursor.write_u16::<LittleEndian>(self.num_ports).unwrap();
        // Write port types
        cursor.write_all(&self.port_types).unwrap();
        // Write good input
        cursor.write_all(&self.good_input).unwrap();
        // Write good output
        cursor.write_all(&self.good_output).unwrap();
        // Write sw in
        cursor.write_all(&self.sw_in).unwrap();
        // Write sw out
        cursor.write_all(&self.sw_out).unwrap();
        // Write priority
        cursor.write_u8(self.priority).unwrap();
        // Write sw macro
        cursor.write_u8(self.sw_macro).unwrap();
        // Write sw remote
        cursor.write_u8(self.sw_remote).unwrap();

        cursor.write_all(&[0 as u8; 3]).unwrap();

        cursor.write_u8(self.style).unwrap();

        let mac_bytes = self.mac.as_bytes();
        cursor.write_all(&mac_bytes).unwrap();

        let ip_bytes = match self.bind_ip {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(_) => [0, 0, 0, 0],
        };
        cursor.write_all(&ip_bytes).unwrap();

        cursor.write_u8(self.bind_index).unwrap();

        cursor.write_u8(self.status2).unwrap();

        cursor.write_all(&self.good_output_b).unwrap();

        cursor.write_u8(self.status3).unwrap();

        let uid_bytes = self.default_responder.uid_serialize();
        cursor.write_all(&uid_bytes).unwrap();

        cursor.write_all(&[0 as u8; 15]).unwrap();

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPollReply
    pub fn deserialize(data : &Vec<u8>) -> Option<OpPollReply> {
        let mut rv = OpPollReply::new();

        let mut cursor = Cursor::new(data);

        let mut pad_bytes : [u8; 10] = [0; 10];

        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        let mut ip_bytes = [0; 4];
        if let Err(_) = cursor.read_exact(&mut ip_bytes) {
            return None;
        }

        rv.ip_address = IpAddr::from(ip_bytes);
        // Read port
        rv.port = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        // Read vers info
        rv.vers_info = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        // Read universe switch
        let high_bytes : u8 = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };
        let low_bytes : u8 = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };

        rv.universe_switch = ((low_bytes as u16) << 4) + ((high_bytes as u16) << 8);

        // rv.universe_switch = match cursor.read_u16::<BigEndian>() {
        //         Ok(n) => n,
        //         Err(_) => return None,
        //     };
        // Read oem
        rv.oem = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        // Read ubea version
        rv.ubea_version = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        // Read status1
        rv.status1 = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        // Read esta mfg
        rv.esta_mfg = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        // Read short name
        let mut short_name_bytes = [0; 18];
        if let Err(_) = cursor.read_exact(&mut short_name_bytes) {
            return None;
        }

        // rv.short_name = 
        rv.short_name = String::from_utf8_lossy(CStr::from_bytes_until_nul(&short_name_bytes).unwrap().to_bytes()).to_string();
        // Read long name
        let mut long_name_bytes = [0; 64];
        if let Err(_) = cursor.read_exact(&mut long_name_bytes) {
            return None;
        }
        rv.long_name = String::from_utf8_lossy(CStr::from_bytes_until_nul(&long_name_bytes).unwrap().to_bytes()).to_string();
        // Read node report
        let mut node_report_bytes = [0; 64];
        if let Err(_) = cursor.read_exact(&mut node_report_bytes) {
            return None;
        }
        rv.node_report = String::from_utf8_lossy(CStr::from_bytes_until_nul(&node_report_bytes).unwrap().to_bytes()).to_string(); // 172

        rv.num_ports = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };

        if let Err(_) = cursor.read_exact(&mut rv.port_types) {
            return None;
        }
        if let Err(_) = cursor.read_exact(&mut rv.good_input) {
            return None;
        }
        if let Err(_) = cursor.read_exact(&mut rv.good_output) {
            return None;
        }
        if let Err(_) = cursor.read_exact(&mut rv.sw_in) {
            return None;
        }
        if let Err(_) = cursor.read_exact(&mut rv.sw_out) {
            return None;
        }
        
        rv.priority = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };

        rv.sw_macro = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };

        rv.sw_remote = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };
        
        let mut spare_bytes : [u8; 3] = [0; 3]; 

        if let Err(_) = cursor.read_exact(&mut spare_bytes) {
            return None;
        }

        rv.style = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };

        let mut mac_bytes : [u8; 6] = [0; 6]; 

        if let Err(_) = cursor.read_exact(&mut mac_bytes) {
            return None;
        }

        rv.mac = MacAddress::from_bytes(&mac_bytes).unwrap_or_default(); 

        rv.bind_index = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.status2 = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };

        if let Err(_) = cursor.read_exact(&mut rv.good_output_b) {
            return None;
        }

        rv.status3 = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            }; // 47 


        let mut uid_bytes : [u8; 6] = [0; 6];

        if let Err(_) = cursor.read_exact(&mut uid_bytes) {
            return None;
        }

        rv.default_responder = Uid::from_bytes(&uid_bytes);

        return Some(rv);
    }

}

#[derive(Debug)]
pub struct OpTodRequest {
    pub net: u8,
    pub command: u8,
    pub add_count: u8,
    pub address: [u8; 32],
}

impl OpTodRequest {
    pub fn new() -> OpTodRequest {
        OpTodRequest { net: 0, command: 0, add_count: 0, address: [0; 32] }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpTodRequest as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        // Pad values
        cursor.write_all(&[0 as u8; 2]).unwrap();

        // Spare values
        cursor.write_all(&[0 as u8; 7]).unwrap();

        cursor.write_u8(self.net).unwrap();

        cursor.write_u8(self.command).unwrap();

        cursor.write_u8(self.add_count).unwrap();

        cursor.write_all(&self.address).unwrap();

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpTodRequest> {
        let mut rv = OpTodRequest::new();
        let mut cursor = Cursor::new(data);

        let mut pad_bytes : [u8; 21] = [0; 21];

        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        rv.net = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };

        rv.command = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };
        rv.add_count = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };

        for i in 0..(rv.add_count as usize) {
            rv.address[i] = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        }

        return Some(rv);
    }

}


#[derive(Debug)]
pub struct OpTodData {
    pub rdm_ver: u8,
    pub port: u8,
    pub bind_index: u8,
    pub net: u8,
    pub command_response: u8,
    pub address: u8,
    pub uid_total: u16,
    pub block_count: u8,
    pub uid_count: u8,
    pub tod: Vec<Uid>,
}

impl OpTodData {
    pub fn new() -> OpTodData {
        OpTodData { 
            rdm_ver: 1, 
            port: 1, 
            bind_index: 1, 
            net: 0, 
            command_response: 0, 
            address: 0, 
            uid_total: 0, 
            block_count: 0, 
            uid_count: 0, 
            tod: Vec::new() 
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpTodRequest as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        cursor.write_u8(self.rdm_ver).unwrap();
        cursor.write_u8(self.port).unwrap();
        
        cursor.write_all(&[0 as u8; 6]).unwrap();

        cursor.write_u8(self.bind_index).unwrap();
        cursor.write_u8(self.net).unwrap();

        cursor.write_u8(self.command_response).unwrap();
        cursor.write_u8(self.address).unwrap();

        cursor.write_u16::<BigEndian>(self.uid_total).unwrap();

        cursor.write_u8(self.block_count).unwrap();

        cursor.write_u8(self.uid_count).unwrap();

        for uid in &self.tod {
            let uid_bytes = uid.uid_serialize();
            cursor.write_all(&uid_bytes).unwrap();            
        }

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpTodData> {
        let mut rv = OpTodData::new();
        let mut cursor = Cursor::new(data);

        let mut pad_bytes : [u8; 12] = [0; 12];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        rv.rdm_ver = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.port = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        
        let mut pad_bytes : [u8; 6] = [0; 6];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        rv.bind_index = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.net = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.command_response = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.address = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.uid_total = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.block_count = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.uid_count = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };

        for i in 0..(rv.uid_count as usize) {
            let mut uid_bytes : [u8; 6] = [0; 6];
            if let Err(_) = cursor.read_exact(&mut uid_bytes) {
                return None;
            }

            rv.tod.push(Uid::from_bytes(&uid_bytes));
            
        }

        return Some(rv);
    }

}


#[derive(Debug)]
pub struct OpTodControl {
    pub net: u8,
    pub command: u8,
    pub address: u8,
}

impl OpTodControl {
    pub fn new() ->  OpTodControl {
        OpTodControl { net: 0, command: 0, address: 0 }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpTodControl as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        // Pad/spare data
        cursor.write_all(&[0 as u8; 9]).unwrap();

        cursor.write_u8(self.net).unwrap();
        cursor.write_u8(self.command).unwrap();
        cursor.write_u8(self.address).unwrap();        

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpTodControl> {

        if data.len() < 24 {
            return None;
        }

        let mut rv = OpTodControl::new();

        rv.net = data[21];
        rv.command = data[22];
        rv.address = data[23];
        
        return Some(rv);
    }

}

#[derive(Debug)]
pub struct OpRdm {
    pub rdm_ver: u8,
    pub net: u8,
    pub command: u8,
    pub address: u8,
    pub rdm_packet: Vec<u8>,
}

impl OpRdm {
    pub fn new() ->  OpRdm {
        OpRdm { 
            rdm_ver: 1, 
            net: 0, 
            command: 0, 
            address: 0, 
            rdm_packet: Vec::new() 
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpRdm as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        cursor.write_u8(self.rdm_ver).unwrap();

        // Pad/spare data
        cursor.write_all(&[0 as u8; 8]).unwrap();

        cursor.write_u8(self.net).unwrap();
        cursor.write_u8(self.command).unwrap();
        cursor.write_u8(self.address).unwrap();        

        cursor.write_all(&self.rdm_packet).unwrap();

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpRdm> {
        if data.len() < 24 {
            return None;
        }

        let mut rv = OpRdm::new();

        rv.rdm_ver = data[11];

        rv.net = data[20];
        rv.command = data[21];
        rv.address = data[22];
        

        // packet is in &data[23..]

        rv.rdm_packet = Vec::from(&data[23..]);

        return Some(rv);
    }

}


#[derive(Debug)]
pub struct OpCommand {
    pub esta_mfg: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl OpCommand{
    pub fn new() ->  OpCommand {
        OpCommand { 
            esta_mfg: 0, 
            length: 0, 
            data: Vec::new() 
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpCommand as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        cursor.write_u16::<BigEndian>(self.esta_mfg).unwrap();
        cursor.write_u16::<BigEndian>(self.length).unwrap();

        cursor.write_all(&self.data).unwrap();

        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpCommand> {
        let mut rv = OpCommand::new();
        let mut cursor = Cursor::new(data);

        let mut pad_bytes : [u8; 12] = [0; 12];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        rv.esta_mfg = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.length = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        
        for i in 0..rv.length {
            let b = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
            rv.data.push(b);
        }

        return Some(rv);
    }

}

#[derive(Debug)]
pub struct OpDmx {
    pub sequence: u8,
    pub physical: u8,
    pub universe: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl OpDmx {
    pub fn new() ->  OpDmx {
        OpDmx { 
            sequence: 0, 
            physical: 0, 
            universe: 0, 
            length: 0, 
            data: Vec::new() 
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        // Art-Net header
        cursor.write_all(&HEADER).unwrap();
        
        // OpCode
        cursor.write_u16::<LittleEndian>(OpCodeValues::OpDmx as u16).unwrap();
        
        // ProtVerHi = 0
        cursor.write_u8(0x00).unwrap();
        // ProtVerLo = 14
        cursor.write_u8(14).unwrap();

        cursor.write_u8(self.sequence).unwrap();
        cursor.write_u8(self.physical).unwrap();

        cursor.write_u16::<LittleEndian>(self.universe).unwrap();

        cursor.write_u16::<BigEndian>(self.length).unwrap();

        cursor.write_all(&self.data).unwrap();
        
        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpDmx> {
        let mut rv = OpDmx::new();
        let mut cursor = Cursor::new(data);

        let mut pad_bytes : [u8; 12] = [0; 12];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        rv.sequence = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.physical = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };

        rv.universe = match cursor.read_u16::<LittleEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        rv.length = match cursor.read_u16::<BigEndian>() {
                Ok(n) => n,
                Err(_) => return None,
            };
        
        for i in 0..rv.length {
            let b = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };
            rv.data.push(b);
        }

        return Some(rv);
    }
}

#[derive(Debug)]
pub struct OpError {
    pub code: String,
}

impl OpError {
    pub fn new() ->  OpError {
        OpError { code: "".to_string() }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        return data;
    }

    /// Assumes the packet has already been verified to be an ArtPoll
    pub fn deserialize(data : &Vec<u8>) -> Option<OpError> {
        let mut rv = OpError::new();
       

        return Some(rv);
    }
}