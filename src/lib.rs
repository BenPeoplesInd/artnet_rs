use e1_20::Uid;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use eui48::MacAddress;
use std::io::Cursor;
use std::io::Write;
use std::io::Read;
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};


const HEADER: [u8; 8] = [65, 114, 116, 45, 78, 101, 116, 0]; // "Art-Net"

// pub fn art_serialize(op_code: OpCode) -> Result<Vec<u8>, OpError> {
//     bincode::serialize(&op_code).or(Err(OpError {
//         code: "Serialization error.".to_string(),
//     }))
// }

// pub fn art_deserialize(bytes: &[u8]) -> Result<OpCode, OpError> {
//     bincode::deserialize(bytes).or(Err(OpError {
//         code: "Deserialization error.".to_string(),
//     }))
// }

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

    pub fn deserialize(&self) -> Option<ArtPkt> {
        
        return None;
    }

}


#[derive(Debug)]
pub struct OpPoll {
    flags: u8,
    diag_priority: u8,
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
        let mut rv = OpPoll::new();

        rv.flags = data[12];
        rv.diag_priority = data[13];

        return Some(rv);
    }

}

// Cannot derive SerDes here for MacAddress
#[derive(Debug)]
pub struct OpPollReply {
    ip_address: IpAddr,
    port: u16,
    vers_info: u16,
    universe_switch: u16,
    oem: u16,
    ubea_version: u8,
    status1: u8,
    esta_mfg: u16,
    short_name: String,
    long_name: String,
    node_report: String,
    num_ports: u16,
    port_types: [u8; 4],
    good_input: [u8; 4],
    good_output: [u8; 4],
    sw_in: [u8; 4],
    sw_out: [u8; 4],
    priority: u8,
    sw_macro: [u8; 4],
    sw_remote: [u8; 4],
    style: u8,
    mac: MacAddress,
    bind_ip: IpAddr,
    bind_index: u8,
    status2: u8,
    good_output_b: [u8; 4],
    status3: u8,
    default_responder: Uid,
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
            sw_macro: [0; 4], 
            sw_remote: [0; 4], 
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
        cursor.write_all(&short_name_bytes).unwrap();
        // Write long name
        let long_name_bytes = self.long_name.as_bytes();
        cursor.write_all(&long_name_bytes).unwrap();
        // Write node report
        let node_report_bytes = self.node_report.as_bytes();
        cursor.write_all(&node_report_bytes).unwrap();
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
        cursor.write_all(&self.sw_macro).unwrap();
        // Write sw remote
        cursor.write_all(&self.sw_remote).unwrap();

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

        cursor.read_exact(&mut pad_bytes).unwrap();

        let mut ip_bytes = [0; 4];
        cursor.read_exact(&mut ip_bytes).unwrap();
        rv.ip_address = IpAddr::from(ip_bytes);
        // Read port
        rv.port = cursor.read_u16::<LittleEndian>().unwrap();
        // Read vers info
        rv.vers_info = cursor.read_u16::<LittleEndian>().unwrap();
        // Read universe switch
        rv.universe_switch = cursor.read_u16::<LittleEndian>().unwrap();
        // Read oem
        rv.oem = cursor.read_u16::<LittleEndian>().unwrap();
        // Read ubea version
        rv.ubea_version = cursor.read_u8().unwrap();
        // Read status1
        rv.status1 = cursor.read_u8().unwrap();
        // Read esta mfg
        rv.esta_mfg = cursor.read_u16::<LittleEndian>().unwrap();
        // Read short name
        let mut short_name_bytes = [0; 18];
        cursor.read_exact(&mut short_name_bytes).unwrap();
        rv.short_name = String::from_utf8_lossy(&short_name_bytes).to_string();
        // Read long name
        let mut long_name_bytes = [0; 64];
        cursor.read_exact(&mut long_name_bytes).unwrap();
        rv.long_name = String::from_utf8_lossy(&long_name_bytes).to_string();
        // Read node report
        let mut node_report_bytes = [0; 64];
        cursor.read_exact(&mut node_report_bytes).unwrap();
        rv.node_report = String::from_utf8_lossy(&node_report_bytes).to_string();

        rv.num_ports = cursor.read_u16::<LittleEndian>().unwrap();

        cursor.read_exact(&mut rv.port_types).unwrap();
        cursor.read_exact(&mut rv.good_input).unwrap();
        cursor.read_exact(&mut rv.good_output).unwrap();
        cursor.read_exact(&mut rv.sw_in).unwrap();
        cursor.read_exact(&mut rv.sw_out).unwrap();
        
        rv.priority = cursor.read_u8().unwrap();

        cursor.read_exact(&mut rv.sw_macro).unwrap();
        cursor.read_exact(&mut rv.sw_remote).unwrap();
        
        let mut spare_bytes : [u8; 3] = [0; 3];

        cursor.read_exact(&mut spare_bytes).unwrap();

        rv.style = cursor.read_u8().unwrap();

        let mut mac_bytes : [u8; 6] = [0; 6];

        cursor.read_exact(&mut mac_bytes).unwrap();

        rv.mac = MacAddress::from_bytes(&mac_bytes).unwrap();

        rv.bind_index = cursor.read_u8().unwrap();
        rv.status2 = cursor.read_u8().unwrap();

        cursor.read_exact(&mut rv.good_output_b).unwrap();

        rv.status3 = cursor.read_u8().unwrap();


        let mut uid_bytes : [u8; 6] = [0; 6];

        cursor.read_exact(&mut uid_bytes).unwrap();

        rv.default_responder = Uid::from_bytes(&uid_bytes);

        return Some(rv);
    }

}

#[derive(Debug)]
pub struct OpTodRequest {
    net: u8,
    command: u8,
    add_count: u8,
    address: [u8; 32],
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

        cursor.read_exact(&mut pad_bytes).unwrap();

        rv.net = cursor.read_u8().unwrap();
        rv.command = cursor.read_u8().unwrap();
        rv.add_count = cursor.read_u8().unwrap();

        for i in 0..(rv.add_count as usize) {
            rv.address[i] = cursor.read_u8().unwrap();
        }

        return Some(rv);
    }

}


#[derive(Debug)]
pub struct OpTodData {
    rdm_ver: u8,
    port: u8,
    bind_index: u8,
    net: u8,
    command_response: u8,
    address: u8,
    uid_total: u16,
    block_count: u8,
    uid_count: u8,
    tod: Vec<Uid>,
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
        cursor.read_exact(&mut pad_bytes).unwrap();

        rv.rdm_ver = cursor.read_u8().unwrap();
        rv.port = cursor.read_u8().unwrap();
        
        let mut pad_bytes : [u8; 6] = [0; 6];
        cursor.read_exact(&mut pad_bytes).unwrap();

        rv.bind_index = cursor.read_u8().unwrap();
        rv.net = cursor.read_u8().unwrap();
        rv.command_response = cursor.read_u8().unwrap();
        rv.address = cursor.read_u8().unwrap();
        rv.uid_total = cursor.read_u16::<BigEndian>().unwrap();
        rv.block_count = cursor.read_u8().unwrap();
        rv.uid_count = cursor.read_u8().unwrap();

        for i in 0..(rv.uid_count as usize) {
            let mut uid_bytes : [u8; 6] = [0; 6];
            cursor.read_exact(&mut uid_bytes).unwrap();

            rv.tod.push(Uid::from_bytes(&uid_bytes));
            
        }

        return Some(rv);
    }

}


#[derive(Debug)]
pub struct OpTodControl {
    net: u8,
    command: u8,
    address: u8,
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
        let mut rv = OpTodControl::new();

        rv.net = data[21];
        rv.command = data[22];
        rv.address = data[23];
        
        return Some(rv);
    }

}

#[derive(Debug)]
pub struct OpRdm {
    rdm_ver: u8,
    net: u8,
    command: u8,
    address: u8,
    rdm_packet: Vec<u8>,
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
    esta_mfg: u16,
    length: u16,
    data: Vec<u8>,
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
        cursor.read_exact(&mut pad_bytes).unwrap();

        rv.esta_mfg = cursor.read_u16::<BigEndian>().unwrap();
        rv.length = cursor.read_u16::<BigEndian>().unwrap();
        
        for i in 0..rv.length {
            rv.data.push(cursor.read_u8().unwrap());
        }

        return Some(rv);
    }

}

#[derive(Debug)]
pub struct OpDmx {
    sequence: u8,
    physical: u8,
    universe: u16,
    length: u16,
    data: Vec<u8>,
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
        cursor.read_exact(&mut pad_bytes).unwrap();

        rv.sequence = cursor.read_u8().unwrap();
        rv.physical = cursor.read_u8().unwrap();

        rv.universe = cursor.read_u16::<LittleEndian>().unwrap();
        rv.length = cursor.read_u16::<BigEndian>().unwrap();
        
        for i in 0..rv.length {
            rv.data.push(cursor.read_u8().unwrap());
        }

        return Some(rv);
    }
}

#[derive(Debug)]
pub struct OpError {
    code: String,
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