use etherparse::SlicedPacket;
use log::{info, debug, error, trace};
use pnet::packet::{Packet, MutablePacket};

use crate::tls::client_hello::parse_client_hello;

mod client_hello;

pub fn strip_sni(packet: &[u8]) -> Option<Vec<u8>> {
    trace!("Original packet {:?}", packet);

    // TODO: Fix var name to ip_packet.
    let ethernet_packet: SlicedPacket = match SlicedPacket::from_ip(packet) {
        Err(e) => {
            error!("failed to parse packet {}", e);
            return None;
        },
        Ok(p) => p,
    };
    // debug!("Parsed packet is {:?}", ethernet_packet);

    let payload_len = ethernet_packet.payload.len();
    debug!("Original packet len is {}", packet.len());

    // Hacky way to extract tcp header length
    let tcp_header_len = match ethernet_packet.transport {
        Some(tp) => match tp {
            etherparse::TransportSlice::Tcp(t) => t.slice().len(),
            _ => {
                debug!("Not TCP, returning None...");
                return None;
            }
        },
        None => {
            debug!("No transport, returning None. Packet: {:?}", ethernet_packet);
            return None;
        }
    };

    debug!("TCP Header len is {}", tcp_header_len);
    debug!("TCP Payload len is {}", payload_len);

    // Only needs TCP header and TCP payload
    let mut new_tcp_data: Vec<u8> = Vec::with_capacity(tcp_header_len + payload_len);
        
    // Copy the TCP header into it
    new_tcp_data.extend_from_slice(&packet[20..20+tcp_header_len]);
    

    let mut binding = ethernet_packet.payload.to_owned();
    let mut ch = match parse_client_hello(&mut binding) {
        Some(ch) => ch,
        None => return None,
    };

    let mut new_tls_data: Vec<u8> = Vec::with_capacity(payload_len);

    // Fantastic reference: https://tls12.xargs.org/#client-hello
    // 5 + 4 + 2 + 32 + 1 = 43 bytes of data we can always skip.
    let mut pos = 43;

    // next byte is length of existing session (if any)
    let session_length = u8::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 1)?.try_into().expect("Fucked up"));
    pos += 1;
    // println!("session length is {:?}, data is {:x?}", session_length, &ethernet_packet.payload[pos .. pos + session_length as usize]);
    pos += session_length as usize;

    // next two bytes give use length of Cipher Suite data
    let cs_length = u16::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 2)?.try_into().expect("Fucked up"));
    pos += 2;
    // println!("Cipher Suite length is {:?}, data is {:x?}", cs_length, &ethernet_packet.payload[pos .. pos + cs_length as usize]);
    pos += cs_length as usize;

    // next byte is length of compression data
    let cd_length = u8::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 1)?.try_into().expect("Fucked up"));
    pos += 1;
    // println!("compression data length is {:?}, data is {:x?}", cd_length, &ethernet_packet.payload[pos .. pos + cd_length as usize]);
    pos += cd_length as usize;

    // Up until here, we need to copy EVERYTHING
    new_tls_data.extend_from_slice(&ethernet_packet.payload[0..pos]);

    // next two bytes are length of extensions
    let extension_length = u16::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 2)?.try_into().expect("Fucked up"));
    pos += 2;
    // println!("extension length is {:?}, data is {:x?}", extension_length, &ethernet_packet.payload[pos .. pos + extension_length as usize]);
    // println!("extension length is {:?}", extension_length);
    debug!("Extensions length is {}", extension_length);

    let mut extension_data: Vec<u8> = Vec::with_capacity(extension_length as usize);

    // loop over extensions
    // read ext_type(u16) and ext_len(u16)
    // if ext_type==0x00 (SNI), skip it, and add (4 + value of ext_len) to skipped_bytes
    // we won't copy these bytes into final packet
    // essentially we strip it from the packet
    // 
    // return resulting packet without SNI data
    
    let mut ext_pos: usize = 0;
    let mut skipped_bytes = 0;

    while ext_pos < extension_length as usize {
        let ext_type = u16::from_be_bytes(ethernet_packet.payload.get(pos + ext_pos .. pos + ext_pos + 2)?.try_into().expect("Fucked up"));
        ext_pos += 2;
        let ext_length = u16::from_be_bytes(ethernet_packet.payload.get(pos + ext_pos .. pos + ext_pos + 2)?.try_into().expect("Fucked up"));
        ext_pos += 2;
        trace!("Found extension, type=0x{:04X?} & length=0x{:04X?}", ext_type, ext_length);

        if ext_type != 0x00 {
            trace!("Non SNI extension, we will add this guy...");
            extension_data.extend_from_slice(&u16::to_be_bytes(ext_type));
            extension_data.extend_from_slice(&u16::to_be_bytes(ext_length));
            extension_data.extend_from_slice(&ethernet_packet.payload[pos + ext_pos .. pos + ext_pos + ext_length as usize]);
        } else {
            debug!("Found SNI extension! We should skip the next 0x{:04X?} bytes!", ext_length);
            // We would want to skip the next ext_length bytes
            // But also, not copy the 4 bytes of extension type , extension length
            skipped_bytes += 4 + ext_length;
        }

        ext_pos += ext_length as usize;
    }

    debug!("Current pos+ext_pos is {}", pos + ext_pos);
    debug!("We are gonna cut {} bytes.", skipped_bytes);

    // New extension length
    let new_extension_length = extension_length - skipped_bytes;
    debug!("New extension length is {}", new_extension_length);
    new_tls_data.extend_from_slice(&u16::to_be_bytes(new_extension_length));
    new_tls_data.extend_from_slice(&extension_data);

    debug!("Old TCP Payload len is {}", ethernet_packet.payload.len());
    debug!("New TCP Payload len is {}", new_tls_data.len());

    trace!("OLD packet is {:02x?}", ethernet_packet.payload);
    trace!("NEW packet is {:02x?}", new_tls_data);

    ch.payload = &mut new_tls_data;
    ch.update_length(ch.payload.len() as u16);
    debug!("New CH is {:02X?}", ch.payload);
    debug!("New CH len is {}", ch.payload.len());
    new_tcp_data.extend_from_slice(ch.payload);


    match pnet::packet::ipv4::MutableIpv4Packet::new(&mut Vec::from(&packet[0..packet.len()-skipped_bytes as usize])) {
        Some(mut p) => {
            debug!("Old IPv4 packet is {:?}", p);
            debug!("old checksum 0x{:04X?}", p.get_checksum());
            // p.payload().s
            // p.se
    
            // let tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(p.payload_mut()).expect("fucc");
            // We need to make a TCP packet, and update the checksum and length
            let mut ntcp = pnet::packet::tcp::MutableTcpPacket::new(&mut new_tcp_data).unwrap();
            debug!("Old TCP packet is {:?}", ntcp);
            // ntcp.set_payload(ch.payload);
            ntcp.set_checksum(pnet::packet::tcp::ipv4_checksum(&ntcp.to_immutable(), &p.get_source(), &p.get_destination()));
            debug!("New TCP packet is {:?}", ntcp);
            
            p.set_payload(ntcp.packet());
            p.set_total_length(p.get_header_length() as u16 * 4 + new_tcp_data.len() as u16);
            let nsum = pnet::packet::ipv4::checksum(&p.to_immutable());
            p.set_checksum(nsum);
            debug!("checksum is now 0x{:04X?}", nsum);
            debug!("New IPv4 packet is {:?}", p);
            Some(p.packet().to_vec())
        },
        None => None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_legit() {
        // A TLS Client Hello Manually Captured at Ethernet Frame
        let packet: [u8; 583] = [
            196, 104, 208, 137, 87, 251, 0, 40, 248, 158, 117, 85, 8, 0, 69, 0, 2, 57, 131, 16, 64,
            0, 64, 6, 255, 57, 192, 168, 128, 128, 172, 64, 201, 11, 191, 16, 1, 187, 213, 80, 4,
            147, 80, 223, 65, 122, 128, 24, 1, 246, 158, 137, 0, 0, 1, 1, 8, 10, 20, 131, 119, 49,
            168, 185, 238, 224, 22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 46, 100, 91, 225, 60, 242, 109,
            71, 168, 84, 54, 64, 29, 170, 54, 107, 134, 248, 37, 15, 15, 82, 60, 255, 134, 245,
            138, 76, 18, 135, 154, 175, 32, 137, 0, 107, 73, 39, 15, 183, 40, 171, 225, 156, 24,
            116, 146, 204, 33, 95, 162, 210, 50, 105, 3, 57, 254, 180, 23, 202, 190, 235, 103, 65,
            123, 0, 62, 19, 2, 19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204,
            170, 192, 43, 192, 47, 0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192,
            10, 192, 20, 0, 57, 192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47,
            0, 255, 1, 0, 1, 117, 0, 0, 0, 16, 0, 14, 0, 0, 11, 105, 102, 99, 111, 110, 102, 105,
            103, 46, 99, 111, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0,
            25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116,
            116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 42, 0, 40,
            4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
            3, 3, 3, 1, 3, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 9, 8, 3, 4, 3, 3, 3, 2, 3, 1, 0, 45, 0,
            2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 253, 145, 47, 236, 113, 48, 41, 240, 119,
            11, 202, 50, 66, 164, 227, 193, 101, 112, 36, 165, 41, 178, 170, 60, 180, 183, 209, 90,
            174, 9, 90, 14, 0, 21, 0, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        strip_sni(&packet);
        // assert_eq!(parsed_sni.is_some(), true);
        // assert_eq!(parsed_sni, Some("ifconfig.co"));
    }

    #[test]
    fn is_legit_tcp(){
        env_logger::init();
        let packet: [u8; 569] = [69, 0, 2, 57, 7, 4, 64, 0, 64, 6, 233, 174, 192, 168, 128, 128, 95, 217, 167, 10, 140, 162, 1, 187, 144, 95, 105, 208, 102, 151, 61, 245, 128, 24, 1, 246, 248, 115, 0, 0, 1, 1, 8, 10, 54, 199, 142, 231, 27, 74, 238, 47, 22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 27, 86, 55, 70, 223, 45, 24, 142, 164, 62, 210, 136, 60, 171, 195, 99, 251, 221, 255, 135, 131, 107, 162, 217, 192, 138, 21, 228, 100, 211, 14, 70, 32, 168, 12, 219, 19, 168, 28, 139, 101, 253, 194, 2, 99, 88, 185, 200, 166, 214, 186, 36, 190, 200, 222, 17, 155, 176, 221, 100, 12, 223, 50, 132, 190, 0, 62, 19, 2, 19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204, 170, 192, 43, 192, 47, 0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192, 10, 192, 20, 0, 57, 192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47, 0, 255, 1, 0, 1, 117, 0, 0, 0, 25, 0, 23, 0, 0, 20, 116, 114, 97, 99, 107, 101, 114, 46, 109, 121, 119, 97, 105, 102, 117, 46, 98, 101, 115, 116, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 42, 0, 40, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 3, 1, 3, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 219, 168, 136, 106, 20, 232, 51, 13, 3, 32, 0, 14, 4, 165, 223, 178, 206, 37, 233, 94, 84, 191, 149, 253, 57, 235, 93, 206, 252, 178, 94, 114, 0, 21, 0, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        strip_sni(&packet);

    }
}
