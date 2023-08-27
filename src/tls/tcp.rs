use log::{trace, debug};
use pnet::packet::{ipv4::{MutableIpv4Packet, checksum}, tcp::MutableTcpPacket, tcp::ipv4_checksum, Packet};

use crate::tls::strip_sni_v2;

// const NEW_PAYLOAD: [u8; 10] = [42, 42, 42, 42, 42, 42, 42, 42, 42, 42];

pub fn placeholder(packet: &[u8]) -> Option<Vec<u8>> {
    trace!("Recevied packet: {:02X?}", packet);

    let mut original_packet = Vec::from(packet);
    let ipv4_packet = MutableIpv4Packet::new(&mut original_packet).expect("Fail to make IPv4 packet");

    // 20 bytes is IPv4 Header, remianing is TCP header+payload
    let original_tcp_data = Vec::from(&packet[20..]);
    // let tcp_packet = MutableTcpPacket::new(&mut original_tcp_payload).expect("Fail to make TCP packet");

    // Technically only the first four bits contain the len, but they do so
    // as a multiple of four. So we need to first get those bits (& 0xF0 >> 4)
    // and then to multiply by four we left shift by 2, so we just right shift by 2
    let tcp_header_len = ((packet[20+12] & 0b1111_0000) >> 2) as usize; // First four bits give the header length
    trace!("Calculate TCP header len as {}", tcp_header_len);

    if packet.len() < 20 + tcp_header_len {
        debug!("Packet too small (NO PAYLOAD), skipping");
        return None;
    }

    let tcp_payload_len = packet.len() - (20 + tcp_header_len);
    
    if tcp_payload_len < 10 {
        debug!("Packet too small, skipping");
        return None;
    }

    debug!("TCP Header len is {}, TCP Payload len is {}", tcp_header_len, tcp_payload_len);

    // Manually convert paylod to "BBBBBBBBBB" (10 Bs)
    // trace!("Original TCP Packet: {:?}", tcp_packet);
    trace!("Original TCP Data: {:02X?}", original_tcp_data);

    // Get the new payload - SNI stripped!
    let new_payload = match strip_sni_v2(&original_tcp_data[tcp_header_len..]) {
        Some(np) => np,
        None => return None,
    };

    // New TCP packet buffer (we cannot modify the existing one)
    // Copy the header into it and then the new payload
    let mut new_tcp_packet_buffer: Vec<u8> = Vec::with_capacity(tcp_header_len as usize + new_payload.len());
    new_tcp_packet_buffer.extend_from_slice(&packet[20..20+tcp_header_len]);
    new_tcp_packet_buffer.extend_from_slice(&new_payload);

    // We need to recompute the checksum on this guy.
    let mut new_tcp_packet = MutableTcpPacket::new(&mut new_tcp_packet_buffer).expect("Fail to make TCP packet");
    new_tcp_packet.set_checksum(ipv4_checksum(&new_tcp_packet.to_immutable(), &ipv4_packet.get_source(), &ipv4_packet.get_destination()));
    trace!("New TCP Packet: {:?}", new_tcp_packet);
    trace!("New TCP Payload: {:02X?}", new_tcp_packet.payload());

    // Now we need to update the original IPv4 packet and its checksum and length fields
    trace!("Original IPv4 Packet: {:?}", ipv4_packet);
    trace!("Original IPv4 Payload: {:02X?}", ipv4_packet.payload());

    // New IPv4 packet buffer (we cannot modify existing one)
    // Copy the IPv4 header into it and the payload (which is a TCP packet)
    let mut new_ipv4_packet_buffer: Vec<u8> = Vec::with_capacity(20 + tcp_header_len as usize + new_payload.len());
    new_ipv4_packet_buffer.extend_from_slice(&packet[0..20]);
    new_ipv4_packet_buffer.extend_from_slice(&new_tcp_packet.packet());

    // Make the new packet with old header and new TCP data
    let mut new_ipv4_packet = MutableIpv4Packet::new(&mut new_ipv4_packet_buffer).expect("Fail to make IPv4 packet");

    // Set the new length, and then need to update checksum
    new_ipv4_packet.set_total_length(new_ipv4_packet.get_header_length() as u16 * 4 + new_tcp_packet_buffer.len() as u16);
    new_ipv4_packet.set_checksum(checksum(&new_ipv4_packet.to_immutable()));
    trace!("New IPv4 Packet: {:?}", new_ipv4_packet);
    trace!("New IPv4 Payload: {:02X?}", new_ipv4_packet.payload());

    Some(new_ipv4_packet.packet().to_vec())
}