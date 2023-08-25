use log::{trace, debug};

pub struct ClientHello<'a> {
    pub payload: &'a mut [u8]
}

impl <'a> ClientHello<'a> {
    pub fn new(payload: &'a mut [u8]) -> Self {
        Self { payload: payload }
    }

    pub fn update_length(&mut self, len: u16) {
        self.payload[3..5].copy_from_slice(&len.to_be_bytes());
        self.payload[7..9].copy_from_slice(&(len-4).to_be_bytes());
    }
}

// TODO: We will improve the `()` into actual structured data
pub fn parse_client_hello(tcp_payload: &[u8]) -> Option<()> {

    // Make sure it is a handshake message
    if tcp_payload[0] != 0x16 {
        trace!("First byte is not 0x16, not a Handshake");
        return None
    }

    if tcp_payload[5] != 0x01 {
        trace!("6th byte is not 0x01, not a ClientHello");
    }

    // This would need to be patched eventually
    let tls_len = u16::from_be_bytes(tcp_payload[3..5].try_into().expect("insufficient length"));
    let mut u32_slice = [0 as u8; 4];
    u32_slice[1..].clone_from_slice(&tcp_payload[6..9]);
    let handshake_len = u32::from_be_bytes(u32_slice);
    debug!("TLS packet len is {}, handshake len is {}", tls_len, handshake_len);


    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn legit_client_hello(){
        env_logger::init();
        let packet: [u8; 322] = [22,3,1,1,61,1,0,1,57,3,3,49,180,5,102,52,61,214,19,46,19,202,104,139,219,55,86,101,197,88,110,139,115,43,166,196,123,70,243,208,36,52,4,32,187,229,51,15,170,55,217,215,215,223,175,114,118,99,76,8,147,197,42,165,41,223,107,229,3,176,240,250,98,224,198,216,0,62,19,2,19,3,19,1,192,44,192,48,0,159,204,169,204,168,204,170,192,43,192,47,0,158,192,36,192,40,0,107,192,35,192,39,0,103,192,10,192,20,0,57,192,9,192,19,0,51,0,157,0,156,0,61,0,60,0,53,0,47,0,255,1,0,0,178,0,0,0,25,0,23,0,0,20,116,114,97,99,107,101,114,46,109,121,119,97,105,102,117,46,98,101,115,116,0,11,0,4,3,0,1,2,0,10,0,22,0,20,0,29,0,23,0,30,0,25,0,24,1,0,1,1,1,2,1,3,1,4,0,35,0,0,0,22,0,0,0,23,0,0,0,13,0,42,0,40,4,3,5,3,6,3,8,7,8,8,8,9,8,10,8,11,8,4,8,5,8,6,4,1,5,1,6,1,3,3,3,1,3,2,4,2,5,2,6,2,0,43,0,5,4,3,4,3,3,0,45,0,2,1,1,0,51,0,38,0,36,0,29,0,32,182,248,236,13,117,186,178,180,61,55,119,252,134,115,85,43,120,111,154,238,8,179,77,238,250,122,232,167,155,185,43,47];
        parse_client_hello(&packet);
    }
}