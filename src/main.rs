use log::info;
use tls::{strip_sni, tcp::placeholder};

mod tls;

struct State<'a>{
    blacklist: Vec<&'a str>
}

impl State<'_> {
    pub fn new(blacklist: Vec<&str>) -> State {
        State { blacklist: blacklist }
    }
}

const hack_packet: [u8; 569] = [69, 0, 2, 57, 7, 4, 64, 0, 64, 6, 233, 174, 192, 168, 128, 128, 95, 217, 167, 10, 140, 162, 1, 187, 144, 95, 105, 208, 102, 151, 61, 245, 128, 24, 1, 246, 248, 115, 0, 0, 1, 1, 8, 10, 54, 199, 142, 231, 27, 74, 238, 47, 22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 27, 86, 55, 70, 223, 45, 24, 142, 164, 62, 210, 136, 60, 171, 195, 99, 251, 221, 255, 135, 131, 107, 162, 217, 192, 138, 21, 228, 100, 211, 14, 70, 32, 168, 12, 219, 19, 168, 28, 139, 101, 253, 194, 2, 99, 88, 185, 200, 166, 214, 186, 36, 190, 200, 222, 17, 155, 176, 221, 100, 12, 223, 50, 132, 190, 0, 62, 19, 2, 19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204, 170, 192, 43, 192, 47, 0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192, 10, 192, 20, 0, 57, 192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47, 0, 255, 1, 0, 1, 117, 0, 0, 0, 25, 0, 23, 0, 0, 20, 116, 114, 97, 99, 107, 101, 114, 46, 109, 121, 119, 97, 105, 102, 117, 46, 98, 101, 115, 116, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 42, 0, 40, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 3, 1, 3, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 219, 168, 136, 106, 20, 232, 51, 13, 3, 32, 0, 14, 4, 165, 223, 178, 206, 37, 233, 94, 84, 191, 149, 253, 57, 235, 93, 206, 252, 178, 94, 114, 0, 21, 0, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn queue_callback(msg: &nfqueue::Message, state: &mut State) {
    // placeholder(msg.get_payload());
    // msg.set_verdict(nfqueue::Verdict::Accept);

    match placeholder(msg.get_payload()) {
        Some(np) => {
            info!("Stripped sni, will send new packet :hapbruh: (Original Len: {}, New Len: {})", msg.get_payload().len(), np.len());
            // msg.set_verdict_full(nfqueue::Verdict::Accept, msg.get_id(), &np);
            // TODO: Fix to only make an IP packet, not whole ethernet packet.
            // info!("New packet is {:02X?}", np);
            msg.set_verdict_full(nfqueue::Verdict::Accept, msg.get_nfmark(), &np);
        },
        None => {
            info!("Did not strip sni, will accept as is.");
            msg.set_verdict(nfqueue::Verdict::Accept);
        }
    }
    // match strip_sni(msg.get_payload()) {
    //     Some(np) => {
    //         info!("Stripped sni, will send new packet :hapbruh: (Original Len: {}, New Len: {})", msg.get_payload().len(), np.len());
    //         // msg.set_verdict_full(nfqueue::Verdict::Accept, msg.get_id(), &np);
    //         // TODO: Fix to only make an IP packet, not whole ethernet packet.
    //         info!("New packet is {:02X?}", np);
    //         msg.set_verdict_full(nfqueue::Verdict::Accept, msg.get_nfmark(), &np);
    //     },
    //     None => {
    //         info!("Did not strip sni, will accept as is.");
    //         msg.set_verdict(nfqueue::Verdict::Accept);
    //     }
    // }
}

fn main() {
    env_logger::init();

    info!("Opening NFQUEUE");
    let mut q = nfqueue::Queue::new(State::new(Vec::new()));
    q.open();

    q.unbind(libc::AF_INET); // ignore result, failure is not critical here

    let rc = q.bind(libc::AF_INET);
    assert!(rc == 0);

    q.create_queue(0, queue_callback);
    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
    q.run_loop();
    
    println!("Hello, world!");
}
