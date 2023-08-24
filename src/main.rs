use log::info;
use tls::strip_sni;

mod tls;

struct State<'a>{
    blacklist: Vec<&'a str>
}

impl State<'_> {
    pub fn new(blacklist: Vec<&str>) -> State {
        State { blacklist: blacklist }
    }
}

fn queue_callback(msg: &nfqueue::Message, state: &mut State) {
    match strip_sni(msg.get_payload()) {
        Some(np) => {
            info!("Stripped sni, will send new packet :hapbruh:");
            msg.set_verdict_full(nfqueue::Verdict::Accept, 0, &np);
        },
        None => {
            info!("Did not strip sni, will accept as is.");
            msg.set_verdict(nfqueue::Verdict::Accept);
        }
    }
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
