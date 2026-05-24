use tun_rs::DeviceBuilder;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // 1. Create the TUN interface and assign it an IP address
    let dev = DeviceBuilder::new()
        .name("tun0")
        .ipv4("10.0.0.1", 24, None)
        .mtu(1500)
        .build_async()?;

    println!("TUN interface 'tun0' created. Waiting for traffic...");

    // Buffer to hold the raw IP packets
    let mut buf = vec![0u8; 1500];

    // 2. The Capture Loop (Grabbing the traffic)
    loop {
        // This blocks asynchronously until the OS routes a packet to tun0
        let len = dev.recv(&mut buf).await?;
        // let raw_packet = &buf[..len];

        println!("Grabbed a raw IP packet of {} bytes", len);

        // NEXT STEPS FOR YOUR VPN:
        // 1. Encrypt `raw_packet` using ChaCha20Poly1305 or similar
        // 2. Send the encrypted bytes via a UdpSocket to your remote server
    }
}
