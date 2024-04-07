extern crate pnet;

use std::collections::HashMap;
use std::io::Read;
use log::{debug, error, info, trace, warn};

use env_logger::Env;
use std::fs;
use std::hash::Hash;


use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};

use std::time::{Duration, SystemTime, UNIX_EPOCH};
//use pcap::{Active, Capture, Packet};





//get integer mac address from its hexadecimal string representation
fn get_mac_address_from_str(iface: String) -> u64{

    let path = format!("/sys/class/net/{iface}/address");

    let addr_str = fs::read_to_string(path)
        .expect("I need root privileges to open this file!");

    let str_addr_vec: Vec<&str> = addr_str.trim().split(':').collect::<Vec<_>>();
    let mut int_addr_vec: Vec<u8> = vec![];

    for &x in &str_addr_vec {
        int_addr_vec.push( u8::from_str_radix(x, 16).unwrap() );
    }

    let result: u64 = (int_addr_vec[0] as u64 ) << 40 |
        (int_addr_vec[1] as u64) << 32 |
        (int_addr_vec[2] as u64) << 24 |
        (int_addr_vec[3] as u64) << 16 |
        (int_addr_vec[4] as u64) << 8 |
        int_addr_vec[5] as u64;

    println!("{:?}", result);
    return result;

}

//get integer mac address from bytes
fn get_mac_address_from_bytes(buffer: &[u8]) -> u64{

    let result: u64 = (buffer[0] as u64 ) << 40 |
        (buffer[1] as u64) << 32 |
        (buffer[2] as u64) << 24 |
        (buffer[3] as u64) << 16 |
        (buffer[4] as u64) << 8 |
        buffer[5] as u64;

    println!("{:?}", result);
    return result;

}




#[derive(Debug)]
struct Scanner{
    syn_count: i32,
    scanned_ports: Vec<u16>,
    syn_threshold: i32,
    window_len: i32,
    window_start_timestamp: Duration,       //now
    window_end_timestamp: Duration,     //40 seconds from now
    downtime_end: Duration,         //whenever the src_ip will end up in downtime this value will represent its duration
}


impl Scanner{

    fn new() -> Scanner{
        Scanner{
            syn_count: 0,
            scanned_ports: vec![],
            syn_threshold: 30,
            window_len: 40,
            window_start_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            window_end_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::new(40,0),
            downtime_end: Duration::ZERO,
        }
    }

    fn add_port(&mut self, port: u16){

        if !self.scanned_ports.contains(&port){
            self.scanned_ports.push(port);
            self.syn_count += 1;
        }
    }

    fn is_scan(&self) -> bool{
        return self.syn_count >= self.syn_threshold;
    }

    fn is_in_downtime(&self) -> bool{
        if self.downtime_end == Duration::ZERO {return false;}
        return SystemTime::now().duration_since(UNIX_EPOCH).expect("error retrieving systemtime").saturating_sub(self.downtime_end) == Duration::ZERO;
    }

    fn is_window_expired(&self) -> bool{
        return SystemTime::now().duration_since(UNIX_EPOCH).expect("error retrieving systemtime").saturating_sub(self.window_end_timestamp) != Duration::ZERO;
    }

}


struct ScannersManager{
    scanners: HashMap<String, Scanner>,
}

impl ScannersManager{
    fn new() -> ScannersManager{
        ScannersManager{
            scanners: HashMap::new(),
        }
    }

    fn is_new_ip(&self, ip:&String) -> bool{
        return !self.scanners.contains_key(ip);
    }


    //add potential scanner to hashmap
    fn add_scanner(&mut self, ip: String, port: u16){
        let mut scanner = Scanner::new();

        scanner.add_port(port);     //register scanned port

        self.scanners.insert(ip, scanner);      //add to hashmap
    }

    //add scanned port to the ports vector associated with the src_ip. Alert if syn_threshold is reached
    fn add_port(&mut self, ip: &String, port: u16){

        self.scanners.get_mut(ip).unwrap().add_port(port);


        let is_scan = self.scanners.get(ip).unwrap().is_scan();

        //alert and downtime the scanner to avoid multiple alerts from being generated during the same scan
        if is_scan{
            self.alert(ip);
            self.downtime_scanner(ip);
        }
    }

    fn alert(&self, ip: &String){
        //log here
        info!("inbound scan by ip: {}", ip);

    }

    fn downtime_scanner(&mut self, ip: &String){
        self.scanners.get_mut(ip).unwrap().downtime_end = SystemTime::now().duration_since(UNIX_EPOCH).expect("error retrieving systemtime") + Duration::new(80,0);
    }


    fn cleanup_routine(&mut self){
        self.scanners.retain(|_, v| !v.is_window_expired() && !v.is_in_downtime());
    }

}


//starts from 14th byte
#[derive(Debug)]
pub struct IPHeader{

    version: u8,
    ihl: u8,
    total_length: u16,
    flags: u8,
    protocol: u8,
    src_ip: String,

}

impl IPHeader{

    fn new(buffer: &[u8]) -> IPHeader{

        let octet_1 = buffer[12].to_string();
        let octet_2 = buffer[13].to_string();
        let octet_3 = buffer[14].to_string();
        let octet_4 = buffer[15].to_string();

        IPHeader{
            version: (buffer[0] & 0xf0) >> 4,
            ihl: buffer[0] & 0x0f,
            total_length: (buffer[2] as u16 ) << 8 | buffer[3] as u16,
            flags: buffer[6] & 0xe0,
            protocol: buffer[9],
            //src_ip: (buffer[12] as u32 ) << 24 | (buffer[13] as u32) << 16 | (buffer[14] as u32) << 8 | buffer[15] as u32,
            src_ip: format!("{octet_1}.{octet_2}.{octet_3}.{octet_4}"),
        }
    }
    fn filter_protocol(&self) -> bool{
        return self.protocol == 0x06;
    }

} //end IP struct


//TCP header
#[derive(Debug)]
pub struct TCPHeader{

    src_port: u16,
    dst_port:u16,
    seq: u32,
    ack:u32,
    hdr_len: u8,
    flags: u8,
}

impl TCPHeader {

    fn new(buffer: &[u8]) -> TCPHeader {
        TCPHeader {

            src_port: (buffer[0] as u16) << 8 | buffer[1] as u16,
            dst_port: (buffer[2] as u16) << 8 | buffer[3] as u16,
            seq: (buffer[4] as u32 ) << 24 | (buffer[5] as u32) << 16 | (buffer[6] as u32) << 8 | buffer[7] as u32,
            ack: (buffer[8] as u32 ) << 24 | (buffer[9] as u32) << 16 | (buffer[10] as u32) << 8 | buffer[11] as u32,
            hdr_len: (buffer[12] & 0xf0) >> 4,
            flags: buffer[13] & 0x3f
        }
    }

    fn is_src_ephemeral(&self) -> bool{ return self.src_port >= 1024; }
    fn is_flag_syn(&self) -> bool { return self.flags == 0x02;}

}





struct Sniffer{
    interface: String,
    receiver: Box<dyn DataLinkReceiver>,
    scanners_manager: ScannersManager,
}

impl Sniffer{

    fn new(interface_str: &str) -> Sniffer{

        let interface_names_match =
            |iface: &NetworkInterface| iface.name == interface_str;


        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap();

        // Create a new channel, dealing with layer 2 packets
        let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(_tx, rx)) => (_tx , rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("An error occurred when creating the data link channel: {}", e)
        };


        Sniffer{
            interface: String::from(interface_str),
            receiver: rx,
            scanners_manager: ScannersManager::new()
        }
    }



    //listen raw socket
    fn start(&mut self){

        info!("sniffer started");
        let mac_addr_int = get_mac_address_from_str(String::from(&self.interface));

        //filter frames based on ether type
        let filter_ether_type = |arr: &[u8]| -> bool { arr[0] == 0x08 && arr[1] == 0x00 };



        let mut cleanup_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("error retrieving systemtime") + Duration::new(120, 0);


        loop{
            match self.receiver.next() {
                Ok(packet) => {
                    let buffer = packet;


                    if SystemTime::now().duration_since(UNIX_EPOCH).unwrap() >= cleanup_time{
                        self.scanners_manager.cleanup_routine();
                        cleanup_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::new(120, 0);
                    }


                    if filter_ether_type(&buffer[12..14]) == false {
                        continue;
                    }

                    //filter mac here
                    //get_mac_address_from_bytes(&buffer[6 .. 12]);


                    let ip_hdr = IPHeader::new(&buffer[14 .. ]);
                    if !ip_hdr.filter_protocol(){ continue; }

                    //tcp header starts at 14 + ip_hdr_len
                    let ip_hdr_len = ip_hdr.ihl * 4;

                    //build tcp header from buffer slice
                    let tcp_hdr: TCPHeader = TCPHeader::new(&buffer[ 34 .. ]);
                    //only interested in syn packets, 0x02
                    if !tcp_hdr.is_flag_syn(){ continue }



                    //process packet

                    //ip has already been registered
                    if !self.scanners_manager.is_new_ip(&ip_hdr.src_ip) {

                        //is scanner in downtime ?
                        let is_in_downtime = self.scanners_manager.scanners.get(&ip_hdr.src_ip).unwrap().is_in_downtime();
                        if is_in_downtime{
                            continue;
                        }

                        let is_window_expired = self.scanners_manager.scanners.get(&ip_hdr.src_ip).unwrap().is_window_expired();
                        if is_window_expired{
                            self.scanners_manager.scanners.remove(&ip_hdr.src_ip);
                            continue;

                        }

                        self.scanners_manager.add_port(&ip_hdr.src_ip, tcp_hdr.dst_port);

                    }

                    //new ip
                    if self.scanners_manager.is_new_ip(&ip_hdr.src_ip){

                        self.scanners_manager.add_scanner(ip_hdr.src_ip, tcp_hdr.dst_port);

                    }



                }
                Err(e) => {
                    panic!("error while reading frame");
                }
            }
        }
    }



}// end sniffer class

fn main() {


    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    let interface= "lo";


    let mut sniffer = Sniffer::new(interface);
    sniffer.start();

}
