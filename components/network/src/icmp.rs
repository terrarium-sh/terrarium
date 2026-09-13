use std::net::IpAddr;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet,
    Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

use super::{Error, MAX_FRAME_BYTES};

const MAX_ECHO_DATA: usize = 1492;

struct Echo {
    guest_mac: EthernetAddress,
    gateway_mac: EthernetAddress,
    guest: IpAddr,
    destination: IpAddr,
    ident: u16,
    seq: u16,
    data: Vec<u8>,
}

pub(crate) fn reply(
    frame: &[u8],
    gateway_ip: IpAddr,
    gateway_ip6: IpAddr,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(request) = parse(frame)? else {
        return Ok(None);
    };
    if request.destination != gateway_ip && request.destination != gateway_ip6 {
        return Ok(None);
    }
    request.reply().map(Some)
}

fn parse(frame: &[u8]) -> Result<Option<Echo>, Error> {
    let ethernet = EthernetFrame::new_checked(frame).map_err(|_| Error::Malformed)?;
    let guest_mac = ethernet.src_addr();
    let gateway_mac = ethernet.dst_addr();
    match ethernet.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ip = Ipv4Packet::new_checked(ethernet.payload()).map_err(|_| Error::Malformed)?;
            if ip.next_header() != IpProtocol::Icmp {
                return Ok(None);
            }
            let icmp = Icmpv4Packet::new_checked(ip.payload()).map_err(|_| Error::Malformed)?;
            let Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::ignored())
                .map_err(|_| Error::Malformed)?
            else {
                return Ok(None);
            };
            echo(
                guest_mac,
                gateway_mac,
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ident,
                seq_no,
                data,
            )
            .map(Some)
        }
        EthernetProtocol::Ipv6 => {
            let ip = Ipv6Packet::new_checked(ethernet.payload()).map_err(|_| Error::Malformed)?;
            if ip.next_header() != IpProtocol::Icmpv6 {
                return Ok(None);
            }
            let icmp = Icmpv6Packet::new_checked(ip.payload()).map_err(|_| Error::Malformed)?;
            let Icmpv6Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } = Icmpv6Repr::parse(
                &ip.src_addr(),
                &ip.dst_addr(),
                &icmp,
                &ChecksumCapabilities::ignored(),
            )
            .map_err(|_| Error::Malformed)?
            else {
                return Ok(None);
            };
            echo(
                guest_mac,
                gateway_mac,
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ident,
                seq_no,
                data,
            )
            .map(Some)
        }
        _ => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn echo(
    guest_mac: EthernetAddress,
    gateway_mac: EthernetAddress,
    guest: IpAddr,
    destination: IpAddr,
    ident: u16,
    seq: u16,
    data: &[u8],
) -> Result<Echo, Error> {
    if data.len() > MAX_ECHO_DATA {
        return Err(Error::Malformed);
    }
    Ok(Echo {
        guest_mac,
        gateway_mac,
        guest,
        destination,
        ident,
        seq,
        data: data.to_vec(),
    })
}

impl Echo {
    fn reply(&self) -> Result<Vec<u8>, Error> {
        match (self.guest, self.destination) {
            (IpAddr::V4(guest), IpAddr::V4(destination)) => {
                let icmp = Icmpv4Repr::EchoReply {
                    ident: self.ident,
                    seq_no: self.seq,
                    data: &self.data,
                };
                let ip = Ipv4Repr {
                    src_addr: destination,
                    dst_addr: guest,
                    next_header: IpProtocol::Icmp,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                };
                let mut reply = vec![0; 14 + ip.buffer_len() + icmp.buffer_len()];
                if reply.len() > MAX_FRAME_BYTES {
                    return Err(Error::Backpressure);
                }
                let mut ethernet = EthernetFrame::new_unchecked(&mut reply);
                ethernet.set_dst_addr(self.guest_mac);
                ethernet.set_src_addr(self.gateway_mac);
                ethernet.set_ethertype(EthernetProtocol::Ipv4);
                let checksum = ChecksumCapabilities::default();
                ip.emit(
                    &mut Ipv4Packet::new_unchecked(ethernet.payload_mut()),
                    &checksum,
                );
                icmp.emit(
                    &mut Icmpv4Packet::new_unchecked(
                        &mut ethernet.payload_mut()[ip.buffer_len()..],
                    ),
                    &checksum,
                );
                Ok(reply)
            }
            (IpAddr::V6(guest), IpAddr::V6(destination)) => {
                let icmp = Icmpv6Repr::EchoReply {
                    ident: self.ident,
                    seq_no: self.seq,
                    data: &self.data,
                };
                let ip = Ipv6Repr {
                    src_addr: destination,
                    dst_addr: guest,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                };
                let mut reply = vec![0; 14 + ip.buffer_len() + icmp.buffer_len()];
                if reply.len() > MAX_FRAME_BYTES {
                    return Err(Error::Backpressure);
                }
                let mut ethernet = EthernetFrame::new_unchecked(&mut reply);
                ethernet.set_dst_addr(self.guest_mac);
                ethernet.set_src_addr(self.gateway_mac);
                ethernet.set_ethertype(EthernetProtocol::Ipv6);
                ip.emit(&mut Ipv6Packet::new_unchecked(ethernet.payload_mut()));
                icmp.emit(
                    &destination,
                    &guest,
                    &mut Icmpv6Packet::new_unchecked(
                        &mut ethernet.payload_mut()[ip.buffer_len()..],
                    ),
                    &ChecksumCapabilities::default(),
                );
                Ok(reply)
            }
            _ => Err(Error::Malformed),
        }
    }
}
