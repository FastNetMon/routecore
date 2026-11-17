#![cfg(feature = "bgp")]

use std::net::Ipv6Addr;

use routecore::bgp::message::update::UpdateTreatment;
use routecore::bgp::message::{SessionConfig, UpdateMessage};
use routecore::bgp::types::AfiSafiType;

fn next_hops(afi: u16) -> Vec<Vec<u8>> {
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let mut hops = vec![
        global.octets().to_vec(),
        [global.octets(), link_local.octets()].concat(),
    ];
    if afi == 1 {
        hops.push(vec![192, 0, 2, 1]);
    }
    hops
}

fn mp_reach_update(
    afi: u16,
    next_hop: &[u8],
    reserved: u8,
    nlri: &[u8],
) -> Vec<u8> {
    let mut reach = afi.to_be_bytes().to_vec();
    reach.extend_from_slice(&[1, next_hop.len() as u8]); // Unicast SAFI.
    reach.extend_from_slice(next_hop);
    reach.push(reserved);
    reach.extend_from_slice(nlri);

    let mut attrs = vec![
        0x40,
        1,
        1,
        0, // ORIGIN: IGP.
        0x40,
        2,
        0, // Empty AS_PATH.
        0x80,
        14,
        reach.len() as u8,
    ];
    attrs.extend_from_slice(&reach);
    let mut wire = vec![0xff; 16];
    wire.extend_from_slice(&((23 + attrs.len()) as u16).to_be_bytes());
    wire.extend_from_slice(&[2, 0, 0]); // UPDATE, no withdrawals.
    wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    wire.extend_from_slice(&attrs);
    wire
}

#[test]
fn rejects_malformed_mp_reach_nlri_during_update_parsing() {
    for (afi, prefix, max_len) in [
        (1, vec![24, 192, 0, 2], 32),
        (2, vec![32, 0x20, 0x01, 0x0d, 0xb8], 128),
    ] {
        for next_hop in next_hops(afi) {
            let mut valid_then_invalid = prefix.clone();
            valid_then_invalid.push(max_len + 1);
            for nlri in [vec![max_len], vec![max_len + 1], valid_then_invalid]
            {
                let wire = mp_reach_update(afi, &next_hop, 0, &nlri);
                assert!(
                    UpdateMessage::from_octets(
                        &wire,
                        &SessionConfig::modern()
                    )
                    .is_err(),
                    "accepted malformed AFI {afi} NLRI {nlri:?} with {}-byte next hop",
                    next_hop.len(),
                );
            }
        }
    }
}

#[test]
fn validates_mp_reach_with_negotiated_addpath_context() {
    for (afi, family, prefix) in [
        (1, AfiSafiType::Ipv4Unicast, vec![24, 192, 0, 2]),
        (
            2,
            AfiSafiType::Ipv6Unicast,
            vec![32, 0x20, 0x01, 0x0d, 0xb8],
        ),
    ] {
        let mut config = SessionConfig::modern();
        config.add_addpath_rxtx(family);
        for next_hop in next_hops(afi) {
            // The path ID would be an invalid prefix length without ADD-PATH.
            let mut nlri = vec![255, 0, 0, 1];
            nlri.extend_from_slice(&prefix);
            let wire = mp_reach_update(afi, &next_hop, 0, &nlri);
            let update = UpdateMessage::from_octets(&wire, &config).unwrap();
            assert_eq!(update.treatment(), UpdateTreatment::Normal);
            let announcements = update
                .announcements()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(announcements.len(), 1);
            assert_eq!(announcements[0].afi_safi(), family);

            // Reject both a truncated prefix and a truncated subsequent path ID.
            nlri.pop();
            let mut truncated_id = vec![255, 0, 0, 1];
            truncated_id.extend_from_slice(&prefix);
            truncated_id.extend_from_slice(&[255, 0, 0]);
            for malformed in [nlri, truncated_id] {
                let wire = mp_reach_update(afi, &next_hop, 0, &malformed);
                assert!(UpdateMessage::from_octets(&wire, &config).is_err());
            }
        }
    }
}

#[test]
fn accepts_valid_and_empty_mp_reach_nlri() {
    for (afi, prefix) in [
        (1, vec![24, 192, 0, 2]),
        (2, vec![32, 0x20, 0x01, 0x0d, 0xb8]),
    ] {
        for next_hop in next_hops(afi) {
            for nlri in [prefix.clone(), vec![]] {
                let wire = mp_reach_update(afi, &next_hop, 0, &nlri);
                let update = UpdateMessage::from_octets(
                    &wire,
                    &SessionConfig::modern(),
                )
                .unwrap();
                assert_eq!(update.treatment(), UpdateTreatment::Normal);
                let announcements = update
                    .announcements()
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert_eq!(
                    announcements.len(),
                    usize::from(!nlri.is_empty())
                );
            }
        }
    }
}

#[test]
fn rejects_nonzero_mp_reach_reserved_byte() {
    for afi in [1, 2] {
        for next_hop in next_hops(afi) {
            let wire = mp_reach_update(afi, &next_hop, 1, &[]);
            assert!(
                UpdateMessage::from_octets(&wire, &SessionConfig::modern())
                    .is_err()
            );
        }
    }
}
