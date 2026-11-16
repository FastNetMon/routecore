#![cfg(feature = "bgp")]

use std::net::Ipv6Addr;

use inetnum::addr::Prefix;
use inetnum::asn::Asn;
use octseq::Parser;
use routecore::bgp::{
    ParseError,
    message::{
        SessionConfig, UpdateMessage,
        open::{Capabilities, OpenBuilder},
        update_builder::UpdateBuilder,
    },
    nlri::afisafi::{
        Addpath, AfiSafiNlri, Ipv4MplsUnicastNlri, Ipv4MulticastNlri,
        Ipv4UnicastNlri, Nlri, NlriCompose, NlriType,
    },
    path_attributes::{OwnedPathAttributes, PaMap},
    types::{AfiSafiType, NextHop, PathId, RouteDistinguisher},
};

const FAMILIES: [AfiSafiType; 3] = [
    AfiSafiType::Ipv4Unicast,
    AfiSafiType::Ipv4Multicast,
    AfiSafiType::Ipv4MplsUnicast,
];

fn next_hops() -> Vec<(Vec<u8>, NextHop)> {
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let mut pair = global.octets().to_vec();
    pair.extend_from_slice(&link_local.octets());
    vec![
        (
            vec![192, 0, 2, 1],
            NextHop::Unicast("192.0.2.1".parse().unwrap()),
        ),
        (global.octets().to_vec(), NextHop::Unicast(global.into())),
        (pair, NextHop::Ipv6LL { global, link_local }),
    ]
}

#[test]
fn ipv4_next_hop_length_selects_address_family_and_consumes_exactly() {
    for family in FAMILIES {
        for (bytes, expected) in next_hops() {
            let mut wire = vec![bytes.len() as u8];
            wire.extend_from_slice(&bytes);
            wire.push(0xa5); // reserved/NLRI bytes must not be consumed
            let mut parser = Parser::from_ref(&wire);
            assert_eq!(
                NextHop::parse(&mut parser, family).unwrap(),
                expected
            );
            assert_eq!(parser.parse_u8().unwrap(), 0xa5);
            assert_eq!(parser.remaining(), 0);
        }
    }
}

#[test]
fn ipv4_next_hop_rejects_unsupported_lengths_and_truncation() {
    for family in FAMILIES {
        for len in 0u8..=255 {
            if [4, 16, 32].contains(&len) {
                continue;
            }
            let mut wire = vec![0; usize::from(len) + 1];
            wire[0] = len;
            assert_eq!(
                NextHop::parse(&mut Parser::from_ref(&wire), family),
                Err(ParseError::Unsupported)
            );
        }
        for len in [4u8, 16, 32] {
            for available in 0..usize::from(len) {
                let mut wire = vec![0; available + 1];
                wire[0] = len;
                assert_eq!(
                    NextHop::parse(&mut Parser::from_ref(&wire), family),
                    Err(ParseError::ShortInput)
                );
            }
        }
    }
}

#[test]
fn extended_lengths_do_not_change_other_address_families() {
    for family in [
        AfiSafiType::Ipv4RouteTarget,
        AfiSafiType::L2VpnVpls,
    ] {
        for len in [16u8, 32] {
            let mut wire = vec![0; usize::from(len) + 1];
            wire[0] = len;
            assert_eq!(
                NextHop::parse(&mut Parser::from_ref(&wire), family),
                Err(ParseError::Unsupported)
            );
        }
    }
    // EVPN takes the IPv4 or IPv6 address of the PE (RFC 7432), but not the
    // form with a link-local address.
    let mut wire = vec![0; 33];
    wire[0] = 32;
    assert_eq!(
        NextHop::parse(&mut Parser::from_ref(&wire), AfiSafiType::L2VpnEvpn),
        Err(ParseError::Unsupported)
    );
}

#[test]
fn second_address_is_kept_only_if_link_local() {
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    for family in [
        AfiSafiType::Ipv4Unicast,
        AfiSafiType::Ipv4Multicast,
        AfiSafiType::Ipv4MplsUnicast,
        AfiSafiType::Ipv6Unicast,
        AfiSafiType::Ipv6Multicast,
        AfiSafiType::Ipv6MplsUnicast,
    ] {
        for (second, expected) in [
            (
                "fe80::1",
                NextHop::Ipv6LL {
                    global,
                    link_local: "fe80::1".parse().unwrap(),
                },
            ),
            ("::", NextHop::Unicast(global.into())),
            ("2001:db8::2", NextHop::Unicast(global.into())),
        ] {
            let second: Ipv6Addr = second.parse().unwrap();
            let mut wire = vec![32];
            wire.extend_from_slice(&global.octets());
            wire.extend_from_slice(&second.octets());
            wire.push(0xa5);
            let mut parser = Parser::from_ref(&wire);
            assert_eq!(
                NextHop::parse(&mut parser, family).unwrap(),
                expected,
                "{family} with second address {second}"
            );
            assert_eq!(parser.parse_u8().unwrap(), 0xa5);
        }
    }
}

#[test]
fn vpn_next_hops_accept_ipv6_forms() {
    let rd = RouteDistinguisher::zeroes();
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();

    let mut v4 = vec![0; 8];
    v4.extend_from_slice(&[192, 0, 2, 1]);
    let mut v6 = vec![0; 8];
    v6.extend_from_slice(&global.octets());
    let mut v6_ll = v6.clone();
    v6_ll.extend_from_slice(&[0; 8]);
    v6_ll.extend_from_slice(&link_local.octets());

    let v4_nh = NextHop::MplsVpnUnicast(rd, "192.0.2.1".parse().unwrap());
    let v6_nh = NextHop::MplsVpnUnicast(rd, global.into());

    for (family, cases) in [
        (
            AfiSafiType::Ipv4MplsVpnUnicast,
            vec![(&v4, v4_nh), (&v6, v6_nh), (&v6_ll, v6_nh)],
        ),
        (
            AfiSafiType::Ipv6MplsVpnUnicast,
            vec![(&v6, v6_nh), (&v6_ll, v6_nh)],
        ),
    ] {
        let lens: Vec<u8> =
            cases.iter().map(|(b, _)| b.len() as u8).collect();
        for (bytes, expected) in cases {
            let mut wire = vec![bytes.len() as u8];
            wire.extend_from_slice(bytes);
            wire.push(0xa5);
            let mut parser = Parser::from_ref(&wire);
            assert_eq!(
                NextHop::parse(&mut parser, family).unwrap(),
                expected
            );
            assert_eq!(parser.parse_u8().unwrap(), 0xa5);
            assert_eq!(parser.remaining(), 0);

            for available in 0..bytes.len() {
                let mut wire = vec![0; available + 1];
                wire[0] = bytes.len() as u8;
                assert_eq!(
                    NextHop::parse(&mut Parser::from_ref(&wire), family),
                    Err(ParseError::ShortInput)
                );
            }
        }
        for len in (0u8..=255).filter(|len| !lens.contains(len)) {
            let mut wire = vec![0; usize::from(len) + 1];
            wire[0] = len;
            assert_eq!(
                NextHop::parse(&mut Parser::from_ref(&wire), family),
                Err(ParseError::Unsupported)
            );
        }
    }
}

fn update_wire(nh: &[u8], safi: u8, addpath: bool) -> Vec<u8> {
    let mut value = vec![0, 1, safi, nh.len() as u8];
    value.extend_from_slice(nh);
    value.push(0);
    if addpath {
        value.extend_from_slice(&42u32.to_be_bytes());
    }
    if safi == 4 {
        // Three-octet MPLS label (16, bottom of stack), then /24 prefix.
        value.extend_from_slice(&[48, 0, 1, 1, 198, 51, 100]);
    } else if safi == 128 {
        // Label, Route Distinguisher 0:1, then /24 prefix.
        value.extend_from_slice(&[112, 0, 1, 1]);
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        value.extend_from_slice(&[198, 51, 100]);
    } else if safi == 2 {
        value.extend_from_slice(&[24, 233, 252, 0]);
    } else {
        value.extend_from_slice(&[24, 198, 51, 100]);
    }
    let mut attrs = vec![0x90, 14];
    attrs.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attrs.extend_from_slice(&value);
    attrs.extend_from_slice(&[0x40, 1, 1, 0]);
    let mut wire = vec![0xff; 16];
    wire.extend_from_slice(&((23 + attrs.len()) as u16).to_be_bytes());
    wire.extend_from_slice(&[2, 0, 0]);
    wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    wire.extend_from_slice(&attrs);
    wire
}

#[test]
fn mp_reach_retains_ipv4_nlri_and_extended_next_hops_with_addpath() {
    for (family, safi) in FAMILIES.into_iter().zip([1, 2, 4]) {
        for (bytes, expected) in next_hops() {
            for addpath in [false, true] {
                let mut sc = SessionConfig::modern();
                if addpath {
                    sc.add_addpath_rxtx(family);
                }
                let update = UpdateMessage::from_octets(
                    update_wire(&bytes, safi, addpath),
                    &sc,
                )
                .unwrap();
                assert_eq!(update.mp_next_hop().unwrap(), Some(expected));
                assert_eq!(update.find_next_hop(family).unwrap(), expected);
                let announced = update.announcements_vec().unwrap();
                assert_eq!(announced.len(), 1);
                assert_eq!(announced[0].afi_safi(), family);
                assert_eq!(
                    announced[0].nlri_type(),
                    NlriType::from((family, addpath))
                );
                if addpath {
                    let id = match &announced[0] {
                        Nlri::Ipv4UnicastAddpath(n) => Addpath::path_id(n),
                        Nlri::Ipv4MulticastAddpath(n) => Addpath::path_id(n),
                        Nlri::Ipv4MplsUnicastAddpath(n) => {
                            Addpath::path_id(n)
                        }
                        other => {
                            panic!("expected ADD-PATH NLRI, got {other:?}")
                        }
                    };
                    assert_eq!(id, PathId(42));
                }
                // Exercise the same ownership/validation conversion as RIBs.
                let owned: OwnedPathAttributes =
                    update.path_attributes().unwrap().into();
                assert!(
                    owned.iter().all(|pa| pa.unwrap().to_owned().is_ok())
                );
                assert!(PaMap::from_update_pdu(&update).is_ok());
            }
        }
    }
}

#[test]
fn ipv6_next_hop_requires_negotiated_extended_next_hop() {
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut vpn_v4 = vec![0; 8];
    vpn_v4.extend_from_slice(&[192, 0, 2, 1]);
    let mut vpn_v6 = vec![0; 8];
    vpn_v6.extend_from_slice(&global.octets());
    let mut vpn_v6_ll = vpn_v6.clone();
    vpn_v6_ll.extend_from_slice(&[0; 8]);
    vpn_v6_ll.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());

    let plain: Vec<Vec<u8>> =
        next_hops().into_iter().map(|(bytes, _)| bytes).collect();
    let vpn = vec![vpn_v4, vpn_v6, vpn_v6_ll];

    for (family, safi, next_hops) in [
        (AfiSafiType::Ipv4Unicast, 1, &plain),
        (AfiSafiType::Ipv4Multicast, 2, &plain),
        (AfiSafiType::Ipv4MplsUnicast, 4, &plain),
        (AfiSafiType::Ipv4MplsVpnUnicast, 128, &vpn),
    ] {
        let other = if family == AfiSafiType::Ipv4Unicast {
            AfiSafiType::Ipv4Multicast
        } else {
            AfiSafiType::Ipv4Unicast
        };
        for bytes in next_hops {
            let wire = update_wire(bytes, safi, false);
            let ipv4 = matches!(bytes.len(), 4 | 12);
            let parses = |sc: &SessionConfig| {
                UpdateMessage::from_octets(&wire, sc).is_ok()
            };

            // Without session knowledge, as when reading from a file.
            assert!(parses(&SessionConfig::modern()));

            let mut sc = SessionConfig::modern();
            sc.restrict_extended_next_hop([]);
            assert_eq!(parses(&sc), ipv4, "{family} len {}", bytes.len());

            sc.restrict_extended_next_hop([other]);
            assert_eq!(parses(&sc), ipv4, "{family} len {}", bytes.len());

            sc.restrict_extended_next_hop([family]);
            assert!(parses(&sc), "{family} len {}", bytes.len());
        }
    }
}

#[test]
fn open_capability_lists_extended_next_hop_families() {
    let mut open = OpenBuilder::new_vec();
    open.set_asn(Asn::from_u32(64512));
    open.set_holdtime(180);
    open.set_bgp_id([192, 0, 2, 1]);
    open.add_mp(AfiSafiType::Ipv4Unicast);
    open.add_extended_next_hop(AfiSafiType::Ipv4Unicast);
    open.add_extended_next_hop(AfiSafiType::Ipv4MplsVpnUnicast);
    let open = open.into_message();
    assert_eq!(
        open.extended_next_hop_ids().collect::<Vec<_>>(),
        [AfiSafiType::Ipv4Unicast, AfiSafiType::Ipv4MplsVpnUnicast]
    );
    assert_eq!(
        Capabilities(&open.capabilities_as_vec())
            .extended_next_hop_ids()
            .collect::<Vec<_>>(),
        [AfiSafiType::Ipv4Unicast, AfiSafiType::Ipv4MplsVpnUnicast]
    );

    // One capability with several tuples. Only IPv4 NLRI with an IPv6 next
    // hop count: an IPv4 next hop AFI and a non-IPv4 NLRI AFI are skipped.
    let caps = [
        5, 18, //
        0, 1, 0, 2, 0, 2, //
        0, 1, 0, 4, 0, 1, //
        0, 2, 0, 1, 0, 2, //
    ];
    assert_eq!(
        Capabilities(&caps).extended_next_hop_ids().collect::<Vec<_>>(),
        [AfiSafiType::Ipv4Multicast]
    );
}

fn builder_roundtrip<A: AfiSafiNlri + NlriCompose + Clone>(
    nlri: A,
    next_hop: NextHop,
    addpath: bool,
) {
    let family = A::afi_safi();
    let mut sc = SessionConfig::modern();
    if addpath {
        sc.add_addpath_rxtx(family);
    }
    let mut builder = UpdateBuilder::new_vec();
    builder.add_announcement(nlri).unwrap();
    builder.set_nexthop(next_hop).unwrap();
    let update = builder.into_message(&sc).unwrap();
    assert_eq!(update.mp_next_hop().unwrap(), Some(next_hop));
    assert_eq!(update.find_next_hop(family).unwrap(), next_hop);
    let announced = update.announcements_vec().unwrap();
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].nlri_type(), NlriType::from((family, addpath)));
    let path_id = match &announced[0] {
        Nlri::Ipv4UnicastAddpath(n) => Some(Addpath::path_id(n)),
        Nlri::Ipv4MulticastAddpath(n) => Some(Addpath::path_id(n)),
        Nlri::Ipv4MplsUnicastAddpath(n) => Some(Addpath::path_id(n)),
        _ => None,
    };
    assert_eq!(path_id, addpath.then_some(PathId(42)));
}

#[test]
fn builder_roundtrips_ipv4_with_ipv6_next_hops() {
    let prefix: Prefix = "198.51.100.0/24".parse().unwrap();
    let unicast: Ipv4UnicastNlri = prefix.try_into().unwrap();
    let multicast: Ipv4MulticastNlri =
        "233.252.0.0/24".parse::<Prefix>().unwrap().try_into().unwrap();

    // Labeled unicast NLRI are taken from a parsed UPDATE.
    let labeled_wire = update_wire(&[192, 0, 2, 1], 4, false);
    let labeled_update = UpdateMessage::from_octets(
        labeled_wire.as_slice(),
        &SessionConfig::modern(),
    )
    .unwrap();
    let labeled = labeled_update
        .typed_announcements::<_, Ipv4MplsUnicastNlri<_>>()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();

    for (_, next_hop) in next_hops() {
        builder_roundtrip(unicast, next_hop, false);
        builder_roundtrip(unicast.into_addpath(PathId(42)), next_hop, true);
        builder_roundtrip(multicast, next_hop, false);
        builder_roundtrip(multicast.into_addpath(PathId(42)), next_hop, true);
        builder_roundtrip(labeled, next_hop, false);
        builder_roundtrip(
            labeled.into_addpath(PathId(42)),
            next_hop,
            true,
        );
    }
}

#[test]
fn builder_default_next_hop_roundtrips_for_multicast() {
    let nlri: Ipv4MulticastNlri =
        "233.252.0.0/24".parse::<Prefix>().unwrap().try_into().unwrap();
    let mut builder = UpdateBuilder::new_vec();
    builder.add_announcement(nlri).unwrap();
    let update = builder.into_message(&SessionConfig::modern()).unwrap();
    assert_eq!(
        update.mp_next_hop().unwrap(),
        Some(NextHop::new(AfiSafiType::Ipv4Multicast))
    );
}

#[test]
fn builder_sets_link_local_next_hop_for_ipv4_nlri() {
    let nlri: Ipv4UnicastNlri = "198.51.100.0/24"
        .parse::<Prefix>()
        .unwrap()
        .try_into()
        .unwrap();
    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let sc = SessionConfig::modern();

    // On top of the IPv4 placeholder a new builder starts with.
    let mut builder = UpdateBuilder::new_vec();
    builder.add_announcement(nlri).unwrap();
    builder.set_nexthop_ll_addr(link_local).unwrap();
    assert_eq!(
        builder.into_message(&sc).unwrap().mp_next_hop().unwrap(),
        Some(NextHop::Ipv6LL { global: Ipv6Addr::UNSPECIFIED, link_local })
    );

    // On top of an explicitly set global address.
    let mut builder = UpdateBuilder::new_vec();
    builder.add_announcement(nlri).unwrap();
    builder.set_nexthop(NextHop::Unicast(global.into())).unwrap();
    builder.set_nexthop_ll_addr(link_local).unwrap();
    assert_eq!(
        builder.into_message(&sc).unwrap().mp_next_hop().unwrap(),
        Some(NextHop::Ipv6LL { global, link_local })
    );

    // Not on a next hop that has no room for a link-local address.
    let mut builder = UpdateBuilder::new_vec();
    builder.add_announcement(nlri).unwrap();
    builder
        .set_nexthop(NextHop::MplsVpnUnicast(
            RouteDistinguisher::zeroes(),
            global.into(),
        ))
        .unwrap();
    assert!(builder.set_nexthop_ll_addr(link_local).is_err());
}
