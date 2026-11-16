use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use octseq::{Octets, Parser};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use crate::bgp::types::RouteDistinguisher;
use crate::util::parser::{parse_ipv4addr, parse_ipv6addr, ParseError};

use super::afisafi::AfiSafiType as AfiSafi;

/// Conventional and BGP-MP Next Hop variants.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))] 
pub enum NextHop {
    /// Composes like `Unicast`. Never produced when parsing, as the wire
    /// format does not distinguish the two.
    Multicast(IpAddr),
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))] 
    Ipv6LL{global: Ipv6Addr, link_local: Ipv6Addr}, // is this always unicast?
    MplsVpnUnicast(RouteDistinguisher, IpAddr),
    Empty, // FlowSpec
    Unimplemented(AfiSafi),
    #[cfg_attr(feature = "serde", serde(untagged, serialize_with = "serialize_unicast"))]
    Unicast(IpAddr),
}

#[cfg(feature = "serde")]
fn serialize_unicast<S>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    match ip {
        IpAddr::V4(v4) => s.serialize_newtype_variant("Afisafi", 0, "ipv4Unicast", &v4),
        IpAddr::V6(v6) => s.serialize_newtype_variant("Afisafi", 1, "ipv6Unicast", &v6),
    }
}

impl NextHop {
    pub fn new(afisafi: AfiSafi) -> Self {
        use AfiSafi::*;
        match afisafi {
            Ipv4Unicast => Self::Unicast(Ipv4Addr::from(0).into()),
            Ipv6Unicast => Self::Unicast(Ipv6Addr::from(0).into()),
            // On the wire a multicast next hop is no different from a
            // unicast one, and `parse` yields `Unicast` for these families.
            Ipv4Multicast => Self::Unicast(Ipv4Addr::from(0).into()),
            Ipv6Multicast => Self::Unicast(Ipv6Addr::from(0).into()),

            Ipv4MplsUnicast => Self::Unicast(Ipv4Addr::from(0).into()),
            Ipv6MplsUnicast => Self::Unicast(Ipv6Addr::from(0).into()),

            Ipv4MplsVpnUnicast => Self::MplsVpnUnicast(
                RouteDistinguisher::zeroes(),
                Ipv4Addr::from(0).into()
            ),
            Ipv6MplsVpnUnicast => Self::MplsVpnUnicast(
                RouteDistinguisher::zeroes(),
                Ipv6Addr::from(0).into()
            ),

            Ipv4RouteTarget => Self::Unicast(Ipv4Addr::from(0).into()),

            Ipv4FlowSpec | Ipv6FlowSpec => Self::Empty,

            L2VpnVpls => Self::Unicast(Ipv4Addr::from(0).into()),
            L2VpnEvpn => Self::Unicast(Ipv4Addr::from(0).into()),
            AfiSafi::Unsupported(_, _) => Self::Unimplemented(afisafi)
        }
    }
}

impl std::fmt::Display for NextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast(ip) | Self::Multicast(ip)  => write!(f, "{}", ip),
            Self::Ipv6LL{global, link_local} => write!(f, "{} {} ", global, link_local),
            Self::MplsVpnUnicast(rd, ip) => write!(f, "rd {} {}", rd, ip),
            Self::Empty => write!(f, "empty"),
            Self::Unimplemented(afisafi) => {
                write!(f, "unimplemented for AfiSafi {}", afisafi)
            }
        }
    }
}



//--- NextHop in MP_REACH_NLRI -----------------------------------------------
impl NextHop {
    /// Parses the length-prefixed Next Hop field of an MP_REACH_NLRI.
    ///
    /// The Next Hop length selects the encoding. For the IPv4 families
    /// covered by RFC 8950 that includes IPv6 forms, so the result for e.g.
    /// [`AfiSafi::Ipv4Unicast`] is not necessarily an IPv4 address.
    ///
    /// This function has no session context: it accepts every encoding that
    /// is valid for `afisafi`. Whether an IPv6 next hop for an IPv4 family
    /// was negotiated (RFC 8950 section 4) is checked when parsing an UPDATE
    /// with a [`SessionConfig`], see
    /// [`SessionConfig::restrict_extended_next_hop`].
    ///
    /// The wire format does not distinguish unicast from multicast next
    /// hops, so `NextHop::Multicast` is never returned.
    ///
    /// [`SessionConfig`]: crate::bgp::message::SessionConfig
    /// [`SessionConfig::restrict_extended_next_hop`]:
    ///     crate::bgp::message::SessionConfig::restrict_extended_next_hop
    pub fn parse<R: Octets>(parser: &mut Parser<'_, R>, afisafi: AfiSafi)
        -> Result<Self, ParseError>
    {
        use AfiSafi::*;
        let len = parser.parse_u8()?;

        match afisafi {
            // RFC 8950 section 3: the next-hop length selects IPv4 (4) or
            // IPv6 (16, or 32 with a link-local address).
            Ipv4Unicast | Ipv4Multicast | Ipv4MplsUnicast => {
                Self::parse_plain(parser, len, &[4, 16, 32])
            }
            Ipv4RouteTarget | L2VpnVpls => {
                Self::parse_plain(parser, len, &[4])
            }
            // RFC 7432 section 9: the IPv4 or IPv6 address of the PE.
            L2VpnEvpn => Self::parse_plain(parser, len, &[4, 16]),
            // RFC 2545 section 3.
            Ipv6Unicast | Ipv6Multicast => {
                Self::parse_plain(parser, len, &[16, 32])
            }
            // RFC 8277 with RFC 2545 next hops. An IPv4 next hop is not
            // standardised for this family (6PE, RFC 4798, uses an
            // IPv4-mapped IPv6 address) but is accepted for compatibility.
            Ipv6MplsUnicast => {
                Self::parse_plain(parser, len, &[4, 16, 32])
            }
            // RFC 4364 section 4.3.2, and RFC 8950 section 3 for the IPv6
            // forms.
            Ipv4MplsVpnUnicast => Self::parse_vpn(parser, len, &[12, 24, 48]),
            // RFC 4659 section 3.2.1.
            Ipv6MplsVpnUnicast => Self::parse_vpn(parser, len, &[24, 48]),

            Ipv4FlowSpec | Ipv6FlowSpec => Ok(Self::Empty),

            AfiSafi::Unsupported(_, _) => Err(ParseError::Unsupported),
        }
    }

    /// Returns whether `len` is an IPv6 Next Hop length for an IPv4 family.
    ///
    /// These are the encodings of RFC 8950, which require the Extended Next
    /// Hop Encoding capability for `afisafi`.
    pub(crate) fn is_extended_len(afisafi: AfiSafi, len: u8) -> bool {
        use AfiSafi::*;
        match afisafi {
            Ipv4Unicast | Ipv4Multicast | Ipv4MplsUnicast => {
                matches!(len, 16 | 32)
            }
            Ipv4MplsVpnUnicast => matches!(len, 24 | 48),
            _ => false,
        }
    }

    /// Parses a next hop without Route Distinguisher.
    fn parse_plain<R: Octets>(
        parser: &mut Parser<'_, R>,
        len: u8,
        allowed: &[u8],
    ) -> Result<Self, ParseError> {
        if !allowed.contains(&len) {
            return Err(ParseError::Unsupported);
        }
        match len {
            4 => Ok(Self::Unicast(parse_ipv4addr(parser)?.into())),
            16 => Ok(Self::Unicast(parse_ipv6addr(parser)?.into())),
            32 => {
                let global = parse_ipv6addr(parser)?;
                let second = parse_ipv6addr(parser)?;
                Ok(match link_local(second) {
                    Some(link_local) => Self::Ipv6LL { global, link_local },
                    None => Self::Unicast(global.into()),
                })
            }
            _ => Err(ParseError::Unsupported),
        }
    }

    /// Parses a next hop prefixed with a Route Distinguisher.
    fn parse_vpn<R: Octets>(
        parser: &mut Parser<'_, R>,
        len: u8,
        allowed: &[u8],
    ) -> Result<Self, ParseError> {
        if !allowed.contains(&len) {
            return Err(ParseError::Unsupported);
        }
        let rd = RouteDistinguisher::parse(parser)?;
        match len {
            12 => Ok(Self::MplsVpnUnicast(rd, parse_ipv4addr(parser)?.into())),
            24 => Ok(Self::MplsVpnUnicast(rd, parse_ipv6addr(parser)?.into())),
            48 => {
                // The second RD and link-local address have no
                // representation in `NextHop`. VPN next hops resolve via
                // the global address, so only that one is kept.
                let global = parse_ipv6addr(parser)?;
                parser.advance(24)?;
                Ok(Self::MplsVpnUnicast(rd, global.into()))
            }
            _ => Err(ParseError::Unsupported),
        }
    }

    pub fn skip<R: Octets>(parser: &mut Parser<'_, R>)
        -> Result<(), ParseError>
    {
        let len = parser.parse_u8()?;
        parser.advance(len.into())?;
        Ok(())
    }
}


/// Returns `addr` if it is a link-local address.
///
/// RFC 2545 section 3 only allows a link-local address in the second half of
/// a 32-byte next hop. Implementations are known to send other values there
/// (e.g. the unspecified address), so anything else is ignored rather than
/// treated as an error, leaving just the global address.
fn link_local(addr: Ipv6Addr) -> Option<Ipv6Addr> {
    addr.is_unicast_link_local().then_some(addr)
}


#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn evpn_next_hops() {
        for ip in ["192.0.2.1", "2001:db8::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            let bytes = match ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut wire = vec![bytes.len() as u8];
            wire.extend_from_slice(&bytes);
            wire.push(0xab);
            let mut parser = Parser::from_ref(&wire);
            assert_eq!(NextHop::parse(&mut parser, AfiSafi::L2VpnEvpn),
                Ok(NextHop::Unicast(ip)));
            assert_eq!(parser.parse_u8().unwrap(), 0xab);
        }
    }

    #[test]
    fn evpn_invalid_next_hops() {
        for len in 0..=255u8 {
            if [4, 16].contains(&len) {
                for available in 0..usize::from(len) {
                    let mut wire = vec![len];
                    wire.resize(1 + available, 0);
                    assert_eq!(
                        NextHop::parse(&mut Parser::from_ref(&wire), AfiSafi::L2VpnEvpn),
                        Err(ParseError::ShortInput),
                    );
                }
            } else {
                let mut wire = vec![len];
                wire.resize(1 + usize::from(len), 0);
                assert_eq!(
                    NextHop::parse(&mut Parser::from_ref(&wire), AfiSafi::L2VpnEvpn),
                    Err(ParseError::Unsupported),
                );
            }
        }
    }

    #[test]
    fn ipv4_unicast_next_hop_lengths() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let cases = [
            (vec![192, 0, 2, 1], NextHop::Unicast(Ipv4Addr::new(192, 0, 2, 1).into())),
            (global.octets().to_vec(), NextHop::Unicast(global.into())),
            (
                [global.octets(), link_local.octets()].concat(),
                NextHop::Ipv6LL { global, link_local },
            ),
        ];
        for (bytes, expected) in cases {
            let mut wire = vec![bytes.len() as u8];
            wire.extend_from_slice(&bytes);
            wire.push(0xab);
            let mut parser = Parser::from_ref(&wire);
            assert_eq!(NextHop::parse(&mut parser, AfiSafi::Ipv4Unicast), Ok(expected));
            assert_eq!(parser.parse_u8().unwrap(), 0xab);
        }
    }

    #[test]
    fn ipv4_unicast_invalid_next_hops() {
        for len in 0..=255u8 {
            if [4, 16, 32].contains(&len) {
                continue;
            }
            let mut wire = vec![len];
            wire.resize(1 + usize::from(len), 0);
            assert_eq!(
                NextHop::parse(&mut Parser::from_ref(&wire), AfiSafi::Ipv4Unicast),
                Err(ParseError::Unsupported),
            );
        }
        for len in [4, 16, 32] {
            for available in 0..len {
                let mut wire = vec![len as u8];
                wire.resize(1 + available, 0);
                assert_eq!(
                    NextHop::parse(&mut Parser::from_ref(&wire), AfiSafi::Ipv4Unicast),
                    Err(ParseError::ShortInput),
                );
            }
        }
        assert_eq!(
            NextHop::parse(&mut Parser::from_ref(&&[4, 192, 0, 2, 1][..]), AfiSafi::Ipv6Unicast),
            Err(ParseError::Unsupported),
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn nexthop_serialize() {
        assert_eq!(
            serde_json::to_string(
                &NextHop::Unicast("1.2.3.4".parse().unwrap()))
            .unwrap(),
            "{\"ipv4Unicast\":\"1.2.3.4\"}"
        );
        assert_eq!(
            serde_json::to_string(
                &NextHop::Unicast("2001:db8:abcd::".parse().unwrap())
            ).unwrap(),
            "{\"ipv6Unicast\":\"2001:db8:abcd::\"}"
        );
        assert_eq!(
            serde_json::to_string(
                &NextHop::Ipv6LL{
                        global: "2001:db8:abcd::".parse().unwrap(),
                        link_local: "fe80::".parse().unwrap(),
                    }
            ).unwrap(),
            "{\"ipv6LL\":{\"global\":\"2001:db8:abcd::\",\"linkLocal\":\"fe80::\"}}"
        );
    }
}
