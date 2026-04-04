# Exposure Analysis Report: exp_943c9e9fef

- Service: VoWiFi
- MCC/MNC: 460/01
- Candidates: 3
- Assessments: 3
- Probe integrated: yes

## Candidate Assessments
### wlan.mnc001.mcc460.3gppnetwork.org
- Level/Score: medium / 0.6
- Protocols: IPsec, IKEv2, DNS
- Network Functions: N3IWF, ePDG
- Evidence docs: 3GPP TS 23.003
- Probe: DNS=False HTTPS=None status=None
- Summary: The candidate host wlan.mnc001.mcc460.3gppnetwork.org is associated with VoWiFi services using IPsec, IKEv2, and DNS protocols, and network functions N3IWF and ePDG as per 3GPP TS 23.003. The confidence in this mapping is moderate (0.63). Probe observations indicate that DNS resolution failed and the host is not permitted due to an empty exposure allowlist configuration. The related risk includes potential leakage of entry point information through boundary service discovery chains. No HTTPS or TLS connectivity data is available to further assess secure communication.

### n3iwf.5gc.mnc001.mcc460.pub.3gppnetwork.org
- Level/Score: medium / 0.5
- Protocols: IPsec, IKEv2, DNS
- Network Functions: N3IWF
- Evidence docs: 3GPP TS 24.502, 3GPP TS 23.003
- Probe: DNS=False HTTPS=None status=None
- Summary: The candidate host n3iwf.5gc.mnc001.mcc460.pub.3gppnetwork.org is identified as an N3IWF network function used in VoWiFi services, with protocols including IPsec, IKEv2, and DNS. Evidence from 3GPP standards and graph inference supports this identification. However, probe observations indicate DNS resolution failed and the host is not permitted due to an empty allowlist configuration, limiting direct verification. The presence of boundary service discovery chains may leak entry point information, increasing exposure risk.

### epdg.epc.mnc001.mcc460.pub.3gppnetwork.org
- Level/Score: medium / 0.55
- Protocols: IPsec, IKEv2, DNS
- Network Functions: ePDG
- Evidence docs: 3GPP TS 24.502, 3GPP TS 23.003
- Probe: DNS=False HTTPS=None status=None
- Summary: The candidate host epdg.epc.mnc001.mcc460.pub.3gppnetwork.org is identified as an ePDG network function supporting VoWiFi with protocols IPsec, IKEv2, and DNS. The confidence in this identification is moderate (0.71) based on standard 3GPP documentation and graph inference. However, probe observations indicate that DNS resolution failed and the host is not permitted due to an empty allowlist configuration, limiting direct exposure verification. The related risk of boundary service discovery potentially leaking entry point information is noted but not fully evidenced here.

## Safety Notice
Probe is restricted to authorized lab environments only.
This system does not include unauthorized scanning.