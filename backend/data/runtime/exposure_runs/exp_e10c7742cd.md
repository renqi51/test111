# Exposure Analysis Report: exp_e10c7742cd

- Service: IMS
- MCC/MNC: 460/01
- Candidates: 1
- Assessments: 1
- Probe integrated: yes

## Candidate Assessments
### ims.mnc001.mcc460.pub.3gppnetwork.org
- Level/Score: medium / 0.5
- Protocols: SIP, DNS
- Network Functions: HSS, S-CSCF, I-CSCF, P-CSCF
- Evidence docs: 3GPP TS 23.003
- Probe: DNS=False HTTPS=None status=None
- Summary: The candidate IMS host ims.mnc001.mcc460.pub.3gppnetwork.org exposes multiple critical IMS network functions (HSS, S-CSCF, I-CSCF, P-CSCF) and uses SIP and DNS protocols. The FQDN follows a standard 3GPP pattern but is publicly resolvable, increasing asset discoverability. Probe observations indicate DNS resolution failure and no HTTPS data, limiting confirmation of service exposure. The confidence score is moderate (0.63), reflecting some uncertainty.

## Safety Notice
Probe is restricted to authorized lab environments only.
This system does not include unauthorized scanning.