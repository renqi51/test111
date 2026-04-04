# Exposure Analysis Report: exp_cba56dd27e

- Service: IMS
- MCC/MNC: 460/001
- Candidates: 1
- Assessments: 1
- Probe integrated: yes

## Candidate Assessments
### ims.mnc001.mcc460.pub.3gppnetwork.org
- Level/Score: low / 0.429
- Protocols: SIP, DNS
- Network Functions: HSS, S-CSCF, I-CSCF, P-CSCF
- Evidence docs: 3GPP TS 23.003
- Probe: DNS=False HTTPS=None status=None
- Summary: ims.mnc001.mcc460.pub.3gppnetwork.org 的潜在暴露面等级为 low。

## Attack Paths
### path_ims_00
- Entrypoint: ims.mnc001.mcc460.pub.3gppnetwork.org
- Pivots: nf:HSS, nf:S-CSCF
- Target: HSS
- Likelihood: 0.5431
- Impact: low
- Validation: hypothesis

## Safety Notice
Probe is restricted to authorized lab environments only.
This system does not include unauthorized scanning.