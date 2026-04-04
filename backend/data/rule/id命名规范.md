# id 命名规范

## 总规则

- 全部小写
- 只允许字母、数字、下划线
- 统一使用 `前缀 + 语义名`
- `id` 一旦定了尽量不改
- 一个节点只能有一个 `type`
- 前缀必须和 `type` 对上
- 不允许再出现 `NF`、`Risk`、`Doc`、`NamingRule` 这种别名

## 前缀规则

| type | 前缀 |
|---|---|
| Service | `svc_` |
| NetworkFunction | `nf_` |
| Interface | `iface_` |
| Protocol | `proto_` |
| FQDNPattern | `fqdn_` |
| Platform | `plat_` |
| Capability | `cap_` |
| APIArtifact | `api_` |
| StandardDoc | `doc_` |
| RiskHypothesis | `risk_` |
| WorkProduct | `wp_` |
| Metric | `met_` |

## 推荐写法

### 服务
- `svc_vowifi`
- `svc_ims`
- `svc_rcs`
- `svc_open_gateway`

### 网元
- `nf_epdg`
- `nf_n3iwf`
- `nf_pcscf`

### 接口
- `iface_swu`
- `iface_rx`
- `iface_nb_api`

### 协议
- `proto_sip`
- `proto_ipsec`
- `proto_oauth2`

### 文档
- `doc_ts23228`
- `doc_ts24229`
- `doc_rfc6749`

### 风险
- `risk_dns_discovery`
- `risk_fqdn_enumeration`
- `risk_openapi_leakage`

## 文档 id 特别规则

- 3GPP：`doc_ts` + 编号  
  例如 `doc_ts23228`
- RFC：`doc_rfc` + 编号  
  例如 `doc_rfc6749`
- GSMA / CAMARA / OIDC：`doc_` + 稳定英文短名  
  例如 `doc_gsma_rcs_up`、`doc_oidc_discovery`
