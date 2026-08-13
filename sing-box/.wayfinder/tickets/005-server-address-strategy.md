# T05: 客户端连接地址策略（grilling）

- **label**: `wayfinder:grilling`
- **类型**: HITL（与用户对话定地址策略）
- **blocked by**: 无（frontier）
- **blocks**: 007（端到端验收矩阵）

## Question

客户端 outbound 的 `server` 字段（连接地址）是**唯一无法从服务端 config 直接取到**的信息——服务端 config 里只有监听端口和 TLS 域名，没有自己的公网地址。现状 `gen-client.sh`：
- `--server 域名/IP` 显式指定（双栈用域名优先，A+AAAA 自动选路）
- 缺省用 `curl ifconfig.me / icanhazip` **自动探测公网 IPv4**，失败则 `die1` 要求 `--server`

要拍板的问题：
1. **默认策略**：不传 `--server` 时自动探测公网 IP 是否仍是合理默认？还是应该反过来——强烈建议传域名（双栈 + CDN 前置），自动探测只作兜底？
2. **双栈语义**：域名（A+AAAA）自动选路 vs 探测到的单个 IPv4——两条路的行为是否都该支持并写进 runbook？v6 优先 or v4 优先的策略给谁定？
3. **探测失败行为**：离线/无公网时 `die1 报错` 还是生成 `server="localhost"` 之类占位让用户改？SNI（`tls.server_name`）与 `server` 是否必须解耦（服务端域名 vs 连接地址可以不同）？
4. **--insecure 自签**：自签证书时 `insecure:true` 自动加还是显式参数？hy2/tuic/anytls 的 `server_name` 现在填的是 `$SERVER`——若 server 是 IP、证书是域名，这里是否该用服务端 config 的域名？
5. **wireguard peer 地址**：wg 的 `peers[].address` 用哪个（服务端 config 能不能给，还是要 --server）？

产出：地址策略定案（默认值 + 双栈 + 失败行为 + 与 SNI/insecure 的联动 + wg 地址来源），写入 runbook。

## 为什么需要

连接地址是单输入流唯一需要外部信息的决策点，也是新手最容易配错的地方；地址与 SNI/insecure 的联动直接决定生成的 client.json 能不能连通。
