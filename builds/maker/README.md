# EdgeOne DoH Maker

RFC 8484 盲转发端点。magdns 发什么就转什么，一个字节不改。ECS 完整透传。

## 部署步骤

1. EdgeOne 控制台 → 站点 → 边缘函数 → 新建
2. 函数名随便（如 `doh-relay`），粘贴 `edgeone-doh.js` 全文
3. **环境变量**：添加 `SECRET`，值 = 你和 magdns 共享的任意字符串
   - 例：`openssl rand -hex 16` 生成一个
4. **路由绑定**：匹配路径 `/dns-query`
5. 部署

## magdns 侧配置

```ini
# builds/dnsdist 的 config 里加：
upstream = https://你的edgeone域名.com/dns-query
maker_auth_kind = bearer
maker_auth_key = <与上面 SECRET 相同的值>
```

## 测试

```bash
# 健康检查（不需要认证）
curl https://你的域名/health
# 应返回 "ok"

# 带 auth 的真实查询
SECRET="你的值"
TOKEN="$SECRET"  # bearer 模式下 token == secret
python3 -c "
import struct,os
q=os.urandom(2)+struct.pack('!HHHHHH',0x0100,1,0,0,0,1)+b'\x07example\x03com\x00'+struct.pack('!HH',1,1)
open('/tmp/q.bin','wb').write(q)
"
curl -X POST https://你的域名/dns-query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/dns-message" \
  --data-binary @/tmp/q.bin | xxd | head -5
```

返回 `Content-Type: application/dns-message` + 二进制 DNS 报文 = 通了。

## 安全模型

- SECRET 只有你和 EdgeOne 知道，不在任何仓库中
- Bearer token 是 constant-time 比较，无时序泄露
- 上游 Google DoH 会透传 ECS 到权威 DNS（Cloudflare 不会，别换）
- EdgeOne 自带 DDoS 防护 + WAF，853/8853 的攻击面由 magdns 自己扛
