# Cloud/ —— 云端名单的公开加密快照

这里放的是 `whitelist.json` / `blacklist.json` 的**加密副本**，供扩展在
「Worker 接口不通」时作为备用通道取用（GitHub raw / 公共反代都能原样转发密文）。

- 文件格式：`*.json.enc`，外壳是 JSON 信封（`_enc` / `alg` / `kdf` / `iter` / `salt` / `iv` / `data`），
  正文用 PBKDF2-SHA256 派生密钥 + AES-256-GCM 加密，口令内置在扩展里。
- **不要**把明文 `*.json` 传到这里：那等于把整份名单公开。

## 名单更新后怎么发布

```bash
# 在扩展目录下执行（源目录默认为同级的 SilverFoxBlocker-Cloud 私有仓库）
node tools/encrypt_cloud.js --verify
```

生成的 `Cloud/blacklist.json.enc` / `Cloud/whitelist.json.enc` 提交到本目录即完成发布。

## 轮换口令（一般不需要）

```bash
node tools/encrypt_cloud.js --gen-key     # 打印新口令
```

把新口令同时写进：

1. `ui/options.js` 的 `SF_CLOUD_ENC_PASS`
2. `tools/encrypt_cloud.js` 的 `DEFAULT_PASS`

然后重新生成快照并一起发版。旧版本扩展解不开新快照时不会写坏本地名单，只会报
「快照解密失败」并继续使用直连 Worker 通道。
