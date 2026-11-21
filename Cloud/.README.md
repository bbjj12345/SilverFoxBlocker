# Cloud/ —— 云端名单的公开加密快照

这里放的是 `whitelist.json` / `blacklist.json` 的**加密副本**，供扩展在
「Worker 接口不通」时作为备用通道取用（GitHub raw / 公共反代都能原样转发密文）。

- 文件格式：`*.json.enc`，外壳是 JSON 信封（`_enc` / `alg` / `kdf` / `iter` / `salt` / `iv` / `data`），
  正文用 PBKDF2-SHA256 派生密钥 + AES-256-GCM 加密，口令内置在扩展里。
- **不要**把明文 `*.json` 传到这里：那等于把整份名单公开。

## 一、先把最新的明文拉到本地

加密工具读的是**本机文件**，不是 GitHub 上的版本。私有仓库有改动却只改了线上，
本地那份就是旧的，打出来的快照也是旧的。

```bash
# 方式 A：clone（推荐，之后 git pull 即可）
git clone https://github.com/bbjj12345/SilverFoxBlocker-Cloud.git

# 方式 B：直接到仓库页面把两个 json 下载下来，覆盖本机同名文件
```

默认读取位置：`SilverFoxBlocker-Cloud/`（与本扩展目录同级），文件名必须保持
`blacklist.json` / `whitelist.json`。

## 二、生成加密快照

### 方式 1：双击网页工具（无需安装任何东西）

打开 `tools/pack-snapshot.html`（Chrome / Edge 双击即可），选两个 json →
「生成 .enc 并下载」。它会先解密回读比对，通过后才给你文件；全程在本机完成。

### 方式 2：命令行（需要本机装有 Node.js）

```bash
# 在扩展目录下执行
node tools/encrypt_cloud.js --verify
```

`--verify` = 加密后立刻解回来逐字比对，输出里应看到「回读校验通过」；
若要指定源目录：`node tools/encrypt_cloud.js --src "D:/path/to/SilverFoxBlocker-Cloud" --verify`。

生成的 `Cloud/blacklist.json.enc` / `Cloud/whitelist.json.enc` 提交到本目录即完成发布。

> `Cloud/.packed.json` 是命令行脚本顺手写的**本机记录**（记录这份密文由哪份明文打出来，
> 供自检比对），不需要上传。用网页工具打包时不会生成/更新它。

## 三、轮换口令（一般不需要）

```bash
node tools/encrypt_cloud.js --gen-key     # 打印新口令
```

把新口令同时写进：

1. `ui/options.js` 的 `SF_CLOUD_ENC_PASS`
2. `tools/encrypt_cloud.js` 的 `DEFAULT_PASS`
3. `tools/pack-snapshot.html` 里 `PASS`（内联脚本开头）

然后重新生成快照并一起发版。旧版本扩展解不开新快照时不会写坏本地名单，只会报
「快照解密失败」并继续使用直连 Worker 通道。
