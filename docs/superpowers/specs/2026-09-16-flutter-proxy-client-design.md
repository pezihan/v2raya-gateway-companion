# 技术设计规格书：全平台 Flutter 代理客户端 (iOS / Android / macOS / Windows)

## 1. 概述与背景

### 1.1 项目目标
构建一款基于 **Flutter** 与 **sing-box** 内核的高性能、全平台（iOS、Android、macOS、Windows）通用代理客户端（支持 VMess、VLESS、Trojan、Shadowsocks 等主流协议）。
重点解决现有市面代理客户端“依赖静态白名单/GFWList，导致冷门或新被封锁域名无法及时分流访问”的痛点，提供**“移动/桌面端浏览器扩展一键加白”**与**“自动嗅探直连异常域名并建议代理”**的敏捷闭环机制。

### 1.2 核心特性矩阵
1. **全终端覆盖**：iOS (iPhone/iPad)、Android、macOS (Apple Silicon/Intel)、Windows (x64)。
2. **多协议与订阅支持**：支持 Base64 订阅链接、`vmess://`、`vless://`、`trojan://`、`ss://` 格式及 Clash YAML 配置解析。
3. **分流模式矩阵**：绕过大陆与局域网 (Bypass LAN & Mainland China)、绕过大陆 (Bypass Mainland China)、全局代理 (Global Proxy)、全局直连 (Direct)。
4. **自定义代理域名绝对第一优先级**：无论处于哪种路由模式，用户自定义规则池拥有最高路由匹配权重。
5. **双通道浏览器扩展**：
   - **iOS / macOS**：原生集成 Safari Web Extension，通过 App Group 共享存储即时同步。
   - **Android / Windows / macOS**：Manifest V3 通用浏览器扩展，通过本地 Localhost REST API（`127.0.0.1:9090`）实现 10ms 级即时写入。
6. **自动嗅探直连阻断域名（智能防封）**：底层捕获 TCP RST、握手连续超时、TLS ClientHello 阻断等 GFW 典型特征，在客户端首页以置顶卡片形式提醒用户一键加入代理。
7. **无断流热重载**：新增或修改域名规则时，通过 sing-box 的动态规则集（rule-set）接口热更新，不中断当前活跃的网络连接与 VPN 隧道。

---

## 2. 系统总体架构

整个系统分为三层：**Flutter 统一展示控制层**、**双端/多端原生网卡驱动层**、**sing-box 底层网络核心层**。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Flutter 统一应用层 (Dart 3.x)                     │
│  ┌─────────────────────────────────┐ ┌────────────────────────────────┐ │
│  │         UI / 交互表现层          │ │        业务与状态中枢 (Riverpod) │ │
│  │ • 首页仪表盘 (连接开关/实时速率)  │ │ • 订阅管理与多协议解析引擎   │ │
│  │ • 节点测速列表 (并发 TCP Ping)   │ │ • sing-box config.json 动态构建│ │
│  │ • 自定义域名规则管理器           │ │ • 本地数据库存储 (Isar DB)     │ │
│  │ • 智能嗅探建议待办卡片           │ │ • 本地 REST API 服务 (Port 9090)│ │
│  └─────────────────────────────────┘ └────────────────────────────────┘ │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Platform Channel / FFI
┌────────────────────────────────────▼────────────────────────────────────┐
│                       多平台底层驱动适配层                                │
├──────────────────┬──────────────────┬──────────────────┬────────────────┤
│    iOS 平台      │   Android 平台   │    macOS 平台    │  Windows 平台  │
├──────────────────┼──────────────────┼──────────────────┼────────────────┤
│ PacketTunnel     │ VpnService       │ PacketTunnel /   │ Wintun 驱动    │
│ Provider (独立)  │ (前台服务 + 通知)│ SystemExtension  │ (wintun.dll)   │
│ App Group 容器   │ JNI 句柄传递     │ Menu Bar 托盘    │ Taskbar 系统托盘│
│ Safari Extension │ WebExtension     │ Safari/Chrome 扩 │ Chrome/Edge 扩 │
└──────────────────┴─────────┬────────┴──────────────────┴────────────────┘
                             │ TUN Packet FileDescriptor (fd) / RingBuffer
┌────────────────────────────▼────────────────────────────────────────────┐
│                    sing-box 通用内核层 (Go / Libbox)                     │
│ • 内存虚拟网卡栈 (gVisor / System TUN 栈)                                │
│ • 协议加解密与多路复用 (VMess, VLESS + Reality, Trojan, Shadowsocks)     │
│ • 内置 DNS 分流解析器 (FakeIP / Direct DNS / Remote DNS)                │
│ • 动态分流路由引擎 (Local Rule-Set 热重载支持)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 核心功能与关键机制设计

### 3.1 路由匹配优先级设计
sing-box 路由表的规则判定严格遵循**自顶向下、首次命中原则**：

```
[传入网络数据包 / DNS 请求]
       │
       ▼
1. 【最高优先级】用户自定义强制代理域名 (Custom Proxy Domain RuleSet)
       ├── 命中 -> 输出至当前选中的代理节点出站 (Proxy Outbound)
       └── 未命中 ↓
2. 【次高优先级】用户自定义强制直连域名 (Custom Direct Domain RuleSet)
       ├── 命中 -> 输出至直连出站 (Direct Outbound)
       └── 未命中 ↓
3. 【系统模式分流】
       ├── 模式 A：全局代理 (Global Proxy) -> 全部走 Proxy Outbound
       ├── 模式 B：全局直连 (Global Direct) -> 全部走 Direct Outbound
       ├── 模式 C：绕过大陆与局域网 (Bypass LAN & CN)
       │     ├── 局域网私有地址 (192.168.x, 10.x 等) -> Direct
       │     ├── GeoIP:CN / Geosite:CN -> Direct
       │     └── 其余流量 -> Proxy
       └── 模式 D：绕过大陆 (Bypass CN)
             ├── GeoIP:CN / Geosite:CN -> Direct
             └── 其余流量 -> Proxy
       └── 未命中 ↓
4. 【默认兜底】系统最终出站 (Default Final Outbound)
```

### 3.2 智能嗅探被墙域名机制 (Smart Sniffing Engine)
1. **阻断特征判定模型**：
   - **TCP RST 阻断**：直连出站尝试与目标服务器建立三次握手时，在发送 SYN 后立即收到远端返回的 TCP RST 标志位（GFW 防火墙伪造响应的绝对特征）。
   - **三次握手超时**：在设备整体网络正常的前提下，针对特定海外目标域名的直连 SYN 包重传 3 次超时未响应。
   - **TLS SNI 阻断**：TCP 握手成功，但在发出含有明文 SNI 的 TLS ClientHello 后，连接瞬间被中间人重置或切断。
2. **处理流程**：
   - sing-box 监控直连出站错误，通过 EventChannel / IPC 向 Flutter 应用层发出报警事件：`{ domain: "notion.so", reason: "TCP_RST", target_ip: "104.18.x.x", timestamp: 1726470000 }`。
   - Flutter 接收后，自动启动后台影子校验（Shadow Verification）：使用当前选中的代理节点发起一次极简 HTTP HEAD 探针。
   - 若代理成功且直连失败，在客户端首页呈现**智能建议卡片**：
     - *“检测到 `notion.so` 直连遭到拦截阻断 (确信度 100%)”*
     - 提供三个动作按钮：**[ 一键加入代理 ]**、**[ 仅本次代理 ]**、**[ 忽略/放行 ]**。
   - 用户点击 **[ 一键加入代理 ]** 后，该域名即刻写入持久化数据库，并触发热重载，下一次访问立即畅通。

### 3.3 浏览器扩展联动架构

#### 方案 A：iOS & macOS 原生 Safari Web Extension
1. 在 Xcode 工程中内嵌 `SafariExtension` Target，与主 App 共享相同的 App Group：`group.com.agency.app`。
2. 用户在 Safari 工具栏点击扩展图标，弹窗显示：
   - 当前网站域名（如 `medium.com`，提供“根域名 `*.medium.com`”与“子域名 `sub.medium.com`”切换选项）。
   - 当前代理状态（已走代理 / 直连中）。
   - **[ 加入强制代理 ]** 按钮。
3. 点击后，扩展后台脚本通过 Swift Native Bridge 将域名追加至共享沙盒中的 `custom_rules.json`，并发送通知唤醒主进程或 `PacketTunnelProvider` 重新加载规则集。

#### 方案 B：Android / Windows / macOS 通用 WebExtension (Manifest V3)
1. 适配 Chrome、Edge、Firefox 以及 Android Kiwi 浏览器。
2. Flutter 客户端运行时在本地回路监听 HTTP REST API：`http://127.0.0.1:9090`。
3. 扩展点击触发简单 HTTP 交互：
   ```http
   POST /api/v1/rules/custom-domain
   Content-Type: application/json
   
   {
     "domain": "github.com",
     "match_type": "domain_suffix",
     "action": "proxy"
   }
   ```
4. 接口验证通过后，将规则存入 Isar 数据库并通知 sing-box 内核热重载，返回 `HTTP 200 { "status": "ok" }`。扩展弹窗呈现“已成功加入代理”提示。

---

## 4. 数据模型与持久化设计 (Isar Database)

使用高性能本地数据库 **Isar** 存储应用核心实体：

### 4.1 节点实体 (`ProxyNode`)
```dart
@collection
class ProxyNode {
  Id id = Isar.autoIncrement;
  late String name;           // 节点名称
  late String type;           // vmess, vless, trojan, shadowsocks
  late String server;         // 远程服务器域名或 IP
  late int port;              // 远程端口
  String? uuid;               // VMess/VLESS UUID
  String? password;           // Trojan/SS 密码
  String? cipher;             // SS 加密方式
  String? network;            // tcp, ws, grpc, http
  String? wsPath;             // WebSocket 路径
  String? sni;                // TLS SNI 伪装域名
  bool tls = false;           // 是否开启 TLS
  String? flow;               // xtls-rprx-vision (针对 VLESS)
  int? latency;               // 最近一次延迟测试 (毫秒)
  DateTime? lastTestedAt;
}
```

### 4.2 自定义域名规则实体 (`CustomDomainRule`)
```dart
@collection
class CustomDomainRule {
  Id id = Isar.autoIncrement;
  @Index(unique: true)
  late String domain;         // 域名字符串 (如 google.com)
  late String matchType;      // full, suffix, keyword, regex
  late String action;         // proxy, direct, block
  bool isEnabled = true;      // 是否启用
  late String source;         // manual(手动添加), browser_extension(扩展同步), sniffing(智能嗅探推荐)
  DateTime createdAt = DateTime.now();
}
```

### 4.3 嗅探告警日志实体 (`SniffingAlert`)
```dart
@collection
class SniffingAlert {
  Id id = Isar.autoIncrement;
  @Index()
  late String domain;
  late String failReason;     // TCP_RST, SYN_TIMEOUT, TLS_BLOCKED
  late String targetIp;
  bool isResolved = false;    // 用户是否已处理 (已加入代理或已忽略)
  DateTime timestamp = DateTime.now();
}
```

---

## 5. 四平台原生网络网卡接管与防护策略

### 5.1 iOS 端关键限制与调优
- **进程内存硬限制**：iOS Network Extension 进程有严格的 Jetsam 内存上限（15MB~30MB）。
  - **优化对策**：使用 `GOMEMLIMIT=15MiB` 编译 sing-box；关闭内核不必要的大型内存缓存；DNS 缓存条目限制在 500 条以内；规避加载数十兆的完整 GEOIP 离线库，采用针对 CN 的紧凑裁剪版规则库（< 2MB）。
- **证书要求**：主 App 与 PacketTunnel 必须开启 `Personal VPN` 与 `Network Extensions (Packet Tunnel)` Capability，需在苹果开发者后台配置专用 Provisioning Profiles。

### 5.2 Android 端后台保活
- 声明 `android.permission.BIND_VPN_SERVICE`。
- 启动 `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` 或 `FOREGROUND_SERVICE_CONNECTED_DEVICE` 前台服务，绑定系统常驻通知栏，显示实时上下行速度与快速断开按钮。
- 提供“忽略电池优化”（Battery Optimization Exemption）引导，防止 MIUI/HarmonyOS 等定制系统在后台杀死 VPN 服务。

### 5.3 macOS 端运行策略
- 优先采用带有沙盒权限的 `NetworkExtension`（与 iOS 架构保持高度统一）。
- 支持状态栏托盘（Menu Bar）：左键弹出 Mini 控制面板，右键提供节点切换菜单。

### 5.4 Windows 端 Wintun 驱动集成
- 将官方签名的 `wintun.dll` 打包在应用执行目录。
- Windows 下首次启动 TUN 模式需申请管理员权限以创建虚拟 TUN 适配器。
- 支持兜底模式：非管理员权限下自动回退为“系统代理模式”（修改注册表 `Internet Settings` 自动指向本地 HTTP/SOCKS 混合端口）。

---

## 6. 验证与验收计划

### 6.1 自动化单元测试与协议解析测试
- **订阅解析测试**：针对标准 V2Ray/VLESS/Trojan 格式及 Clash 格式编写解析器单元测试，验证解析结果无乱码、字段映射准确。
- **配置生成器测试**：验证将不同路由模式与自定义域名规则转换为 sing-box `config.json` 的语法正确性与规则优先级排序。

### 6.2 关键业务链路人工真机验证
1. **基础代理链路验证**：
   - 导入有效测试节点，分别在 iOS 真机、Android 手机、macOS 及 Windows 电脑上点击连接。
   - 验证打开 `https://www.google.com`、`https://ipinfo.io` 正常代理且显示节点 IP。
2. **自定义域名强分流验证**：
   - 设为“绕过大陆”模式。访问一个原本走直连的国内/测试域名（如 `baidu.com`），确认直连。
   - 在自定义域名规则中添加 `baidu.com` 走代理，确认即时生效，刷新页面后 `ipinfo` 显示访问来自代理节点。
3. **移动端与桌面端浏览器扩展联调**：
   - **iOS**：在 Safari 浏览器中浏览未在规则库中的网站，点击扩展弹窗中的“一键加入代理”，确认无需重启 VPN，网站即刻走代理打开。
   - **Android / 电脑**：在 Kiwi/Chrome 浏览器中点击扩展，调用 `127.0.0.1:9090`，确认数据库与内核热更新成功。
4. **智能嗅探告警验证**：
   - 模拟直连访问一个已被封锁且不在白名单的域名。
   - 观察客户端首页是否准确捕获 TCP RST/超时并弹出智能建议卡片，点击“一键加入代理”后验证连通性恢复。
