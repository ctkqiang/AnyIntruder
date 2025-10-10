
# AnyIntruder

基于 libpcap 的实时网络入侵监控（支持 Linux / macOS / FreeBSD / Windows(Npcap)）

![AnyIntruder](./assets/demo.png)

---

## 概览

AnyIntruder 用于实时捕获并可视化展示 TCP 流量中常见的扫描与攻击尝试（HTTP / HTTPS / SSH / SYN 等）。  
程序包含：抓包模块、事件缓冲、攻击者统计与终端 UI（ncurses）。

**要点**：抓包通常需要 `root` 权限或等效 capability（Linux 可使用 `setcap`）。

---

## 快速使用（示例）

在多数平台上先列出可用接口，然后以 `root` 或具有抓包权限的方式运行：

### 列设备

```bash
sudo tcpdump -D
# 或 macOS
ifconfig -a
````

### 运行示例

```bash
sudo ./anyintruder en0     # macOS: 主网卡（或 eth0，视系统而定）
sudo ./anyintruder eth0    # Linux: 有线/主网卡
sudo ./anyintruder lo      # 本地回环（针对 127.0.0.1 测试）
sudo ./anyintruder any     # Linux-only: 抓取所有接口流量
```

<details>
<summary>建议：如何快速产生可见事件（开发调试）</summary>

在另一终端启动简单 HTTP 服务并触发请求：

```bash
python3 -m http.server 8000
curl http://127.0.0.1:8000
ssh -p 22 127.0.0.1   # 触发 SSH 尝试（会要求密码）
```

注意：若你使用回环 (`lo` / `lo0`)，运行 AnyIntruder 时应指定该接口或确保选取器选择了回环。

</details>

<details>
<summary>权限替代方案（Linux）</summary>

```bash
# 给可执行文件赋予抓包能力（不需要 sudo 运行）
sudo setcap cap_net_raw,cap_net_admin+ep ./anyintruder
./anyintruder enp3s0
```

</details>

---

## 平台指南（摘要）

<details>
<summary>Linux</summary>

**安装依赖（Debian/Ubuntu）：**

```bash
sudo apt update
sudo apt install build-essential pkg-config libpcap-dev libncurses-dev
```

接口示例： `lo`, `eth0`, `wlan0`, `docker0`, `any`（Linux 专用）

</details>

<details>
<summary>macOS</summary>

**安装依赖（Homebrew）：**

```bash
brew install pkg-config libpcap ncurses
export PKG_CONFIG_PATH="/opt/homebrew/opt/libpcap/lib/pkgconfig:$PKG_CONFIG_PATH"
```

接口示例： `lo0`, `en0`, `en1`, `awdl0`

</details>

<details>
<summary>FreeBSD</summary>

通常自带 libpcap，若缺少可用 `pkg` 安装 ncurses 等。
接口示例： `lo0`, `em0`, `bridge0`

</details>

<details>
<summary>Windows (Npcap) / WSL</summary>

原生 Windows 请安装 Npcap 并以管理员运行；推荐在 WSL2 中运行 Linux 版本进行开发。

</details>

---

## 功能要点与限制

* 实时解析 HTTP 请求行（若 payload 可读）并显示摘要。
* HTTPS 为加密流量，只能尝试解析 `ClientHello` 的 SNI；后续数据一律标注为 `[ENCRYPTED/BINARY]`。
* 仅支持 IPv4（当前实现）；IPv6 可后续扩展。
* 事件缓冲为环形队列，满后覆盖最旧记录。

---

## 开发者友好（可用开关、调试）

程序支持命令行与交互方式选择接口、列出设备与无 UI 模式：

```bash
sudo ./anyintruder -i en0          # 指定接口
sudo ./anyintruder -n 2            # 使用 --list 时的编号
sudo ./anyintruder --no-ui         # 仅运行抓包与日志（适合容器/CI）
```

<details>
<summary>调试技巧</summary>

1. 使用 `tcpdump` 验证接口是否确实有流量：

```bash
sudo tcpdump -i en0 tcp port 80
```

2. 在 `monitor.c` 的 `got_packet` 回调加临时 debug 输出：

```c
fprintf(stderr, "got_packet len=%u\n", header->len);
```

3. 开发时可注入测试事件，快速验证 UI 渲染与日志功能。

</details>

---

## 示例：典型启动流程

```bash
# 列设备
sudo tcpdump -D

# 运行 AnyIntruder（macOS）
sudo ./anyintruder en0

# 本机测试（回环）
sudo ./anyintruder lo0   # macOS
sudo ./anyintruder lo    # Linux

# Linux 全接口抓包（仅 Linux 支持）
sudo ./anyintruder any
```

---

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目！

1. Fork 本仓库
2. 创建您的特性分支 (git checkout -b feature/AmazingFeature)
3. 提交您的更改 (git commit -m 'Add some AmazingFeature')
4. 推送到分支 (git push origin feature/AmazingFeature)
5. 打开一个 Pull Request

---

## 作者信息

* 项目作者: ctkqiang
* GitHub：[https://github.com/ctkqiang](https://github.com/ctkqiang)
* Gitcode：[https://gitcode.com/ctkqiang_sr](https://gitcode.com/ctkqiang_sr)
* 个人博客：[https://www.ctkqiang.xin](https://www.ctkqiang.xin)
* 反馈邮箱：[ctkqiang@dingtalk.com](mailto:ctkqiang@dingtalk.com)

---

## 开源项目赞助

感谢您使用本项目！您的支持是开源持续发展的核心动力。

* 服务器与基础设施维护
* 新功能开发与版本迭代
* 文档优化与社区建设

## 许可证

本项目采用 **木兰宽松许可证 (Mulan PSL)** 进行许可。  
有关详细信息，请参阅 [LICENSE](LICENSE) 文件。  
（魔法契约要保管好哟~）

[![License: Mulan PSL v2](https://img.shields.io/badge/License-Mulan%20PSL%202-blue.svg)](http://license.coscl.org.cn/MulanPSL2)


### 🌐 全球捐赠通道

#### 国内用户

<div align="center" style="margin: 40px 0">

<div align="center">
<table>
<tr>
<td align="center" width="300">
<img src="https://github.com/ctkqiang/ctkqiang/blob/main/assets/IMG_9863.jpg?raw=true" width="200" />
<br />
<strong>🔵 支付宝</strong>（小企鹅在收金币哟~）
</td>
<td align="center" width="300">
<img src="https://github.com/ctkqiang/ctkqiang/blob/main/assets/IMG_9859.JPG?raw=true" width="200" />
<br />
<strong>🟢 微信支付</strong>（小绿龙在收金币哟~）
</td>
</tr>
</table>
</div>
</div>

#### 国际用户

<div align="center" style="margin: 40px 0">
  <a href="https://qr.alipay.com/fkx19369scgxdrkv8mxso92" target="_blank">
    <img src="https://img.shields.io/badge/Alipay-全球支付-00A1E9?style=flat-square&logo=alipay&logoColor=white&labelColor=008CD7">
  </a>
  
  <a href="https://ko-fi.com/F1F5VCZJU" target="_blank">
    <img src="https://img.shields.io/badge/Ko--fi-买杯咖啡-FF5E5B?style=flat-square&logo=ko-fi&logoColor=white">
  </a>
  
  <a href="https://www.paypal.com/paypalme/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/PayPal-安全支付-00457C?style=flat-square&logo=paypal&logoColor=white">
  </a>
  
  <a href="https://donate.stripe.com/00gg2nefu6TK1LqeUY" target="_blank">
    <img src="https://img.shields.io/badge/Stripe-企业级支付-626CD9?style=flat-square&logo=stripe&logoColor=white">
  </a>
</div>

---

### 📌 开发者社交图谱

#### 技术交流

<div align="center" style="margin: 20px 0">
  <a href="https://github.com/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/GitHub-开源仓库-181717?style=for-the-badge&logo=github">
  </a>
  
  <a href="https://stackoverflow.com/users/10758321/%e9%92%9f%e6%99%ba%e5%bc%ba" target="_blank">
    <img src="https://img.shields.io/badge/Stack_Overflow-技术问答-F58025?style=for-the-badge&logo=stackoverflow">
  </a>
  
  <a href="https://www.linkedin.com/in/ctkqiang/" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-职业网络-0A66C2?style=for-the-badge&logo=linkedin">
  </a>
</div>

#### 社交互动

<div align="center" style="margin: 20px 0">
  <a href="https://www.instagram.com/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/Instagram-生活瞬间-E4405F?style=for-the-badge&logo=instagram">
  </a>
  
  <a href="https://twitch.tv/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/Twitch-技术直播-9146FF?style=for-the-badge&logo=twitch">
  </a>
  
  <a href="https://github.com/ctkqiang/ctkqiang/blob/main/assets/IMG_9245.JPG?raw=true" target="_blank">
    <img src="https://img.shields.io/badge/微信公众号-钟智强-07C160?style=for-the-badge&logo=wechat">
  </a>
</div>

---

致极客与未来的你

> "世界由代码驱动，安全靠你我守护。"

无论你是网络安全研究员、CTF 挑战者、自由极客，还是热爱数学与工程的探索者，这个项目都向你敞开怀抱。
欢迎你 fork、魔改、重构、注入灵感，它是工具，也是信仰。

但请铭记心底：

> **技术本无善恶，使用才有底线。**
> 愿你在这个开源项目中，找到属于自己的价值与乐趣。

> 享受黑客精神，享受学习之旅！—— 你最贴心的代码姐姐 💖