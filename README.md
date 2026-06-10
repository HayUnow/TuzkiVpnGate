# TuzkiVpnGate
TuzkiVpnGate是一个借助vpngate.net让Linux用干净ip出站的代理工具。<br>

VPNGATE 地址：https://www.vpngate.net/ja/

上游仓库地址：https://github.com/baoweise-bot/aimili-vpngate<br>

本仓库fork后自定义修改了大部分代码：<br>

1.支持ip断线后从备选池切换ip。<br>

2.支持singbox脚本运行的vps环境（singbox的配置路径务必确保是：/etc/sing-box，文件名称 config.json。<br>

3.支持绑定域名,支持锁定固定国家。<br>

4.支持登录失败5次，锁定IP和用户名，锁定后可以通过重启服务刷新。<br>

5.其余细节优化。<br>

6.使用方法：下载代码后，在vps上新建一个目录，然后将文件拖进去，cd 到对应目录，之后 bash install.sh 即可！<br>

## 📢 其他说明

### 🔵 **1. 每 6 小时自动更新节点（不断网获取新节点）**

`FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "21600")) # 6 小时拉取一次`<br>
`CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "21600")) # 6 小时巡逻一次`

### 🟢 **2. 每日 7 点强制更新所有节点（断网重新获取新节点）**

`maintain_valid_nodes(force=True)`

- **True**：断网后重新获取全部节点
- **False**：不断网，仅刷新节点

---

**以上所有修改均来自于谷歌的 “Gemini”**

![AimiliVPN](aimili.png)
