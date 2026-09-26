# ddns-cf

Cloudflare DDNS + network watchdog for Debian / Ubuntu VPS. Pure Python 3 standard library, no pip.

## 功能

- **DDNS**：定期检测公网 IPv4 / IPv6，更新 Cloudflare 的 A / AAAA 记录（记录不存在可自动创建；没有 IPv6 时自动跳过）。
- **凭据放在 `.env`**：安装后位于 `/opt/ddns-cf/.env`，权限 `600 root`。
- **掉线自动恢复**：每 `CHECK_INTERVAL` 秒 ping `CHECK_TARGETS`，连续 `FAIL_THRESHOLD` 次失败后按系统自动识别逐级恢复：
  1. DHCP 续租：`networkctl renew` / `nmcli device reapply` / `dhclient -r && dhclient`（ifupdown 下只对 `inet dhcp` 接口执行，不会动静态 IP）
  2. 重启网络：`netplan apply` / `systemctl restart systemd-networkd` / `NetworkManager` / `systemctl restart networking`（失败时 `ifdown && ifup`）
  3. 可选：多轮失败后重启 VPS（`REBOOT_ON_FAILURE=true`，默认关闭）
  恢复成功后立即强制跑一次 DDNS。
- **systemd 服务 + 开机自启**：`ddns-cf.service`，崩溃自动重启，日志进 journald。

## 安装

```bash
scp -r DDNS_CF root@your-vps:/root/
ssh root@your-vps
cd /root/DDNS_CF
cp .env.example .env && nano .env      # 填 CF_API_TOKEN、CF_RECORDS
sudo bash install.sh
```

Cloudflare Token 权限：`Zone → DNS → Edit`（如果不填 `CF_ZONE_ID`，还需要 `Zone → Zone → Read`）。

## 常用命令

```bash
ddns-cf check                 # 检查配置、Token、网络栈识别、公网 IP
ddns-cf ddns                  # 立即更新一次 DNS
sudo ddns-cf recover          # 手动演练一次恢复流程（会真的重启网络）
systemctl status ddns-cf
journalctl -u ddns-cf -f
sudo systemctl restart ddns-cf   # 改了 .env 之后
sudo bash uninstall.sh [--purge]
```

## 配置项

见 `.env.example`，每项都有注释。时间单位都是秒。
