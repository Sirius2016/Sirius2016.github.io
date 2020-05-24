+++
Description = ""
Tags = ["linux教程", "windows教程"]
date = "2015-09-23T16:30:37+08:00"
menu = "main"
title = "Openvpn-install"
+++

## openvpn-install

* OpenVPN road warrior installer for Ubuntu, Debian, CentOS and Fedora.

     This script will let you set up your own VPN server in no more than a minute, even if you haven't used OpenVPN before. It has been designed to be as unobtrusive and universal as possible.

    Installation

	Run the script and follow the assistant:  

```bash
wget https://git.io/vpn -O openvpn-install.sh && bash openvpn-install.sh
   ```
   Once it ends, you can run it again to add more users, remove some of them or even completely uninstall OpenVPN.  
   * [Openvpn github项目地址](https://github.com/Nyr/openvpn-install)
   * [Openvpn github项目地址2](https://github.com/angristan/openvpn-install)
   * 解决通过脚本安装，在server.conf中添加:  log-append openvpn.log  
     <font color=green> 实际历史记录未记录时间标志</font>  
 vim /lib/systemd/system/openvpn-server@.service
找到ExecStart行，删除字段："--suppress-timestamps"  
修改为：  
```bash
ExecStart=/usr/sbin/openvpn --status %t/openvpn-server/status-%i.log --status-version 2 --config %i.conf
   ```

### 示例代码
 * Openvpn服务端配置调整
```bash
port 8901
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn
reneg-sec 54000
comp-lzo
fast-io
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
tun-mtu 1500
mssfix 1360
txqueuelen 4000
mode server
tls-server
ifconfig 10.8.0.1 255.255.255.0
push "topology subnet"
route-gateway 10.8.0.1
push "route-gateway 10.8.0.1"
ifconfig-pool 10.8.0.129 10.8.0.190 255.255.255.0
ifconfig-pool-persist ipp.txt
client-config-dir client
push "dhcp-option DNS 223.5.5.5"
push "dhcp-option DNS 114.114.114.114"
keepalive 10 120
cipher AES-256-CBC
#user nobody
#group nobody
#duplicate-cn
persist-key
persist-tun
status openvpn-status.log
log-append openvpn.log
verb 3
crl-verify crl.pem
```
  + 配置解释
```cmd
reneg-sec 54000  #表示15个小时之后需要再次认证
plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn #通过/etc/pam.d/openvpn配置文件实现认证
duplicate-cn  #同一个证书配置成允许多个用户同时登录
```

 * Openvpn客户端配置调整   
```bash
remote-cert-tls server
auth-user-pass
reneg-sec 54000
tun-mtu 1500
mssfix 1360
auth-nocache
comp-lzo
```

### 知识扩展
[结合MySQL实现OpenVPN用户名密码登录认证](https://my.oschina.net/HeAlvin/blog/2051355)

### 测试Shortcodes
<h2 id="youtube">youtube</h2>

<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden;">
  <iframe src="https://www.youtube.com/embed/w7Ft2ymGmfc" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border:0;" allowfullscreen title="YouTube Video"></iframe>
</div>

<h2 id="vimeo">vimeo</h2>

<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden;">
  <iframe src="https://player.vimeo.com/video/146022717" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border:0;" title="vimeo video" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe>
 </div>

<h2 id="youku">youku</h2>


<div style="position: relative; padding-bottom: 56.25%; padding-top: 30px; height: 0; overflow: hidden;">
    <iframe src="https://player.youku.com/embed/XMzQ0ODUxMjM2NA?autoplay=0" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" allowfullscreen frameborder="0" title="YouKu Video">
    </iframe>
</div>



    </div>

