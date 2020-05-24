---
title: "Centos7.6下使用StrongSwan架设IKEv2 VPN"
date: 2020-05-21T01:37:56+08:00
lastmod: 2020-05-21T01:37:56+08:00
draft: false
tags: ["preview", "linux", "tag-1"]
categories: ["centos"]
author: "Wikipedia"

contentCopyright: '<a rel="license noopener" href="https://en.wikipedia.org/wiki/Wikipedia:Text_of_Creative_Commons_Attribution-ShareAlike_3.0_Unported_License" target="_blank">Creative Commons Attribution-ShareAlike License</a>'

---
### Centos7.6下使用StrongSwan架设IKEv2 VPN

- 介绍使用StrongSwan 5.7.2在服务器上架设支持IKEv2的VPN
- 介绍使用Windows、Android客户端连接使用VPN
- 官网：https://www.strongswan.org/

### 一. 安装

#### 1.1 安装EPEL扩展源

~~~Bash
# yum -y install epel-release redhat-release
~~~

#### 1.2 安装StrongSwan

~~~Bash
# yum -y install strongswan xl2tpd ppp
~~~

#### 1.3 查看版本

~~~Bash
# strongswan version
~~~

#### 1.4 官网安装参考

https://wiki.strongswan.org/projects/strongswan/wiki/InstallationDocumentation

### 二、生成服务器证书

#### 2.1 生成CA私钥

~~~Bash
# strongswan pki --gen --outform pem > ca.key.pem
~~~

#### 2.2 基于这个私钥自己签一个 CA 证书

~~~Bash
# strongswan  pki --self --in ca.key.pem --dn "C=CN, O=VPN, CN=StrongSwan CA" --ca --outform pem > ca.cert.pem
~~~

#### 2.3 参数解释

- C 表示国家名
- O 表示组织名
- CN 为通用名

#### 2.3 生成服务器证书所需的私钥

~~~Bash
# strongswan pki --gen --outform pem > server.key.pem
~~~

#### 2.4 用CA证书签发服务器证书

~~~Bash
# strongswan pki --pub --in server.key.pem | strongswan pki --issue --cacert ca.cert.pem --cakey ca.key.pem --dn "C=CN, O=VPN, CN=服务器公网地址或域名"  --san="服务器公网地址或域名" --flag serverAuth --flag ikeIntermediate  --outform pem > server.cert.pem
~~~

#### 2.5 服务器证书签发注意事项

- 这里C、O的值要跟2.2的一致
- CN值及--san值填写服务器公网地址或域名

### 三、生成客户端证书

#### 3.1 生成客户端证书所需的私钥

```Bash
# strongswan pki --gen --outform pem > client.key.pem
```

#### 3.2 用CA证书签发客户端证书

```Bash
# strongswan pki --pub --in client.key.pem | strongswan pki --issue --cacert ca.cert.pem --cakey ca.key.pem --dn "C=CN, O=VPN, CN=VPN Client" --outform pem > client.cert.pem
```

#### 3.2 客户端证书签发注意事项

- 这里C、O的值要跟2.2的一致

#### 3.3 生成 pkcs12 证书用来导入电脑或手机

~~~Bash
# openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "VPN Client" -out client.cert.p12
~~~

### 四、安装证书

#### 4.1 拷贝证书

~~~Bash
# cp -r ca.cert.pem /etc/strongswan/ipsec.d/cacerts/
# cp -r server.cert.pem /etc/strongswan/ipsec.d/certs/
# cp -r server.key.pem /etc/strongswan/ipsec.d/private/
# cp -r client.cert.pem /etc/strongswan/ipsec.d/certs/
# cp -r client.key.pem /etc/strongswan/ipsec.d/private/
~~~

#### 4.2 查看证书目录树

~~~Bash
# tree /etc/strongswan/ipsec.d/
/etc/strongswan/ipsec.d/
├── aacerts
├── acerts
├── cacerts
│   └── ca.cert.pem
├── certs
│   ├── client.cert.pem
│   └── server.cert.pem
├── crls
├── ocspcerts
├── private
│   ├── client.key.pem
│   └── server.key.pem
└── reqs

8 directories, 5 files
~~~

### 五、配置StrongSwan

#### 5.1 配置文件及目录

```bash
# rpm -ql strongswan | head -15
/etc/strongswan
/etc/strongswan/ipsec.conf           # ipsec.conf主配置文件    
/etc/strongswan/ipsec.d
/etc/strongswan/ipsec.d/aacerts
/etc/strongswan/ipsec.d/acerts
/etc/strongswan/ipsec.d/cacerts
/etc/strongswan/ipsec.d/certs
/etc/strongswan/ipsec.d/crls
/etc/strongswan/ipsec.d/ocspcerts
/etc/strongswan/ipsec.d/private
/etc/strongswan/ipsec.d/reqs
/etc/strongswan/ipsec.secrets         # ipsec.secrets密码认证文件
/etc/strongswan/strongswan.conf       # strongswan.conf配置文件
/etc/strongswan/strongswan.d
```

#### 5.2 配置ipsec.conf

```Bash
# 
cat >/etc/strongswan/ipsec.conf <<-EOF
config setup
    # strictcrlpolicy=yes
    uniqueids = never
conn %default
    compress = yes
    esp = aes256-sha256,aes256-sha1,3des-sha1!
    ike = aes256-sha256-ecp384,aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,3des-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    keyexchange = ike
    keyingtries = 1
    leftdns = 119.29.29.29,114.114.114.114
    rightdns = 119.29.29.29,114.114.114.114
conn IKEv2-BASE
    # 服务器端根证书 DN 名称
    leftca = "C=CN, O=VPN, CN=StrongSwan CA"
    # 是否发送服务器证书到客户端
    leftsendcert = always
    # 客户端不发送证书
    rightsendcert = never
conn IKEv2-EAP
    leftca = "C=CN, O=VPN, CN=StrongSwan CA"
    leftcert = server.cert.pem
    leftsendcert = always
    rightsendcert = never
    leftid = 123.235.99.100
    left = %any
    right = %any
    leftauth = pubkey
    rightauth = eap-mschapv2
    leftfirewall = yes
    leftsubnet = 0.0.0.0/0
    rightsourceip = 10.1.0.0/24
    fragmentation = yes
    rekey = no
    eap_identity = %any
    auto = add

conn android_xauth_psk
       keyexchange=ikev1
       fragmentation=yes
       keyingtries=3
       left=%defaultroute
       leftauth=psk
       right=%any
       rightsourceip = %config
       rightsubnet=0.0.0.0/0
       rightauth=psk
       rightauth2=xauth
       rightsourceip=10.1.0.0/24
       auto=add


conn android_hybrid_rsa
  keyexchange = ikev1
  left = %any
  leftid = 123.235.99.100
  leftsendcert = always
  leftcert = server.cert.pem
  leftsubnet = 0.0.0.0/0
  right = %any
  rightauth = xauthpsk
  rightsourceip = 10.1.0.0/24
  auto = add

conn windows7
 keyexchange = ike
 ike = aes256-sha1-modp1024!
 rekey = no
 left = %defaultroute
 leftauth = pubkey
 leftsubnet = 0.0.0.0/0
 leftcert=server.cert.pem
 right = %any
 rightauth = eap-mschapv2
 rightsourceip = 10.1.0.0/24
 rightsendcert = never
 eap_identity = %any
 auto = add

conn L2TP-PSK
    keyexchange=ikev1
    authby=secret
    leftprotoport=17/1701 #l2tp端口
    leftfirewall=no
    rightprotoport=17/%any
    type=transport
    auto=add

conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightsourceip=10.1.0.0/24
    rightcert=client.cert.pem
    auto=add

conn iOS_cert
    keyexchange=ikev1
    fragmentation=yes
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightauth2=xauth
    rightsourceip=10.1.0.0/24
    rightcert=client.cert.pem
    auto=add
EOF
```

#### 5.3 配置ipsec.conf注意事项

- 如上配置leftid需要自行按要求手动修改

#### 5.4 配置ipsec.conf相关项解释

- config setup 只能出现一次，而 conn <连接名称> 可以有很多个。conn<连接名称>可以自定义
- uniqueids=never ID不唯一，允许多个客户端使用同一个证书，多设备同时在线
- conn %default 项目共用的配置项
- left=%any  服务器端标识,%any表示任意
- leftsubnet=0.0.0.0/0  服务器端虚拟ip, 0.0.0.0/0表示通配
- leftsourceip=%config4 服务器内部源IP，也称为虚拟IP，并使用％config4显式请求给定地址族的地址
- rightsourceip=10.0.0.0/8 分配给客户端的虚拟 ip 段
- right=%any  客户端端标识，%any表示任意
- auto=add  IPsec启动时会添加加载连接而不启动它
- conn IKE-BASE  自定义的一个ike基础连接
- keyexchange=ike2 使用ike2密钥交换协议来发起连接
- ike=和esp= 采用的连接算法
- leftikeport=4500 用于IKE通信的UDP端口
- ikelifetime=60m 服务器程序连接超时时间 
- keyingtries=3  应该进行多少次尝试来协商连接或替换，默认3次
- also=IKE-BASE 继承上面的IKE-BASE的配置
- leftsendcert=always 对等方必须发送证书请求
- dpdaction=clear 定期发送sage（IKEv2），以检查IPsec对等方的活动性
- rekey=no 连接即将到期时是否应该重新协商连接，no阻止守护程序重新协商，但不阻止响应
- leftauth=pubkey 采用公钥连接
- leftcert=server.cert.pem   填写服务器证书
- leftid= 需要和申请CA签发证书中的域名一致  
- rightauth=eap-mschapv2 *身份验证方法*
- rightsendcert=never 接受的值是**never**或**no**，**always**或**yes**，以及**ifasked**，后者表示
  对等方必须发送证书请求（CR）有效负载才能获得证书作为回报。
- eap_identity=*％identity* 定义客户端用来回复EAP身份请求的身份，特殊值*％identity*使用EAP Identity方法
  来向客户端请求EAP身份
- fragmentation=yes 使用IKE分段，始终会处理由对等方发送的碎片消息
- leftfirewall=yes 使用iptables对来自左子网的流量进行转发防火墙

#### 5.5 配置ipsec.conf参数官网参考

https://wiki.strongswan.org/projects/strongswan/wiki/IpsecConf

https://wiki.strongswan.org/projects/strongswan/wiki/ConnSection

#### 5.6 配置ipsec.secrets文件 

~~~Bash
# 
cat >/etc/strongswan/ipsec.secrets <<-EOF
# ipsec.secrets - strongSwan IPsec secrets file
: RSA server.key.pem
: PSK "test123"
%any %any : PSK "test123"
test123 %any : EAP "test123"
test123 %any : XAUTH "test123"
EOF
~~~

#### 5.7 配置ipsec.secrets格式

- : RSA server.key.pem  申请的证书的私钥
- zhangsan %any  : EAP "x3.dEhgN"  格式为 [账号 %any : EAP "密码"]，每行一个账号

#### 5.8 配置strongswan.conf文件

~~~Bash
# 
cat >/etc/strongswan/strongswan.conf <<-EOF
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files

charon {
	load_modular = yes
	duplicheck{ #这里
        enable = no
        }
	compress = yes
	dns1 = 119.29.29.29
	dns2 = 114.114.114.114
	bdns1 = 119.29.29.29
	bdns2 = 114.114.114.114
	#dns1 = 183.60.83.19
	#dns2 = 183.60.82.98
#	bdns1 = 183.60.83.19
#	bdns2 = 183.60.82.98
	plugins {
		include strongswan.d/charon/*.conf
	}
	filelog {
               charon {
                   path = /var/log/charon.log
                   time_format = %b %e %T
                   default = 2
                   append = yes
                   flush_line = yes
               }
         }
}

include strongswan.d/*.conf
EOF
~~~

#### 5.9 配置stronswan.conf相关项解释

- filelog 配置日志模块
- duplicheck_enable = no：是为了同时连接多个设备，所以要把冗余检查关闭
- path = /var/log/charon.log 
- default = 2：定义的是日志的级别，默认日志级别为：-1,0,1,2,3,4，-1是完全没有日志

- 0只告诉你建立连接，连接关闭

- 1只输出错误提示
- 2会输出错误，警告和调试信息
- 3会把连接传输的数据也打印
- 4则会把密钥内容这些敏感数据也打印
- 一般情况下，1或2都可以

- append = no：重启strogswan后，追加 写日志，不新建一个日志（上次的会删除）

- no flush_line = yes 每产生一行日志，就写入到磁盘一次，防止突然断电，磁盘缓存数据丢失

### 六、启动检证strongswan

#### 6.1 启动和设置开机自启

```Bash
# systemctl enable strongswan
# systemctl start strongswan
```

#### 6.2 检查进程和开机启动

```Bash
# systemctl status strongswan
# systemctl list-unit-files | grep strongswan
# netstat -ulnp | grep charon
udp        0      0 0.0.0.0:4500            0.0.0.0:*                           14201/charon        
udp        0      0 0.0.0.0:500             0.0.0.0:*                           14201/charon        
udp        0      0 0.0.0.0:68              0.0.0.0:*                           14201/charon        
udp6       0      0 :::4500                 :::*                                14201/charon        
udp6       0      0 :::500                  :::*                                14201/charon  
```

### 七、防火墙配置

#### 7.1 CentOS7firewalld配置

##### 7.1.1 允许ESP加密协议通过防火墙

```Bash
# firewall-cmd --zone=public --permanent --add-rich-rule='rule protocol value="esp" accept'
```

##### 7.1.2 开放 相关端口

```Bash
# firewall-cmd --zone=public --permanent --add-port=500/udp
# firewall-cmd --zone=public --permanent --add-port=4500/udp
```

##### 7.1.3 允许IP伪装

```Bash
# firewall-cmd --zone=public --permanent --add-masquerade
```

##### 7.1.4 重载防火墙验证

```Bash
# firewall-cmd --reload
# firewall-cmd --list-all
```

#### 7.2 CentOS7iptables配置

##### 7.2.1 允许 ‘AH’ 和 ‘ESP’ 身份验证协议和加密协议通过防火墙

~~~Bash
# 
iptables -I INPUT -p esp -j ACCEPT
iptables -I INPUT -p ah -j ACCEPT
~~~

##### 7.2.2 开放 ipsec 和相关端口

```Bash
# 
iptables -I INPUT -p udp -m udp --dport 68 -j ACCEPT
iptables -I INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 500 -j ACCEPT
iptables -I INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -I INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 1723 -j ACCEPT
iptables -I FORWARD -s 10.1.0.0/24 -j ACCEPT
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
```

##### 7.2.3 允许IP伪装和android mtu值

```Bash
# 
iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -j MASQUERADE
#注意eth0网卡名称，适当修改
iptables -t mangle -A FORWARD -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
```

##### 7.2.4 保存并重启查看防火墙

```Bash
# 
service iptables save 
systemctl restart iptables
iptables -nL
```

### 八、开启内核转发

```Bash
# grep 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && sysctl -p 
```

### 九、VPN PPTP/L2TP/IKEv2/OpenVPN/SSH协议的区别

- OpenVPN：OpenVPN允许参与建立VPN的单点使用预设的私钥，第三方证书，或者用户名/密码来进行身份验证。OpenVPN能在Linux、xBSD、Mac OS X与Windows2000/XP上运行。它不与IPsec及其他VPN软件包兼容。
  支持平台：Windows、Mac OS、iPhone、Android。
  其特点是：安全系数高。缺点：易用性差、兼容性差。
- PPTP：点对点隧道协议（PPTP）是一种支持多协议虚拟专用网络的网络技术。通过该协议，远程用户能够通过Windows NT工作站、XP、2000 、2003、Win7操作系统以及其它装有点对点协议的系统安全访问公司网络。默认端口号：1723
  其特点是：连接速度快。缺点：已河蟹，使用不稳定。
  支持平台：Windows、Mac OS、iPhone、Android、Linux。
- L2TP：L2TP和PPTP差不多，PPTP要求网络为IP网络，L2TP要求面向数据包的点对点连接；PPTP使用单一隧道，L2TP使用多隧道；L2TP提供包头压缩、隧道验证，而PPTP不支持。
  其特点是：连接速度快。缺点：已河蟹，使用不稳定（但稳定性比PPTP稍高）。
  支持平台：Windows、Mac OS、iPhone、Android、Linux。
- SSH和Socks：这2种代理协议其实差不多，这里就拿到一块儿说了。SSH 为建立在应用层和传输层基础上的安全协议。SSH目前较可靠，专为远程登录会话和其他网络服务提供安全性的协议。利用 SSH 协议可以有效防止远程管理过程中的信息泄露。
  其特点是：速度快，使用稳定、加密性高。缺点：1、无法全局代理（除非借助第三方软件）；2、使用稍复杂。
- 支持平台：Windows、Mac OS、Android、Linux。
  IPSec/IKEv2：“Internet 协议安全性 (IPSec)”是一种开放标准的框架结构，通过使用加密的安全服务以确保在 Internet 协议 (IP) 网络上进行保密而安全的通讯。
  其特点是：连接速度快、稳定性高。缺点：使用稍复杂。
  支持平台：Windows 7以上、Mac OS、iPhone、Android 4.0以上。

### 十、参考网址

http://blog.sina.com.cn/s/blog_a72b50c80102wf0j.html

https://linsir.org/post/how_to_install_IPSec_IKEV2_base_on_strongswan_with_CentOS7/

https://zh.opensuse.org/index.php?title=SDB:Setup_Ipsec_VPN_with_Strongswan&variant=zh

### 十一、查看strongswan状态：

```Bash
strongswan statusall
```



### 十二、Android手机证书配置：

- 复制以下证书文件到手机上，点击打开进行安装:

```Bash
cp server.cert.pem server.cert.crt
sz client.cert.p12 server.cert.crt
```

Android可用2种连接方式：

1、IPSec Hybrid RSA（ca证书+服务器证书+用户名+密码）

```cmd
设置 -> VPN -> 添加vpn
名称：ikev1
类型：IPSec Hybrid RSA
服务器地址：111.78.143.23
IPSEC CA证书：选择client证书
IPSEC服务器证书：选择server证书
账户：user1
密码：12345678
```

2、IPSec Xauth PSK(共享密钥+用户名+密码)

```cmd
设置 -> VPN -> 添加vpn
名称：ikev1
类型：IPSec Xauth PSK
服务器地址：111.78.143.23
IPSec 标识符：不需要填写
预共享密钥：vpntest
账户：user1
密码：12345678
```

### 十三、win7/win10 证书配置：

- **方法1**: 通过**证书**+**密码**认证连接vpn

  1、下载证书文件：

```Bash
sz ca.cert.pem
```

​      2、windows导入证书到受信任的根证书颁发机构(复制下面脚本代码，新建import.bat)：

```cmd
@echo off
@setlocal enableextensions
@set current_dir="%~dp0"
@cd /d "%current_dir%"
@echo %current_dir%
@certutil -addstore root ca.cert.pem
if %ERRORLEVEL% EQU 0 @echo  import ok
pause
```

**或者通过第三方工具导入：**

第三方证书管理工具CertMg下载地址：

http://down1.100down.com/pc/CertMgr.rar

新建import1.bat:

```cmd
cd /d %~dp0
CertMgr.exe /add ca.cert.crt -s -r localMachine trustedpublisher -all
CertMgr.exe /add ca.cert.crt -s -r localMachine AuthRoot -all
```

​     `注意：运行脚本时，证书文件要和脚本在同一目录下。`

​      3、通过powershell创建ikev2 vpn连接(create-vpn.ps1)：

```powershell
$VpnServerAddress = "123.235.99.100"
$VpnName = "IKEv2-vpn"

$addVpnParams = @{
    Name = $VpnName
    ServerAddress = $VpnServerAddress
    TunnelType = "IKEv2"
    AuthenticationMethod = "EAP"
    EncryptionLevel = "Required"
}
Add-VpnConnection @addVpnParams
```



- **方法2** : 通过**个人证书**认证连接vpn

下载证书文件：

```Bash
sz ca.cert.pem client.cert.p12
```

windows导入证书到受信任的根证书颁发机构(复制下面脚本代码，新建create-vpn.ps1)：

```powershell
$VpnServerAddress = "123.235.99.100"
$UserP12Path = "client.cert.p12"
$CaCertPath = "client.cert.pem"
$VpnName = "IKEv2-VPN-own"
$p12Pass = Read-Host -AsSecureString -Prompt "P12 Password"
Import-PfxCertificate -FilePath $UserP12Path -CertStoreLocation Cert:\LocalMachine\My -Password $p12Pass
Import-Certificate -FilePath $CaCertPath -CertStoreLocation Cert:\LocalMachine\Root

Add-VpnConnection -Name $VpnName -ServerAddress $VpnServerAddress -TunnelType IKEv2 -AuthenticationMethod MachineCertificate
Set-VpnConnection -ConnectionName $VpnName -splittunneling $false
```

- **方法3** : 通过psk**共享密钥+用户名+密码**连接vpn(create-l2tp.ps1)

```powershell
Add-VpnConnection -Name 'l2tp-vpn' `
	-ServerAddress '123.235.99.100' `
	-L2tpPsk 'test123' `
	-TunnelType L2tp `
	-EncryptionLevel Required `
	-AuthenticationMethod Chap,MSChapv2 `
	-Force `
	-RememberCredential `
	-PassThru
```

```powershell
如果连接l2tp出现：Windows错误809，请以管理员身份打开cmd命令行窗口中输入以下2条命令，并重启电脑：

REG ADD HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 0x2 /f

REG ADD HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters /v ProhibitIpSec /t REG_DWORD /d 0x0 /f
```



### 十四、苹果ios 配置vpn连接：

- 系统iOS 13通过IPsec连接vpn（**共享密钥+用户名+密码**）

  ```powershell
  设置 -> VPN -> 添加vpn配置
  类型：IPSec
  描述：ipsec
  服务器：111.78.143.23
  账户：user1
  密码：12345678
  使用证书： OFF（关闭）
  群组名：不需要填写
  密钥：abcd1234
  ```

- 系统iOS 13通过ikev2方式连接vpn（**共享密钥+用户名+密码**）

  通过**邮箱发送**或者**系统自带Safari浏览器**访问下载（**ca.cert.pem和client.cert.p12**）

  比如：

  http://100.25.3.11/ca.cert.pem

  http://100.25.3.11/client.cert.p12

  用Safari浏览器访问上面2个地址，

  会提示“**此网站正尝试下载一个配置描述文件。您要允许吗？**”，点击“**允许**”，然后进入系统设置，在**已下载描述文件**中查看，并进行安装。

  以上2个网址依次访问，在安装client.cert.p12这个证书时，会要求输入证书“身份证书”的密码，输入密码之后，点击安装。

  安装完成就可以进行下面配置：

 ```cmd
  设置 -> VPN -> 添加vpn配置
  类型：IKEv2
  描述：ikev2
  服务器：111.78.143.23
  远程ID：111.78.143.23
  本地ID：不需要填写
  用户鉴定：用户名
  账户：user1
  密码：12345678
 ```
