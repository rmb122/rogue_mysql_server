# Rogue Mysql Server

基于 https://github.com/vitessio/vitess 实现的恶意 mysql 服务器, 支持 go, php, python, java, 原生命令行等多种语言下的多种库的 mysql 客户端.  
远离恼人的兼容性问题, 测试过的客户端见下表  

language | library | pass |
---     | --- | --- | 
go | github.com/go-sql-driver/mysql | ✔️ | 
php | mysqli, pdo | ✔️ | 
python | pymysql | ✔️ | 
java | mysql-connector-java | ✔️ |
native | 10.4.13-MariaDB | ✔️ |

## 功能

* 可以兼容多种 mysql 客户端
* 可以读取二进制文件
* 自动保存文件
* 作为蜜罐使用时, 可选择开启帐号密码验证

## 配置文件

示例:
```yaml
lhost: 127.0.0.1
lport: 3306
auth: false
username: root
password: root
filelist: ["/etc/passwd", "C:/boot.ini"]
```

`lhost`, `lport` 对应监听的 ip 和端口.  
`auth` 对应是否开启验证, 如果为 `false`, 那么不管输什么密码或者不输入密码都可以登录.  
如果为 `true`, 则需要帐号密码匹配下面的 `username` 和 `password`.  
而 `filelist` 对应需要读取的文件, 会按照客户端执行语句的顺序读取列表中的文件, 并保存到 `loot` 文件夹中.  

## Ref

https://github.com/vitessio/vitess  
https://github.com/src-d/go-mysql-server  
http://scz.617.cn:8/network/202001101612.txt  
