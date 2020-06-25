import pymysql

mysql = pymysql.connections.Connection('127.0.0.1', 'root', local_infile=True)
mysql.query("SELECT 123;")