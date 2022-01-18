import pymysql

mysql = pymysql.connect(host='127.0.0.1', user='root', password='root', local_infile=True)
mysql.query("SELECT 123;")