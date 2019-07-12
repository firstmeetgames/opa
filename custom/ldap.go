package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/runtime"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	LDAP_DATA_OBJECTCLASS         = "OPAData"
	LDAP_POLICY_OBJECTCLASS       = "OPAPolicy"
	LDAP_DATA_PATH_ATTRIBUTE      = "path"
	LDAP_DATA_CONTENT_ATTRIBUTE   = "jsonData"
	LDAP_POLICY_PATH_ATTRIBUTE    = "id"
	LDAP_POLICY_CONTENT_ATTRIBUTE = "content"
)

type Factory struct{}

type Config struct {
	Addr     string `json:"addr"`
	BaseDN   string `json:"base_dn"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Synchronizer struct {
	manager *plugins.Manager
	mtx     sync.Mutex
	config  Config
	data    map[string]interface{}
	files   []bundle.ModuleFile
	conn    *ldap.Conn
}

func Init() error {
	runtime.RegisterPlugin("init_ldap_datas", Factory{})
	return nil
}

func (Factory) New(manager *plugins.Manager, config interface{}) plugins.Plugin {
	log.Println("ldap同步数据插件初始化", config)
	return &Synchronizer{
		config:  config.(Config),
		manager: manager,
	}
}

func (Factory) Validate(_ *plugins.Manager, config []byte) (interface{}, error) {
	log.Println("ldap同步数据插件配置", string(config))
	var parsedConfig Config
	err := util.Unmarshal(config, &parsedConfig)
	return parsedConfig, err
}

func (s *Synchronizer) Start(ctx context.Context) error {
	var conn *ldap.Conn
	for {
		con, err := s.connectToLdap()
		if err == nil {
			conn = con
			break
		}
		time.Sleep(5 * time.Second)
		log.Println("ldap连接失败，5秒后重试", err)
	}

	s.conn = conn
	datas, err := s.FetchDatasFromLdap()
	if err != nil {
		return err
	}
	s.data = datas
	files, err := s.FetchPoliciesFromLdap()
	if err != nil {
		return err
	}
	s.files = files
	return s.callback(ctx)
}

func (s *Synchronizer) Stop(ctx context.Context) {
	s.conn.Close()
}

func (s *Synchronizer) Reconfigure(ctx context.Context, config interface{}) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.config = config.(Config)
}

func (s *Synchronizer) callback(ctx context.Context) error {
	return storage.Txn(ctx, s.manager.Store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := s.writeData(ctx, txn, s.data); err != nil {
			return err
		}
		return s.writeModules(ctx, txn, s.files)
	})
}

func (s *Synchronizer) writeData(ctx context.Context, txn storage.Transaction, data map[string]interface{}) error {
	for path, value := range data {
		if !strings.HasPrefix(path, "/") {
			path += "/"
		}
		p := storage.MustParsePath(path)
		if err := storage.MakeDir(ctx, s.manager.Store, txn, p); err != nil {
			return err
		}
		if err := s.manager.Store.Write(ctx, txn, storage.AddOp, p, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Synchronizer) writeModules(ctx context.Context, txn storage.Transaction, files []bundle.ModuleFile) error {
	modules := map[string]*ast.Module{}
	for _, file := range files {
		modules[file.Path] = file.Parsed
	}
	compiler := ast.NewCompiler().
		WithPathConflictsCheck(storage.NonEmpty(ctx, s.manager.Store, txn))
	if compiler.Compile(modules); compiler.Failed() {
		return compiler.Errors
	}
	for _, file := range files {
		if err := s.manager.Store.UpsertPolicy(ctx, txn, file.Path, file.Raw); err != nil {
			return err
		}
	}
	return nil
}

func (s *Synchronizer) connectToLdap() (conn *ldap.Conn, err error) {
	conn, err = ldap.Dial("tcp", s.config.Addr)
	if err != nil {
		return
	}
	err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	err = conn.Bind(s.config.Username, s.config.Password)
	if err != nil {
		return
	}
	return
}

func (s *Synchronizer) SearchFromLdap(filter string) (result *ldap.SearchResult, err error) {
	request := ldap.NewSearchRequest(
		s.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter, nil, nil)
	log.Println("ldap查询请求", request.BaseDN, request.Filter)
	result, err = s.conn.Search(request)
	log.Println("ldap查询结果", result, err)
	return
}

func (s *Synchronizer) FetchDatasFromLdap() (datas map[string]interface{}, err error) {
	datas = make(map[string]interface{})
	filter := fmt.Sprintf("(objectclass=%s)", LDAP_DATA_OBJECTCLASS)
	result, err := s.SearchFromLdap(filter)
	if err != nil {
		return
	}
	for _, entry := range result.Entries {
		var value interface{}
		path := entry.GetAttributeValue(LDAP_DATA_PATH_ATTRIBUTE)
		content := entry.GetRawAttributeValue(LDAP_DATA_CONTENT_ATTRIBUTE)
		err := json.Unmarshal(content, &value)
		if err != nil {
			return datas, err
		}
		datas[path] = value
	}
	return
}

func (s *Synchronizer) FetchPoliciesFromLdap() (files []bundle.ModuleFile, err error) {
	filter := fmt.Sprintf("(objectclass=%s)", LDAP_POLICY_OBJECTCLASS)
	result, err := s.SearchFromLdap(filter)
	if err != nil {
		return
	}
	for _, entry := range result.Entries {
		path := entry.GetAttributeValue(LDAP_POLICY_PATH_ATTRIBUTE)
		content := entry.GetRawAttributeValue(LDAP_POLICY_CONTENT_ATTRIBUTE)
		file := bundle.ModuleFile{
			Path:   path,
			Raw:    content,
			Parsed: ast.MustParseModule(string(content)),
		}
		files = append(files, file)
	}
	return
}
