package lib

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Conf struct {
	Info     Info     `yaml:"info"`
	Rules    []Rule   `yaml:"rules"`
	Variable []string `yaml:"variable"`
}

type Info struct {
	VulId     string `yaml:"vulId"`
	Detail    string `yaml:"detail"`
	FofaQuery string `yaml:"fofaQuery"`
	ExpType   string `yaml:"expType"`
}
type Rule struct {
	Request         Request `yaml:"request"`
	ChecksCondition string  `yaml:"checksCondition"`
	Checks          []Check `yaml:"checks"`
}

type Request struct {
	Payload  []string               `yaml:"payload"`
	Path     string                 `yaml:"path"`
	Method   string                 `yaml:"method"`
	Headers  map[string]interface{} `yaml:"headers"`
	Redirect bool                   `yaml:"redirect"`
	DataType string                 `yaml:"dataType"`
	Data     string                 `yaml:"data"`
	Files    Files                  `yaml:"files"`
}

type Check struct {
	CheckType string   `yaml:"checkType"`
	Desireds  []string `yaml:"desireds"`
	Place     string   `yaml:"place"`
	Condition string   `yaml:"condition"`
}

type Files struct {
	Name        string `yaml:"name"`
	FilePath    string `yaml:"filePath"`
	FileName    string `yaml:"fileName"`
	ContentType string `yaml:"contentType"`
}

func ReadYamlConfig(path string) (Conf, error) {
	var exploit Conf
	if f, err := os.Open(path); err != nil {
		return exploit, err
	} else {
		err := yaml.NewDecoder(f).Decode(&exploit)
		if err != nil {
			return exploit, err
		}
	}
	return exploit, nil
}

// ConfReplace 替换处理Conf中的各个参数
func ConfReplace(target string, conf Conf) Conf {
	u, err := url.Parse(target)
	if err != nil {
		return conf
	}
	scheme := u.Scheme
	// 主机信息host，包括hostname和port
	host := u.Host
	// 拆分host为主机名和端口号
	ho := strings.Split(host, ":")
	var port string
	hostName := ho[0]
	if len(ho) == 1 {
		port = ""
	} else {
		port = ho[1]
	}
	// json序列化conf，便于转换为string
	byts, err := json.Marshal(conf)
	if err != nil {
		println(err.Error())
	}

	strConf := string(byts)
	if strings.Contains(strConf, "{{fileName}}") {
		strConf = strings.ReplaceAll(strConf, "{{fileName}}", FileName)
	}
	if strings.Contains(strConf, "{{command}}") {
		strConf = strings.ReplaceAll(strConf, "{{command}}", Command)
	}
	// 解决从页面中获取的带有双引号的字符中的双引号没有转义字符，导致后面json格式出错的问题
	if strings.Contains(FileContent, "\"") {
		FileContent = strings.ReplaceAll(FileContent, "\"", "\\\"")
	}
	if strings.Contains(FileContent, "\r") {
		FileContent = strings.ReplaceAll(FileContent, "\r", "\\r")
	}
	if strings.Contains(FileContent, "\n") {
		FileContent = strings.ReplaceAll(FileContent, "\n", "\\n")
	}
	if strings.Contains(strConf, "{{fileContent}}") {
		strConf = strings.ReplaceAll(strConf, "{{fileContent}}", FileContent)
	}
	if strings.Contains(strConf, "{{rootUrl}}") {
		strConf = strings.ReplaceAll(strConf, "{{rootUrl}}", scheme+"://"+host)
	}
	if strings.Contains(strConf, "{{hostName}}") {
		strConf = strings.ReplaceAll(strConf, "{{hostName}}", hostName)
	}
	if strings.Contains(strConf, "{{host}}") {
		strConf = strings.ReplaceAll(strConf, "{{host}}", host)
	}
	if strings.Contains(strConf, "{{port}}") {
		strConf = strings.ReplaceAll(strConf, "{{port}}", port)
	}
	if strings.Contains(strConf, "{{year}}") {
		year := time.Now().Format("06")
		strConf = strings.ReplaceAll(strConf, "{{year}}", year)
	}
	if strings.Contains(strConf, "{{month}}") {
		month := time.Now().Format("01")
		strConf = strings.ReplaceAll(strConf, "{{month}}", month)
	}
	if strings.Contains(strConf, "{{day}}") {
		day := time.Now().Format("02")
		strConf = strings.ReplaceAll(strConf, "{{day}}", day)
	}

	// {{md5(string)}}的处理
	if strings.Contains(strConf, "{{md5(") {
		re := "{{md5\\((.*?)\\)}}"
		v := regexp.MustCompile(re).FindStringSubmatch(strConf)[1]
		md := md5.Sum([]byte(v))
		a := fmt.Sprintf("%x", md)
		md5Str := md5.Sum([]byte(a))
		md5NewStr := fmt.Sprintf("%x", md5Str)
		md5OldStr := "{{md5(" + v + ")}}"
		strConf = strings.ReplaceAll(strConf, md5OldStr, md5NewStr)
	}
	// {{random(num)}}的处理
	if strings.Contains(strConf, "{{random(") {
		re := "{{random\\((\\d)\\)}}"
		n := regexp.MustCompile(re).FindStringSubmatch(strConf)[1]
		randomOldStr := "{{random(" + n + ")}}"
		num, _ := strconv.Atoi(n)
		result := make([]byte, num/2)
		rand.Seed(time.Now().UnixNano())
		rand.Read(result)
		randomNewStr := hex.EncodeToString(result)
		strConf = strings.ReplaceAll(strConf, randomOldStr, randomNewStr)
	}
	// 将字符串类型的数据重新json格式化为lib.Conf类型
	err = json.Unmarshal([]byte(strConf), &conf)
	if err != nil {
		println(err.Error())
	}

	return conf
}
