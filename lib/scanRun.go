package lib

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var Exit = false

func scanRun() {
	t, _ := Thread.Get()
	thread, err1 := strconv.Atoi(t)
	if err1 == nil {
		thread = 20
	}
	pwd, _ := os.Getwd()
	var allPocPath []string
	//获取当前目录下的所有文件或目录信息
	err := filepath.Walk(pwd+"\\poc\\", func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, ".yaml") {
			allPocPath = append(allPocPath, path)
		}
		return nil
	})
	if err != nil {
		return
	}
	for _, pocName := range OptLeak {
		var path string
		for _, pocPath := range allPocPath {
			if strings.Contains(pocPath, pocName) {
				path = pocPath
			}
		}
		cf, err := ReadYamlConfig(path)
		if err != nil {
			println(err.Error())
		}
		if strings.Contains(Target, "\n") {
			var targetChan = make(chan string)
			go setTarget(targetChan)
			// 循环创建线程调用threadRun函数，循环多少次就会创建多少线程
			for i := 0; i < thread; i++ {
				go threadRun(targetChan, cf)
			}
		} else {
			// 对url进行简单处理
			if !strings.Contains(Target, "http") && !strings.Contains(Target, "https") {
				Target = "http://" + Target
			}
			if Target[len(Target)-1:] == "/" {
				Target = Target[:len(Target)-1]
			}
			conf := cf
			checkRun(Target, conf)
		}

	}
}

// 将Target以换行符切片并逐个传入通道targetChan
func setTarget(targetChan chan string) {
	var a []string
	if strings.Contains(Target, "\r") {
		Target = strings.ReplaceAll(Target, "\r", "")
	}
	a = strings.Split(Target, "\n")
	Zongliang = len(a) * len(OptLeak)
	for _, line := range a {
		// 对于没有前缀的赋前缀为http://
		if !strings.Contains(line, "http") && !strings.Contains(line, "https") {
			line = "http://" + line
		}
		// 去掉末尾的斜线
		if line[len(line)-1:] == "/" {
			line = line[:len(line)-1]
		}
		targetChan <- line
		if Exit {
			break
		}
	}
	close(targetChan)
}

// 读取targetChan通道中的url值并调用函数exploit开始扫描
func threadRun(targetChan chan string, cf Conf) {
	for {
		// 每个子线程都重新创建一个conf用来暂存cf，避免多线程同时读取同一个conf时锁死的问题
		var conf Conf
		byts, err := json.Marshal(cf)
		if err != nil {
			println(err.Error())
		}
		strConf := string(byts)
		err = json.Unmarshal([]byte(strConf), &conf)
		target, ok := <-targetChan
		if ok {
			checkRun(target, conf)

		} else {
			break
		}
	}
}

// 根据request里面的参数判断调用的请求函数
func checkRun(target string, conf Conf) {
	// 替换掉rule中设置的一些需要处理的参数{{payload}}和{{base64(string)}}除外
	conf = ConfReplace(target, conf)
	isSuccess := false
	for _, rule := range conf.Rules {
		var variable []string
		if strings.Contains(rule.Request.Path, "getrecords.php") {
			// 如果是dnslog判断的则延迟几秒请求
			time.Sleep(3 * 1e9)
		}
		byts2, err := json.Marshal(rule)
		if err != nil {
			println(err.Error())
		}
		ruleStr := string(byts2)
		if rule.Request.Payload != nil {
			// 遍历取出每个payload赋值给rule中的{{payload}}并发起请求
			for _, payload := range rule.Request.Payload {
				newRuleStr := ruleStr
				if strings.Contains(newRuleStr, "{{payload}}") {
					newRuleStr = strings.ReplaceAll(newRuleStr, "{{payload}}", payload)
				}
				// {{base64(string)}}的处理,放在这里处理是避免需要被编码的数据中包含有payload时先被编码了，{{payload}}还没被替换为requests中的payload
				if strings.Contains(newRuleStr, "{{base64(") {
					re := "{{base64\\((.*?)\\)}}"
					n := regexp.MustCompile(re).FindStringSubmatch(newRuleStr)[1]
					bsOldStr := "{{base64(" + n + ")}}"
					bsNewStr := base64.StdEncoding.EncodeToString([]byte(n))
					newRuleStr = strings.ReplaceAll(newRuleStr, bsOldStr, bsNewStr)
				}
				err = json.Unmarshal([]byte(newRuleStr), &rule)
				if err != nil {
					println(err.Error())
				}
				isSuccess, variable = SendPayload(rule)
				if isSuccess {
					break
				}
			}
		} else {
			newRuleStr := ruleStr
			if strings.Contains(newRuleStr, "{{base64(") {
				re := "{{base64\\((.*?)\\)}}"
				n := regexp.MustCompile(re).FindStringSubmatch(newRuleStr)[1]
				bsOldStr := "{{base64(" + n + ")}}"
				bsNewStr := base64.StdEncoding.EncodeToString([]byte(n))
				newRuleStr = strings.ReplaceAll(newRuleStr, bsOldStr, bsNewStr)
			}
			err = json.Unmarshal([]byte(newRuleStr), &rule)
			if err != nil {
				println(err.Error())
			}
			isSuccess, variable = SendPayload(rule)
		}

		// 如果从返回包获取到了下一个请求中需要的值则重新处理一下conf，将conf.Variable的值替换掉后面请求需要用到的参数
		if len(variable) > 0 {
			for _, v := range variable {
				conf.Variable = append(conf.Variable, v)
			}
			// json序列化conf，便于转换为string
			byts, err := json.Marshal(conf)
			if err != nil {
				println(err.Error())
			}
			strConf := string(byts)
			for num, variable := range conf.Variable {
				if strings.Contains(strConf, "variable["+strconv.Itoa(num)+"]") {
					strConf = strings.ReplaceAll(strConf, "{{variable["+strconv.Itoa(num)+"]}}", variable)
				}
			}
			err = json.Unmarshal([]byte(strConf), &conf)
			if err != nil {
				println(err.Error())
			}
		}
		if isSuccess == false {
			break
		}
	}
	if ExpType == "scan" {
		if isSuccess == true {
			o, _ := OutPrint.Get()
			u, err := url.Parse(target)
			if err != nil {
				println(err.Error())
			}
			scheme := u.Scheme
			// 主机信息host，包括hostname和port
			host := u.Host
			err = OutPrint.Set(o + "\n" + scheme + "://" + host + "-----------------存在" + conf.Info.Detail)
			if err != nil {
				println(err.Error())
			}
			//result := "[++++]" + target + "存在" + conf.Info.Detail
			//color.Green(result)
			f, err := os.OpenFile("./result/"+conf.Info.VulId+"_yes.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0744)
			if err != nil {
				println(err.Error())
			}
			defer func(f *os.File) {
				err := f.Close()
				if err != nil {
					println(err.Error())
				}
			}(f)
			write := bufio.NewWriter(f)
			_, err = write.WriteString(target + "\n")
			if err != nil {
				println(err.Error())
			}
			err = write.Flush()
			if err != nil {
				println(err.Error())
			}
			// 获取完成数并加一，计算进度
			Completed += 1
			err = ProgressData.Set(float64(Completed) / float64(Zongliang))
			if err != nil {
				println(err.Error())
			}

		}

	} else if ExpType == "upload" {
		if isSuccess == true {
			var outString string
			for _, variable := range conf.Variable {
				outString += variable
			}
			err := UploadOutPrint.Set("文件上传成功，文件地址为：" + outString)
			if err != nil {
				println(err.Error())
			}
		} else {
			err := UploadOutPrint.Set("文件上传失败")
			if err != nil {
				println(err.Error())
			}
		}
	} else if ExpType == "command" {
		if isSuccess == true {
			var outString string
			for _, variable := range conf.Variable {
				outString += variable
			}
			err := CmdOutPrint.Set(outString)
			if err != nil {
				println(err.Error())
			}
		} else {
			err := CmdOutPrint.Set("命令执行失败！")
			if err != nil {
				println(err.Error())
			}
		}
	}

}
