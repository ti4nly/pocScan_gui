package lib

import (
	"github.com/eddieivan01/nic"
	"regexp"
	"strconv"
	"strings"
)

// SendPayload 发送带有payload的请求
func SendPayload(rule Rule) (bool, []string) {
	url := rule.Request.Path
	var res *nic.Response
	var err error
	proxy, _ := Proxy.Get()
	timeOutStr, _ := Timeout.Get()
	timeOut, _ := strconv.Atoi(timeOutStr)
	if rule.Request.Method == "GET" {
		res, err = nic.Get(url, &nic.H{
			AllowRedirect: rule.Request.Redirect,
			Headers:       rule.Request.Headers,
			Raw:           rule.Request.Data,
			Proxy:         proxy,
			Timeout:       int64(timeOut),
		})
		if err != nil {
			println(err.Error())
			return false, nil
		}
	} else if rule.Request.Method == "POST" {
		if rule.Request.Files.FilePath == "" {
			res, err = nic.Post(url, &nic.H{
				AllowRedirect: rule.Request.Redirect,
				Headers:       rule.Request.Headers,
				Raw:           rule.Request.Data,
				Proxy:         proxy,
				Timeout:       int64(timeOut),
			})
			if err != nil {
				println(err.Error())
				return false, nil
			}
		} else {
			res, err = nic.Post(url, &nic.H{
				AllowRedirect: rule.Request.Redirect,
				Headers:       rule.Request.Headers,
				Files: nic.KV{
					rule.Request.Files.Name: nic.FileFromPath(rule.Request.Files.FilePath).FName(rule.Request.Files.FileName).MIME(rule.Request.Files.ContentType),
				},
				Proxy:   proxy,
				Timeout: int64(timeOut),
			})

			if err != nil {
				println(err.Error())
				return false, nil
			}
		}

		if err != nil {
			println(err.Error())
			return false, nil
		}
	}
	return CheckRule(res, rule)

}

// CheckRule 在发送请求后校验yaml中需要校验的内容
func CheckRule(res *nic.Response, rule Rule) (bool, []string) {
	// 对应conf.Variable，每次校验时从返回包获取需要提取的数据并返回，用于存入conf.Variable
	var variable []string
	// 用于存储每一个check校验的结果
	var isSuccess []bool
	// 用于存储check中每个desired的校验结果
	for _, check := range rule.Checks {
		var desiredYes []bool
		// req截取请求返回包中的某部分数据，用于与不同类型的desired作比较
		var req string
		if check.CheckType == "status" {
			req = strconv.Itoa(res.StatusCode)
		} else {
			// check.CheckType为string和regex类似，均需要在body或者header中判断
			if check.Place == "body" {
				req = res.Text
			} else if check.Place == "header" {
				// 循环取出headers的全部数据并拼接为string
				for name, values := range res.Header {
					for _, value := range values {
						req += name + ": " + value + "\n"
					}
				}
			} else {
				// 如果check.Place没有指定或者指定不是body也不是header则默认为匹配header+body
				for name, values := range res.Header {
					for _, value := range values {
						req += name + ": " + value + "\n"
					}
				}
				req += res.Text
			}
		}
		// 遍历desireds中的每个desired进行校验
		for _, desired := range check.Desireds {
			if check.CheckType == "regex" {
				// 正则校验
				re := regexp.MustCompile(desired)
				if strings.Contains(desired, "(") {
					// 分组校验
					v := re.FindStringSubmatch(req)
					if len(v) == 0 {
						desiredYes = append(desiredYes, false)
					} else {
						variable = append(variable, v[1])
						desiredYes = append(desiredYes, true)
					}
				} else {
					// 正则校验
					v := re.FindString(req)
					if len(v) == 0 {
						desiredYes = append(desiredYes, false)
					} else {
						variable = append(variable, v)
						desiredYes = append(desiredYes, true)
					}
				}

			} else {
				if string(desired[0]) == "!" {
					// 如果desired中第一个字符是！则将！去掉然后，然后如果req中不包含desired为真
					desired = strings.Replace(desired, "!", "", 1)
					if !strings.Contains(req, desired) {
						desiredYes = append(desiredYes, true)
					} else {
						desiredYes = append(desiredYes, false)
					}
				}
				// 如果desired中的字符在返回包对应的数据中为真
				if strings.Contains(req, desired) {
					desiredYes = append(desiredYes, true)
				} else {
					desiredYes = append(desiredYes, false)
				}
			}
		}

		// check中desired有任意一个通过校验
		if check.Condition == "or" {
			for num, a := range desiredYes {
				// 取到一个为真则该check为true，退出遍历
				if a == true {
					isSuccess = append(isSuccess, true)
					break
				}
				// 取出所有校验结果都没退出说明全为false则该check为false
				if num == len(desiredYes)-1 {
					isSuccess = append(isSuccess, false)
				}
			}
		} else {
			// check中desired全部通过校验
			for num, a := range desiredYes {
				// 取到一个为false则该check为false，退出遍历
				if a == false {
					isSuccess = append(isSuccess, false)
					break
				}
				// 取出所有校验结果都没退出说明全为true则该check为true
				if num == len(desiredYes)-1 {
					isSuccess = append(isSuccess, true)
				}
			}
		}
	}

	if rule.ChecksCondition == "or" {
		// 遍历isSuccess，有一个check通过校验即可，遇到true则返回true
		for _, b := range isSuccess {
			if b == true {
				return true, variable
			}
		}
		return false, nil
	} else {
		// 默认rule.ChecksCondition == "and"
		// check需要全部校验通过，有false则退出并返回false
		for _, b := range isSuccess {
			if b == false {
				return false, nil
			}
		}
		return true, variable
	}
}
