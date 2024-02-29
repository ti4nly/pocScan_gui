package lib

import (
	"strings"
)

func expRun() {
	cf, _ := ReadYamlConfig(ExpPath)
	if cf.Info.ExpType == ExpType {
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
