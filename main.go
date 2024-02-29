package main

import (
	"TLScan/lib"
	_ "embed"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"os"
)

func main() {
	pwd, _ := os.Getwd()
	fontPwd := pwd + "/assert/STKAITI.TTF"
	err := os.Setenv("FYNE_FONT", fontPwd)
	if err != nil {
		return
	}
	myApp := app.New()
	myWin := myApp.NewWindow("TLScan")
	myWin.SetIcon(lib.ResourceLogoJpg)
	myWin.Resize(fyne.NewSize(700, 730))
	myApp.Settings().SetTheme(theme.DarkTheme())

	// 顶部工具栏
	//set := lib.MakeSetMenu(myApp)

	// 漏洞扫描中主页面的布局设计
	scanMain := lib.MakeScanMain()
	//漏洞扫描中选项的布局设计
	scanOpt := lib.MakeScanOpt()

	//漏洞扫描模块
	scanTabls := container.NewAppTabs(
		container.NewTabItem("扫描", scanMain),
		container.NewTabItem("选项", scanOpt),
	)

	//漏洞利用模块
	attackTabls := lib.MakeExpView()

	tabs := container.NewAppTabs(
		container.NewTabItem("漏洞扫描", scanTabls),
		container.NewTabItem("漏洞利用", attackTabls),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	myWin.SetContent(tabs)
	//myWin.SetMainMenu(set)
	myWin.SetMaster()
	myWin.ShowAndRun()

}
