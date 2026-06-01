package main

import (
	"embed"
	_ "embed"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

// Wails uses Go's `embed` package to embed the frontend files into the binary.
// Any files in the frontend/dist folder will be embedded into the binary and
// made available to the frontend.
// See https://pkg.go.dev/embed for more information.

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--diagnose-core" {
		if err := runCoreDiagnostic(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	app := application.New(application.Options{
		Name:        "Sandfox",
		Description: "A Wails sing-box desktop client",
		Services: []application.Service{
			application.NewService(NewSandfoxService()),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:           "Sandfox",
		Width:           1220,
		Height:          780,
		MinWidth:        1180,
		MinHeight:       720,
		StartState:      application.WindowStateNormal,
		InitialPosition: application.WindowCentered,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(243, 244, 241),
		URL:              "/",
	})

	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		window.Hide()
		e.Cancel()
	})

	showMainWindow := func() {
		window.Show()
		window.Restore()
		window.Focus()
	}

	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(e *application.ApplicationEvent) {
		showMainWindow()
	})
	app.Event.OnApplicationEvent(events.Mac.ApplicationDidBecomeActive, func(e *application.ApplicationEvent) {
		showMainWindow()
	})
	app.Event.OnApplicationEvent(events.Mac.ApplicationShouldHandleReopen, func(e *application.ApplicationEvent) {
		showMainWindow()
	})

	menu := app.Menu.New()
	menu.Add("Show Sandfox").OnClick(func(ctx *application.Context) {
		showMainWindow()
	})
	menu.AddSeparator()
	menu.Add("Quit").OnClick(func(ctx *application.Context) {
		app.Quit()
	})
	app.Menu.Set(menu)

	tray := app.SystemTray.New()
	tray.SetTooltip("Sandfox")
	if runtime.GOOS == "darwin" {
		tray.SetTemplateIcon(icons.SystrayMacTemplate)
	}
	tray.OnClick(func() {
		showMainWindow()
	})
	tray.SetMenu(menu)

	go func() {
		for _, delay := range []time.Duration{800 * time.Millisecond, 2 * time.Second, 4 * time.Second} {
			time.Sleep(delay)
			showMainWindow()
		}
	}()

	err := app.Run()

	if err != nil {
		log.Fatal(err)
	}
}

func runCoreDiagnostic() error {
	service := NewSandfoxService()
	path, err := service.GenerateConfig()
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}
	fmt.Println("config:", path)

	check := service.ValidateConfig()
	fmt.Println("check ok:", check.OK)
	if check.Message != "" {
		fmt.Println("check message:", check.Message)
	}
	if !check.OK {
		return fmt.Errorf("config validation failed")
	}

	if err := service.StartCore(); err != nil {
		return fmt.Errorf("start core: %w", err)
	}
	time.Sleep(2 * time.Second)

	status := service.GetSingboxStatus()
	fmt.Println("running:", status.Data.Running)
	if status.Data.PID != 0 {
		fmt.Println("pid:", status.Data.PID)
	}
	if status.Data.BinaryPath != "" {
		fmt.Println("binary:", status.Data.BinaryPath)
	}
	if status.Data.ConfigPath != "" {
		fmt.Println("status config:", status.Data.ConfigPath)
	}
	if !status.Data.Running {
		return fmt.Errorf("core stopped after launch")
	}

	if err := service.StopCore(); err != nil {
		return fmt.Errorf("stop core: %w", err)
	}
	return nil
}
