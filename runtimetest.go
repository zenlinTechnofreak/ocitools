package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/ocitools/units"
)

const bundleCacheDir = "./bundles"

var runtimetestFlags = []cli.Flag{
	cli.StringFlag{Name: "runtime, r", Usage: "runtime to be tested"},
	cli.StringFlag{Name: "level, l", Usage: "-l=all: output all the details and statistics; -l=err-only: output failure details and statistics"},
	cli.BoolFlag{Name: "debug, d", Usage: "switch of debug mode, default to 'false', with '--debug' to enable debug mode"},
}

var runtimeTestCommand = cli.Command{
	Name:  "runtimetest",
	Usage: "test if a runtime is compliant to OCI Runtime Specification",
	Flags: runtimetestFlags,
	Action: func(context *cli.Context) {
		if os.Geteuid() != 0 {
			logrus.Fatalln("Should be run as 'root'")
		}
		var runtime string
		if runtime = context.String("runtime"); runtime != "runc" {
			logrus.Fatalf("'%v' is currently not supported", runtime)
		}
		level := context.String("level")
		setDebugMode(context.Bool("debug"))

		units.LoadTestUnits("./cases.conf")

		if err := os.MkdirAll(bundleCacheDir, os.ModePerm); err != nil {
			logrus.Printf("Failed to create cache dir: %v", bundleCacheDir)
			return
		}

		for _, tu := range *units.Units {
			testTask(tu, runtime)
		}

		units.OutputResult(output)

		if err := os.RemoveAll(bundleCacheDir); err != nil {
			logrus.Fatalf("Failed to remove cache dir of bundles '%v': %v\n", bundleCacheDir, err)
		}

		if err := os.Remove("./config.json"); err != nil {
			logrus.Fatalf("Failed to remove ./config.json: %v\n", err)
		}
	},
}

func setDebugMode(debug bool) {
	if !debug {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

func testTask(unit *units.TestUnit, runtime string) {
	logrus.Debugf("Testing bundle: %v, Testing args: %v\n", unit.Name, unit.Args)
	if err := unit.SetRuntime(runtime); err != nil {
		logrus.Fatalf("Failed to setup runtime '%s': %v\n", runtime, err)
	} else {
		unit.Run()
	}
	return
}
