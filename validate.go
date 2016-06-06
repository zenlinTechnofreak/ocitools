package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

type configCheck func(rspec.Spec, string) []error

var bundleValidateFlags = []cli.Flag{
	cli.StringFlag{Name: "path", Usage: "path to a bundle"},
	cli.BoolFlag{Name: "hooks", Usage: "Check specified hooks exist and are executable on the host."},
}

var (
	hooksCheck     bool
	defaultRlimits = []string{
		"RLIMIT_CPU",
		"RLIMIT_FSIZE",
		"RLIMIT_DATA",
		"RLIMIT_STACK",
		"RLIMIT_CORE",
		"RLIMIT_RSS",
		"RLIMIT_NPROC",
		"RLIMIT_NOFILE",
		"RLIMIT_MEMLOCK",
		"RLIMIT_AS",
		"RLIMIT_LOCKS",
		"RLIMIT_SIGPENDING",
		"RLIMIT_MSGQUEUE",
		"RLIMIT_NICE",
		"RLIMIT_RTPRIO",
		"RLIMIT_RTTIME",
	}
)

var bundleValidateCommand = cli.Command{
	Name:  "validate",
	Usage: "validate a OCI bundle",
	Flags: bundleValidateFlags,
	Action: func(context *cli.Context) {
		inputPath := context.String("path")
		if inputPath == "" {
			logrus.Errorf("Bundle path shouldn't be empty")
		}

		if _, err := os.Stat(inputPath); err != nil {
			logrus.Fatal(err)
		}

		configPath := path.Join(inputPath, "config.json")
		content, err := ioutil.ReadFile(configPath)
		if err != nil {
			logrus.Fatal(err)
		}
		if !utf8.Valid(content) {
			logrus.Errorf("%q is not encoded in UTF-8", configPath)
		}
		var spec rspec.Spec
		if err = json.Unmarshal(content, &spec); err != nil {
			logrus.Fatal(err)
		}

		rootfsPath := path.Join(inputPath, spec.Root.Path)
		if fi, err := os.Stat(rootfsPath); err != nil {
			logrus.Fatalf("Cannot find the root path %q", rootfsPath)
		} else if !fi.IsDir() {
			logrus.Fatalf("The root path %q is not a directory.", rootfsPath)
		}

		hooksCheck = context.Bool("hooks")

		checks := []configCheck{
			checkMandatoryFields,
			checkSemVer,
			checkPlatform,
			checkProcess,
			checkLinux,
			checkHooks,
		}

		ret := 0
		defer os.Exit(ret)
		for _, check := range checks {
			for _, err := range check(spec, rootfsPath) {
				logrus.Error(err)
				ret = 1
			}
		}

		if ret == 0 {
			logrus.Debugf("Bundle validation succeeded.")
		}
	},
}

func checkSemVer(spec rspec.Spec, rootfs string) []error {
	logrus.Debugf("check version")

	version := spec.Version
	re, _ := regexp.Compile("^(\\d+)?\\.(\\d+)?\\.(\\d+)?$")
	if ok := re.Match([]byte(version)); !ok {
		return append([]error{}, fmt.Errorf("%q is not a valid version format, please read 'SemVer v2.0.0'", version))
	}

	return nil
}

func checkPlatform(spec rspec.Spec, rootfs string) []error {
	logrus.Debugf("check platform")

	platform := spec.Platform
	validCombins := map[string][]string{
		"darwin":    {"386", "amd64", "arm", "arm64"},
		"dragonfly": {"amd64"},
		"freebsd":   {"386", "amd64", "arm"},
		"linux":     {"386", "amd64", "arm", "arm64", "ppc64", "ppc64le", "mips64", "mips64le"},
		"netbsd":    {"386", "amd64", "arm"},
		"openbsd":   {"386", "amd64", "arm"},
		"plan9":     {"386", "amd64"},
		"solaris":   {"amd64"},
		"windows":   {"386", "amd64"}}
	for os, archs := range validCombins {
		if os == platform.OS {
			for _, arch := range archs {
				if arch == platform.Arch {
					return nil
				}
			}
			return append([]error{}, fmt.Errorf("Combination of %q and %q is invalid.", platform.OS, platform.Arch))
		}
	}

	return append([]error{}, fmt.Errorf("Operation system %q of the bundle is not supported yet.", platform.OS))
}

func checkHooks(spec rspec.Spec, rootfs string) (errs []error) {
	logrus.Debugf("check hooks")

	hooks := spec.Hooks
	errs = append(errs, checkEventHooks("pre-start", hooks.Prestart)...)
	errs = append(errs, checkEventHooks("post-start", hooks.Poststart)...)
	errs = append(errs, checkEventHooks("post-stop", hooks.Poststop)...)

	return
}

func checkEventHooks(hookType string, hooks []rspec.Hook) (errs []error) {
	for _, hook := range hooks {
		if !filepath.IsAbs(hook.Path) {
			errs = append(errs, fmt.Errorf("The %s hook %v: is not absolute path", hookType, hook.Path))
		}

		if hooksCheck {
			fi, err := os.Stat(hook.Path)
			if err != nil {
				errs = append(errs, fmt.Errorf("Cannot find %s hook: %v", hookType, hook.Path))
			}
			if fi.Mode()&0111 == 0 {
				errs = append(errs, fmt.Errorf("The %s hook %v: is not executable", hookType, hook.Path))
			}
		}

		for _, env := range hook.Env {
			if !envValid(env) {
				errs = append(errs, fmt.Errorf("Env %q for hook %v is in the invalid form.", env, hook.Path))
			}
		}
	}

	return
}

func checkProcess(spec rspec.Spec, rootfs string) (errs []error) {
	logrus.Debugf("check process")

	process := spec.Process
	if !path.IsAbs(process.Cwd) {
		errs = append(errs, fmt.Errorf("cwd %q is not an absolute path", process.Cwd))
	}

	for _, env := range process.Env {
		if !envValid(env) {
			errs = append(errs, fmt.Errorf("env %q should be in the form of 'key=value'. The left hand side must consist solely of letters, digits, and underscores '_'.", env))
		}
	}

	for index := 0; index < len(process.Capabilities); index++ {
		capability := process.Capabilities[index]
		if !capValid(capability) {
			errs = append(errs, fmt.Errorf("capability %q is not valid, man capabilities(7)", process.Capabilities[index]))
		}
	}

	for index := 0; index < len(process.Rlimits); index++ {
		if !rlimitValid(process.Rlimits[index].Type) {
			errs = append(errs, fmt.Errorf("rlimit type %q is invalid.", process.Rlimits[index].Type))
		}
	}

	if len(process.ApparmorProfile) > 0 {
		profilePath := path.Join(rootfs, "/etc/apparmor.d", process.ApparmorProfile)
		if _, err := os.Stat(profilePath); err != nil {
			errs = append(errs, err)
		}
	}

	return
}

//Linux only
func checkLinux(spec rspec.Spec, rootfs string) (errs []error) {
	logrus.Debugf("check linux")

	utsExists := false

	logrus.Debugf("check uid mappings")
	if len(spec.Linux.UIDMappings) > 5 {
		errs = append(errs, fmt.Errorf("Only 5 UID mappings are allowed (linux kernel restriction)."))
	}

	logrus.Debugf("check gid mappings")
	if len(spec.Linux.GIDMappings) > 5 {
		errs = append(errs, fmt.Errorf("Only 5 GID mappings are allowed (linux kernel restriction)."))
	}

	logrus.Debugf("check gid mappings")
	for index := 0; index < len(spec.Linux.Namespaces); index++ {
		if !namespaceValid(spec.Linux.Namespaces[index]) {
			errs = append(errs, fmt.Errorf("namespace %v is invalid.", spec.Linux.Namespaces[index]))
		} else if spec.Linux.Namespaces[index].Type == rspec.UTSNamespace {
			utsExists = true
		}
	}

	if spec.Platform.OS == "linux" && !utsExists && spec.Hostname != "" {
		errs = append(errs, fmt.Errorf("On Linux, hostname requires a new UTS namespace to be specified as well"))
	}

	for index := 0; index < len(spec.Linux.Devices); index++ {
		if !deviceValid(spec.Linux.Devices[index]) {
			errs = append(errs, fmt.Errorf("device %v is invalid.", spec.Linux.Devices[index]))
		}
	}

	if spec.Linux.Seccomp != nil {
		errs = append(errs, checkSeccomp(*spec.Linux.Seccomp)...)
	}

	switch spec.Linux.RootfsPropagation {
	case "":
	case "private":
	case "rprivate":
	case "slave":
	case "rslave":
	case "shared":
	case "rshared":
	default:
		errs = append(errs, fmt.Errorf("rootfsPropagation must be empty or one of \"private|rprivate|slave|rslave|shared|rshared\""))
	}

	return
}

func checkSeccomp(s rspec.Seccomp) (errs []error) {
	logrus.Debugf("check seccomp")

	if !seccompActionValid(s.DefaultAction) {
		errs = append(errs, fmt.Errorf("seccomp defaultAction %q is invalid.", s.DefaultAction))
	}
	for index := 0; index < len(s.Syscalls); index++ {
		if !syscallValid(s.Syscalls[index]) {
			errs = append(errs, fmt.Errorf("syscall %v is invalid.", s.Syscalls[index]))
		}
	}
	for index := 0; index < len(s.Architectures); index++ {
		switch s.Architectures[index] {
		case rspec.ArchX86:
		case rspec.ArchX86_64:
		case rspec.ArchX32:
		case rspec.ArchARM:
		case rspec.ArchAARCH64:
		case rspec.ArchMIPS:
		case rspec.ArchMIPS64:
		case rspec.ArchMIPS64N32:
		case rspec.ArchMIPSEL:
		case rspec.ArchMIPSEL64:
		case rspec.ArchMIPSEL64N32:
		default:
			errs = append(errs, fmt.Errorf("seccomp architecture %q is invalid", s.Architectures[index]))
		}
	}

	return
}

func envValid(env string) bool {
	items := strings.Split(env, "=")
	if len(items) < 2 {
		return false
	}
	for _, ch := range strings.TrimSpace(items[0]) {
		if !unicode.IsDigit(ch) && !unicode.IsLetter(ch) && ch != '_' {
			return false
		}
	}

	return true
}

func capValid(capability string) bool {
	for _, val := range defaultCaps {
		if val == capability {
			return true
		}
	}

	return false
}

func rlimitValid(rlimit string) bool {
	for _, val := range defaultRlimits {
		if val == rlimit {
			return true
		}
	}

	return false
}

func namespaceValid(ns rspec.Namespace) bool {
	switch ns.Type {
	case rspec.PIDNamespace:
	case rspec.NetworkNamespace:
	case rspec.MountNamespace:
	case rspec.IPCNamespace:
	case rspec.UTSNamespace:
	case rspec.UserNamespace:
	default:
		return false
	}

	return true
}

func deviceValid(d rspec.Device) bool {
	switch d.Type {
	case "b":
	case "c":
	case "u":
		if d.Major <= 0 {
			return false
		}
		if d.Minor <= 0 {
			return false
		}
	case "p":
		if d.Major > 0 || d.Minor > 0 {
			return false
		}
	default:
		return false
	}

	return true
}

func seccompActionValid(secc rspec.Action) bool {
	switch secc {
	case "":
	case rspec.ActKill:
	case rspec.ActTrap:
	case rspec.ActErrno:
	case rspec.ActTrace:
	case rspec.ActAllow:
	default:
		return false
	}

	return true
}

func syscallValid(s rspec.Syscall) bool {
	if !seccompActionValid(s.Action) {
		return false
	}
	for index := 0; index < len(s.Args); index++ {
		arg := s.Args[index]
		switch arg.Op {
		case rspec.OpNotEqual:
		case rspec.OpLessEqual:
		case rspec.OpEqualTo:
		case rspec.OpGreaterEqual:
		case rspec.OpGreaterThan:
		case rspec.OpMaskedEqual:
		default:
			return false
		}
	}

	return true
}

func isStruct(t reflect.Type) bool {
	return t.Kind() == reflect.Struct
}

func isStructPtr(t reflect.Type) bool {
	return t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct
}

func checkMandatoryUnit(field reflect.Value, tagField reflect.StructField, parent string) (errs []error) {
	mandatory := !strings.Contains(tagField.Tag.Get("json"), "omitempty")
	switch field.Kind() {
	case reflect.Ptr:
		if mandatory && field.IsNil() == true {
			errs = append(errs, fmt.Errorf("'%s.%s' should not be empty.", parent, tagField.Name))
		}
	case reflect.String:
		if mandatory && (field.Len() == 0) {
			errs = append(errs, fmt.Errorf("'%s.%s' should not be empty.", parent, tagField.Name))
		}
	case reflect.Slice:
		if mandatory && (field.Len() == 0) {
			return append(errs, fmt.Errorf("'%s.%s' should not be empty.", parent, tagField.Name))
		}
		for index := 0; index < field.Len(); index++ {
			mValue := field.Index(index)
			if mValue.CanInterface() {
				errs = append(errs, checkMandatory(mValue.Interface())...)
			}
		}
	case reflect.Map:
		if mandatory && ((field.IsNil() == true) || (field.Len() == 0)) {
			return append(errs, fmt.Errorf("'%s.%s' should not be empty.", parent, tagField.Name))
		}

		keys := field.MapKeys()
		for index := 0; index < len(keys); index++ {
			mValue := field.MapIndex(keys[index])
			if mValue.CanInterface() {
				errs = append(errs, checkMandatory(mValue.Interface())...)
			}
		}
	default:
	}

	return
}

func checkMandatory(obj interface{}) (errs []error) {
	objT := reflect.TypeOf(obj)
	objV := reflect.ValueOf(obj)
	if isStructPtr(objT) {
		objT = objT.Elem()
		objV = objV.Elem()
	} else if !isStruct(objT) {
		return nil
	}

	for i := 0; i < objT.NumField(); i++ {
		t := objT.Field(i).Type
		if isStructPtr(t) && objV.Field(i).IsNil() {
			if !strings.Contains(objT.Field(i).Tag.Get("json"), "omitempty") {
				errs = append(errs, fmt.Errorf("'%s.%s' should not be empty", objT.Name(), objT.Field(i).Name))
			}
		} else if (isStruct(t) || isStructPtr(t)) && objV.Field(i).CanInterface() {
			errs = append(errs, checkMandatory(objV.Field(i).Interface())...)
		} else {
			errs = append(errs, checkMandatoryUnit(objV.Field(i), objT.Field(i), objT.Name())...)
		}

	}

	return
}

func checkMandatoryFields(spec rspec.Spec, rootfs string) (errs []error) {
	logrus.Debugf("check mandatory fields")

	return checkMandatory(spec)
}
