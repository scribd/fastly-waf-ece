module github.com/scribd/fastly-waf-ece

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/magiconair/properties v1.8.0
	github.com/mitchellh/go-homedir v1.0.0
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/pkg/errors v0.8.1
	github.com/spf13/cobra v0.0.3
	github.com/spf13/viper v1.3.1
	github.com/stretchr/testify v1.2.2
	gopkg.in/mcuadros/go-syslog.v2 v2.2.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0-20170531160350-a96e63847dc3
)

replace gopkg.in/mcuadros/go-syslog.v2 => github.com/libc/go-syslog v0.0.0-20190315120441-9a827eb2069c
