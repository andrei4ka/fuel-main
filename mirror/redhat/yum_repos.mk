define yum_conf
[main]
cachedir=$(BUILD_DIR)/mirror/redhat/cache
keepcache=0
debuglevel=6
logfile=$(BUILD_DIR)/mirror/redhat/yum.log
exclude=*.i686.rpm
exactarch=1
obsoletes=1
gpgcheck=0
plugins=1
pluginpath=$(BUILD_DIR)/mirror/redhat/etc/yum-plugins
pluginconfpath=$(BUILD_DIR)/mirror/redhat/etc/yum/pluginconf.d
reposdir=$(BUILD_DIR)/mirror/redhat/etc/yum.repos.d
endef

define yum_repo_official
[base]
name=RHEL-$(REDHAT_RELEASE) - Base
baseurl=$(MIRROR_REDHAT)/os/$(REDHAT_ARCH)
gpgcheck=0
enabled=1
priority=10

[updates]
name=RHEL-$(REDHAT_RELEASE) - Updates
baseurl=$(MIRROR_REDHAT)/updates/$(REDHAT_ARCH)
gpgcheck=0
enabled=1
priority=10

[extras]
name=RHEL-$(REDHAT_RELEASE) - Extras
baseurl=$(MIRROR_REDHAT)/extras/$(REDHAT_ARCH)
gpgcheck=0
enabled=0
priority=10

[contrib]
name=RHEL-$(REDHAT_RELEASE) - Contrib
baseurl=$(MIRROR_REDHAT)/contrib/$(REDHAT_ARCH)
gpgcheck=0
enabled=0
priority=10
endef

define yum_repo_fuel
[fuel]
name=Mirantis OpenStack Custom Packages
baseurl=$(MIRROR_FUEL)
gpgcheck=0
enabled=1
priority=1
endef

define yum_repo_proprietary
[proprietary]
name = RHEL-$(REDHAT_RELEASE) - Proprietary
baseurl = $(MIRROR_REDHAT)/os/$(REDHAT_ARCH)
gpgcheck = 0
enabled = 1
priority=1
endef

# It's a callable object.
# Usage: $(call create_extra_repo,repo)
# where:
# repo="repo_name,http://path_to_the_repo another_name,http://awesome_repo"
define create_extra_repo
[$(shell VAR=$($1); echo "$${VAR%%,*}")]
name = Extra repo "$(shell VAR=$($1); echo "$${VAR%%,*}")"
baseurl = $(shell VAR=$($1); echo "$${VAR#*,}")
gpgcheck = 0
enabled = 1
priority = 10
endef
