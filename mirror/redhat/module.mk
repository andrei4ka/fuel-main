# This module downloads required rpm packages and creates rpm repository.
include $(SOURCE_DIR)/mirror/redhat/repo.mk
# This module downloads RH installation images.
include $(SOURCE_DIR)/mirror/redhat/boot.mk

$(BUILD_DIR)/mirror/redhat/build.done: \
		$(BUILD_DIR)/mirror/redhat/repo.done \
		$(BUILD_DIR)/mirror/redhat/boot.done
	$(ACTION.TOUCH)
