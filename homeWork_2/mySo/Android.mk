 # Android.mk必须以LOCAL_PATH开头，注释#除外
    # 设置工作目录，而my-dir则会返回Android.mk文件所在的目录
    LOCAL_PATH := $(call my-dir)

    # 借助CLEAR_VARS变量清除除LOCAL_PATH外的所有LOCAL_<name>变量
    include $(CLEAR_VARS)

    # 设置模块的名称，即编译出来.so文件名
    # 注，要和上述步骤中build.gradle中NDK节点设置的名字相同
    LOCAL_MODULE := myHook

    # 指定参与模块编译的C/C++源文件列表，多文件用"\"隔开
    LOCAL_SRC_FILES := myHook.c


    # 必须在文件结尾定义编译类型，指定生成的静态库或者共享库在运行时依赖的共享库模块列表。
    # BUILD_SHARED_LIBRARY 共享库，供java或者其他共享库调用
    # BUILD_STATIC_LIBRARY 静态库，供共享库调用，不能直接被java调用
    include $(BUILD_SHARED_LIBRARY)