
E:/android_SDK/ndk/26.1.10909125/ndk-build NDK_PROJECT_PATH=. NDK_APPLICATION_MK=./Application.mk APP_BUILD_SCRIPT=Android.mk clean
E:/android_SDK/ndk/26.1.10909125/ndk-build NDK_DEBUG=1 NDK_PROJECT_PATH=. NDK_APPLICATION_MK=./Application.mk APP_BUILD_SCRIPT=Android.mk -j16
adb push obj/local/armeabi-v7a/my_inject /data/local/tmp/
adb shell chmod 777 /data/local/tmp/my_inject
adb forward tcp:1234 tcp:1234
#防止因为指令出错打断流程
adb shell su -c '/data/local/tmp/rm-server.sh'
#后台执行 不要一直等待
Write-Output "123456"
Start-Process -WindowStyle hidden -FilePath "adb" "shell nohup su -c '/data/local/tmp/lldb-server platform --listen '*:1234' --server' "
