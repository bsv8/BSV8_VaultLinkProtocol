"""SDK 使用框架固定的 mbedTLS，不依赖 RocKey 源码或其构建脚本。"""
import os
Import("env")
pkg = env.PioPlatform().get_package_dir("framework-arduinoespressif32")
env.Append(LIBPATH=[os.path.join(pkg, "tools", "sdk", "esp32", "lib")],
           LIBS=["mbedtls", "mbedx509", "mbedcrypto"])
# 框架静态库未编入 HKDF/RIPEMD160。显式编译同版上游两个模块，非自写密码算法。
env.BuildSources(os.path.join("$BUILD_DIR", "mbedtls-extra"),
                 os.path.join(env["PROJECT_DIR"], "lib", "mbedtls-extra"))
