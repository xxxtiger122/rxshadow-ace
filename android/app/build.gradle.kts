plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.rxshadow.ace"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.rxshadow.ace"
        minSdk = 28          // Android 9，与 lab-ace NDK API 28 一致
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.11"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.04.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

// 任务：用 NDK 构建 lab-ace 二进制并拷入 assets/bin（无 NDK 时跳过并警告）
tasks.register<Exec>("buildNative") {
    val ndk = System.getenv("NDK") ?: System.getenv("ANDROID_NDK_HOME") ?: ""
    val outDir = project.file("src/main/assets/bin")
    commandLine("bash", "-c", """
        set -e
        if [ -z "$ndk" ] && ! command -v aarch64-linux-android28-clang >/dev/null 2>&1; then
            echo "WARN: 未找到 NDK（aarch64-linux-android28-clang），跳过 native 构建"
            echo "WARN: 请设置 NDK=/path/to/ndk 或把 NDK 工具链加入 PATH"
            exit 0
        fi
        cd ../..  # lab-ace 根目录
        NDK="$ndk" ./build-lab-ace.sh
        mkdir -p android/app/src/main/assets/bin
        cp bin/arm64/* android/app/src/main/assets/bin/
        echo "native 产物已拷入 assets/bin"
    """)
}
