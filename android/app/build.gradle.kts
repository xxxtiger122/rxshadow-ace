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
        versionCode = 2
        versionName = "1.0"

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
                cFlags += "-O0 -g"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    ndkVersion = "27.0.12077973"

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

// AGP 要求 CMake 源在 src/main/cpp 内 —— 构建时从仓库根同步 lab-ace C 源
// 到 cpp/ace-src/（单一来源，避免复制两份代码）
tasks.register<Sync>("syncAceSources") {
    from(rootProject.projectDir.parentFile)   // lab-ace 根（android/ 的父目录）
    into(layout.projectDirectory.dir("src/main/cpp/ace-src"))
    include("*.c", "*.h")
}
tasks.named("preBuild") {
    dependsOn("syncAceSources")
}
