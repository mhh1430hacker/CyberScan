import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing with the CyberScan publisher key (the same key as the APK on the website, so this
// app installs as an update over it). android/key.properties (never committed) names the key file
// and alias; the password comes from CYBERSCAN_KEYSTORE_PASSWORD. phone/release.ps1 sets both up.
val keyProps = Properties().apply {
    val f = rootProject.file("key.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
val releaseKey = keyProps.getProperty("storeFile") != null && System.getenv("CYBERSCAN_KEYSTORE_PASSWORD") != null

android {
    namespace = "io.github.mhh1430hacker.cyberscan"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "27.0.12077973"   // installed locally; Flutter requires an NDK for every Android build

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "io.github.mhh1430hacker.cyberscan"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        create("release") {
            if (releaseKey) {
                storeFile = file(keyProps.getProperty("storeFile"))
                keyAlias = keyProps.getProperty("keyAlias")
                storePassword = System.getenv("CYBERSCAN_KEYSTORE_PASSWORD")
                keyPassword = System.getenv("CYBERSCAN_KEY_PASSWORD") ?: System.getenv("CYBERSCAN_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // the publisher key when it is set up (phone/release.ps1), else debug keys so `flutter run --release` works
            signingConfig = signingConfigs.getByName(if (releaseKey) "release" else "debug")
        }
    }
}

flutter {
    source = "../.."
}
