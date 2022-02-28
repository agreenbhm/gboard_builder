# Gboard Builder #
Python script for modding official Gboard APK to allow grammar-check feature on non-Pixel devices.

### Requirements ###
- Python3
- Java 'keytool' in PATH
- Smali JAR (https://bitbucket.org/JesusFreke/smali/downloads/)
- Baksmali JAR (https://bitbucket.org/JesusFreke/smali/downloads/)
- UberAPKSigner JAR (https://github.com/patrickfav/uber-apk-signer)
- Android signing key (instructions to generate below)

### Usage ###

gboard_builder.py [-h] --keystore KEYSTORE --keyAlias KEYALIAS --keystorePassword KEYSTOREPASSWORD --keyPassword KEYPASSWORD --apk APK --baksmali BAKSMALI --smali SMALI --uberApkSigner UBERAPKSIGNER [--skipCleanup]

All arguments are required (except for skipCleanup, which if set will not delete temporary files).

### How It Works ###

- APK is copied to local directory
- classes.dex is extracted from APK and decompiled 
- Resulting Smali code is patched to enable grammar-check feature and to allow the app to run using your signing key (workaround for security feature of Gboard).
- Patched Smali is recompiled into classes.dex and injected into APK
- APK is zipaligned and signed using UberAPKSigner

### How-To: Generate Signing Key ###

keytool -genkey -v -keystore debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000

* Keystore File will be "debug.keystore"
* Keystore Password will be "android"
* Key Alias will be "androiddebugkey"
* Key Password will be "android"