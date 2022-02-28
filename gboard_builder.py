import subprocess
import argparse
import os
import shutil

parser = argparse.ArgumentParser()
parser.add_argument("--keystore", type=str, required=True)
parser.add_argument("--keyAlias", type=str, required=True)
parser.add_argument("--keystorePassword", type=str, required=True)
parser.add_argument("--keyPassword", type=str, required=True)
parser.add_argument("--apk", type=str, required=True)
parser.add_argument("--baksmali", type=str, required=True)
parser.add_argument("--smali", type=str, required=True)
parser.add_argument("--uberApkSigner", type=str, required=True)
parser.add_argument("--skipCleanup", action="store_true")
args = parser.parse_args()

key = subprocess.check_output("keytool -list -keystore " + args.keystore + " -alias " + args.keyAlias \
    + " -storepass " + args.keystorePassword + " -keypass " + args.keyPassword + " | grep SHA-256 | cut -d':' -f2- | xargs", shell=True)
keyArray = key.decode().strip().lower().split(':')

print("Copying APK to local directory...")
apkFileName, apkFileExt = os.path.splitext(os.path.basename(args.apk))
moddedApkFile = "./" + apkFileName + "_modded" + apkFileExt
shutil.copyfile(args.apk, moddedApkFile)

print("Extracting 'classes.dex' from APK...")
subprocess.Popen("unzip -o " + moddedApkFile + " classes.dex", shell=True).wait()
print("Decompiling 'classes.dex' using baksmali...")
subprocess.Popen("java -jar " + args.baksmali + " disassemble classes.dex", shell=True).wait()

print("Searching for signature-check file...")
smaliFile = subprocess.check_output("grep -R '0x19t' out | cut -d':' -f1 | uniq | xargs grep '0x75t' | cut -d':' -f1", shell=True).decode().strip()
print("Searching for grammar-check control file...")
grammarFile = subprocess.check_output("grep -R '\"enable_grammar_checker\"' out | cut -d':' -f1", shell=True).decode().strip()
print("Searching for lines to modify...")
startLine = subprocess.check_output("echo $(($(cat " + smaliFile + " | grep -n 'array-data 1' | cut -d':' -f1 | head -1) + 1))", shell=True).decode().strip()
endLine= subprocess.check_output("echo $(($(cat " + smaliFile + " | grep -n '.end array-data' | cut -d':' -f1 | head -1) - 1))", shell=True).decode().strip()
grammarBoolLine= subprocess.check_output("echo $(($(cat " + grammarFile + " | grep -n '\"enable_grammar_checker\"' | cut -d':' -f1 | head -1) + 2))", shell=True).decode().strip()

print("Modifying signature-check file...")
replacement = ""
with open(smaliFile, 'r') as f:
    i = 1
    keyIndex = 0
    for line in f:
        if i >= int(startLine) and i <= int(endLine):
            line = "        0x" + keyArray[keyIndex] + "t\n"
            keyIndex += 1
        i += 1
        replacement += line
with open(smaliFile, 'w') as f:
    f.write(replacement)

print("Modifying grammar-check control file...")
replacement = ""
with open(grammarFile, 'r') as f:
    i = 1
    for line in f:
        if i == int(grammarBoolLine):
            line = line.replace("0x0", "0x1")
        i += 1
        replacement += line
with open(grammarFile, 'w') as f:
    f.write(replacement)

print("Compiling modified smali...")
subprocess.Popen("java -jar " + args.smali + " assemble out", shell=True).wait()
subprocess.Popen("mv out.dex classes.dex", shell=True).wait()
print("Injecting compiled code into APK...")
subprocess.Popen("zip " + moddedApkFile + " classes.dex", shell=True).wait()
print("Zip-aligning and signing APK...")
subprocess.Popen("java -jar " + args.uberApkSigner + " --ks " + args.keystore + " --ksPass " + args.keystorePassword + \
    " --ksKeyPass " + args.keyPassword + " -a " + moddedApkFile + " --ksAlias " + args.keyAlias, shell=True).wait()
if not args.skipCleanup:
    print("Cleaning up temporary files...")
    shutil.rmtree("./out")
    os.remove("./classes.dex")
    os.remove("./" + moddedApkFile)
print("Done!")
print("Install file '" + moddedApkFile + "' to your device.")