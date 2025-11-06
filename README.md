# munki_rebrand_swift
Rebrands Munki 7+

Based on the fantastic work from IT Services, University of Oxford (https://github.com/ox-it/munki-rebrand/blob/main/munki_rebrand.py)


```
sudo ./munki_rebrand_swift.py -h
usage: munki_rebrand_swift.py [-h] -a APPNAME [-k PKG] [-i ICON_FILE] [--identifier IDENTIFIER] [-o OUTPUT_FILE] [-s SIGN_PACKAGE] [-S SIGN_BINARIES] [-u USER] [-v]
                              [-x]

Rebrands Munki's Managed Software Center for Swift-based MSC (Munki 7+)

options:
  -h, --help            show this help message and exit
  -a APPNAME, --appname APPNAME
                        Your desired app name for Managed Software Center
  -k PKG, --pkg PKG     Prebuilt munkitools pkg to rebrand
  -i ICON_FILE, --icon-file ICON_FILE
                        Optional icon file (1024x1024 PNG)
  --identifier IDENTIFIER
                        Package identifier prefix
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Base name for customized pkg
  -s SIGN_PACKAGE, --sign-package SIGN_PACKAGE
                        Sign package with Developer ID Installer
  -S SIGN_BINARIES, --sign-binaries SIGN_BINARIES
                        Sign binaries with Developer ID Application
  -u USER, --user USER  Username to use for signing (default: current sudo user)
  -v, --verbose         Be more verbose
  -x, --version         Print version and exit
```
  i.e.
```
  sudo ./munki_rebrand_swift.py --appname "My New App Store" -v
```
```
  sudo ./munki_rebrand_swift.py --appname "My New App Store" --icon-file New_App_Store_Icon.png -v
```
```
  sudo ./munki_rebrand_swift.py --appname "My New App Store" --icon-file New_App_Store_Icon.png --sign-package "Developer ID Installer: xxxxxx (S1234567P)" --user userwithcertificatesinkeychain -v
```

You must have Xcode and Xcode tools installed to run this.

Update 06-11-25:
Fixed Custom Naming for acOS 26 (Sequoia)
Better Checking on Files

  
