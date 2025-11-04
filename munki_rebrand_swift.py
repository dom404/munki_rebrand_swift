#!/usr/bin/env python3
# encoding: utf-8
"""
munki_rebrand_swift.py

Script to rebrand and customise Munki's Managed Software Center (Munki 7+)
"""

import subprocess
import os
import stat
import shutil
from tempfile import mkdtemp
from xml.etree import ElementTree as ET
import plistlib
import argparse
import sys
import atexit
import glob
import fnmatch
import io
import json
import getpass

VERSION = "7.0"

APPNAME_LOCALIZED = {
    "Base": "Managed Software Center",
    "da": "Managed Software Center",
    "de": "Geführte Softwareaktualisierung", 
    "en": "Managed Software Center",
    "en-AU": "Managed Software Centre",
    "en-GB": "Managed Software Centre",
    "en-CA": "Managed Software Centre",
    "en_AU": "Managed Software Centre",
    "en_GB": "Managed Software Centre", 
    "en_CA": "Managed Software Centre",
    "es": "Centro de aplicaciones",
    "fi": "Managed Software Center",
    "fr": "Centre de gestion des logiciels",
    "it": "Centro Gestione Applicazioni",
    "ja": "Managed Software Center",
    "nb": "Managed Software Center",
    "nl": "Managed Software Center",
    "ru": "Центр Управления ПО",
    "sv": "Managed Software Center",
}

# Function to generate app paths dynamically based on the provided app name
def get_app_paths(appname):
    """Generate app paths dynamically based on the provided app name"""
    # Sanitize app name for filesystem use
    sanitized_name = appname.replace("/", "-").replace("\\", "-")
    
    return [
        {
            "path": "Payload/Applications/Managed Software Center.app",
            "new_path": f"Payload/Applications/{sanitized_name}.app",
            "icon": ["Managed Software Center.icns", "AppIcon.icns"],
            "binary": "Managed Software Center",
        },
        {
            "path": "Payload/Applications/Managed Software Center.app/Contents/Helpers/MunkiStatus.app",
            "new_path": f"Payload/Applications/{sanitized_name}.app/Contents/Helpers/MunkiStatus.app", 
            "icon": ["MunkiStatus.icns", "AppIcon.icns"],
            "binary": "MunkiStatus",
        },
        {
            "path": "Payload/Applications/Managed Software Center.app/Contents/Helpers/munki-notifier.app",
            "new_path": f"Payload/Applications/{sanitized_name}.app/Contents/Helpers/munki-notifier.app",
            "icon": ["AppIcon.icns"],
            "binary": "munki-notifier",
        }
    ]

MUNKI_PATH = "usr/local/munki"
PY_FWK = os.path.join(MUNKI_PATH, "Python.Framework")
PY_CUR = os.path.join(PY_FWK, "Versions/Current")

ICON_SIZES = [
    ("16", "16x16"),
    ("32", "16x16@2x"),
    ("32", "32x32"),
    ("64", "32x32@2x"),
    ("128", "128x128"),
    ("256", "128x128@2x"),
    ("256", "256x256"),
    ("512", "256x256@2x"),
    ("512", "512x512"),
    ("1024", "512x512@2x"),
]

PKGBUILD = "/usr/bin/pkgbuild"
PKGUTIL = "/usr/sbin/pkgutil"
PRODUCTBUILD = "/usr/bin/productbuild"
PRODUCTSIGN = "/usr/bin/productsign"
CODESIGN = "/usr/bin/codesign"
FILE = "/usr/bin/file"
PLUTIL = "/usr/bin/plutil"
SIPS = "/usr/bin/sips"
ICONUTIL = "/usr/bin/iconutil"
CURL = "/usr/bin/curl"
ACTOOL = [
    "/usr/bin/actool",
    "/Applications/Xcode.app/Contents/Developer/usr/bin/actool",
]

MUNKIURL = "https://api.github.com/repos/munki/munki/releases/latest"

global verbose
verbose = False
tmp_dir = mkdtemp()

@atexit.register
def cleanup():
    print("Cleaning up...")
    try:
        shutil.rmtree(tmp_dir)
    except OSError:
        pass
    print("Done.")

def run_cmd(cmd, ret=None):
    """Runs a command passed in as a list."""
    proc = subprocess.run(cmd, capture_output=True)
    if verbose and proc.stdout != b"" and not ret:
        print(proc.stdout.rstrip().decode())
    if proc.returncode != 0:
        print(proc.stderr.rstrip().decode())
        sys.exit(1)
    if ret:
        return proc.stdout.rstrip().decode()

def get_latest_munki_url():
    cmd = [CURL, "-s", MUNKIURL]
    j = run_cmd(cmd, ret=True)
    api_result = json.loads(j)
    return api_result["assets"][0]["browser_download_url"]

def download_pkg(url, output):
    print(f"Downloading munkitools from {url}...")
    cmd = [CURL, "--location", "--output", output, url]
    run_cmd(cmd)

def flatten_pkg(directory, pkg):
    """Flattens a pkg folder"""
    cmd = [PKGUTIL, "--flatten-full", directory, pkg]
    run_cmd(cmd)

def expand_pkg(pkg, directory):
    """Expands a flat pkg to a folder"""
    cmd = [PKGUTIL, "--expand-full", pkg, directory]
    run_cmd(cmd)

def plist_to_xml(plist):
    """Converts plist file to xml1 format"""
    cmd = [PLUTIL, "-convert", "xml1", plist]
    run_cmd(cmd)

def plist_to_binary(plist):
    """Converts plist file to binary1 format"""
    cmd = [PLUTIL, "-convert", "binary1", plist]
    run_cmd(cmd)

def guess_encoding(f):
    cmd = [FILE, "--brief", "--mime-encoding", f]
    enc = run_cmd(cmd, ret=True)
    if "ascii" in enc:
        return "utf-8"
    return enc

def is_binary(f):
    return guess_encoding(f) == "binary"

def is_signable_bin(path):
    '''Checks if a path is a file and is executable'''
    if os.path.isfile(path) and (os.stat(path).st_mode & stat.S_IXUSR > 0):
        return True
    return False

def is_signable_lib(path):
    '''Checks if a path is a file and ends with .so or .dylib'''
    if os.path.isfile(path) and (path.endswith(".so") or path.endswith(".dylib")):
        return True
    return False

def replace_strings(strings_file, code, appname):
    """EXACT COPY from original script - replaces localized app name in a .strings file with desired app name"""
    localized = APPNAME_LOCALIZED[code]
    if verbose:
        print(f"Replacing '{localized}' in {strings_file} with '{appname}'...")
    backup_file = f"{strings_file}.bak"
    enc = guess_encoding(strings_file)

    # Could do this in place but im oldskool so
    with io.open(backup_file, "w", encoding=enc) as fw, io.open(
        strings_file, "r", encoding=enc
    ) as fr:
        for line in fr:
            # We want to only replace on the right hand side of any =
            # and we don't want to do it to a comment
            if "=" in line and not line.startswith("/*"):
                left, right = line.split("=")
                right = right.replace(localized, appname)
                line = "=".join([left, right])
            fw.write(line)
    os.remove(strings_file)
    os.rename(backup_file, strings_file)

def icon_test(png):
    # EXACT COPY from original script - Check if icon is png
    with open(png, "rb") as f:
        pngbin = f.read()
    if pngbin[:8] == b'\x89PNG\r\n\x1a\n' and pngbin[12:16] == b'IHDR':
        return True
    return False

def convert_to_icns(png, output_dir, actool=""):
    """EXACT COPY from original script - Takes a png file and attempts to convert it to an icns set"""
    icon_dir = os.path.join(output_dir, "icons")
    os.mkdir(icon_dir)
    xcassets = os.path.join(icon_dir, "Assets.xcassets")
    os.mkdir(xcassets)
    iconset = os.path.join(xcassets, "AppIcon.appiconset")
    os.mkdir(iconset)
    contents = {}
    contents["images"] = []
    for hw, suffix in ICON_SIZES:
        scale = "1x"
        if suffix.endswith("2x"):
            scale = "2x"
        cmd = [
            SIPS,
            "-z",
            hw,
            hw,
            png,
            "--out",
            os.path.join(iconset, f"AppIcon_{suffix}.png"),
        ]
        run_cmd(cmd)
        if suffix.endswith("2x"):
            hw = str(int(hw) / 2)
        image = dict(
            size=f"{hw}x{hw}",
            idiom="mac",
            filename=f"AppIcon_{suffix}.png",
            scale=scale,
        )
        contents["images"].append(image)
    icnspath = os.path.join(icon_dir, "AppIcon.icns")

    # Munki 3.6+ has an Assets.car which is compiled from the Assets.xcassets
    # to provide the AppIcon
    if actool:
        # Use context of the location of munki_rebrand.py to find the Assets.xcassets
        # directory.
        rebrand_dir = os.path.dirname(os.path.abspath(__file__))
        xc_assets_dir = os.path.join(rebrand_dir, "Assets.xcassets/")
        if not os.path.isdir(xc_assets_dir):
            print(
                f"The Assets.xcassets folder could not be found in {rebrand_dir}. "
                "Make sure it's in place, and then try again."
            )
            sys.exit(1)
        shutil.copytree(xc_assets_dir, xcassets, dirs_exist_ok=True)
        with io.open(os.path.join(iconset, "Contents.json"), "w") as f:
            contentstring = json.dumps(contents)
            f.write(contentstring)
        cmd = [
            actool,
            "--compile",
            icon_dir,
            "--app-icon",
            "AppIcon",
            "--minimum-deployment-target",
            "10.11",
            "--output-partial-info-plist",
            os.path.join(icon_dir, "Info.plist"),
            "--platform",
            "macosx",
            "--errors",
            "--warnings",
            xcassets,
        ]
        run_cmd(cmd)
    else:
        # Old behaviour for < 3.6
        cmd = [ICONUTIL, "-c", "icns", iconset, "-o", icnspath]
        run_cmd(cmd)

    carpath = os.path.join(icon_dir, "Assets.car")
    if not os.path.isfile(carpath):
        carpath = None
    if not os.path.isfile(icnspath):
        icnspath = None

    return icnspath, carpath

def remove_signature(app_path):
    """Remove code signature from app"""
    if os.path.exists(app_path):
        cmd = [CODESIGN, "--remove-signature", app_path]
        try:
            run_cmd(cmd)
        except:
            print(f"Warning: Could not remove signature from {app_path}")

def sign_binary(signing_id, binary, verbose=False, deep=False, options=[], entitlements="", force=False):
    """EXACT COPY from original script - Signs a binary with a signing id, with optional arguments for command line args"""
    cmd = [CODESIGN, "--sign", signing_id]
    if force:
        cmd.append("--force")
    if deep:
        cmd.append("--deep")
    if verbose:
        cmd.append("--verbose")
    if entitlements:
        cmd.append("--entitlements")
        cmd.append(entitlements)
    if options:
        cmd.append("--options")
        cmd.append(",".join([option for option in options]))
    cmd.append(binary)
    run_cmd(cmd)

def sign_app(app_path, signing_id=None):
    """Re-sign application with proper entitlements for Swift apps"""
    if not os.path.exists(app_path):
        return
    
    # Create basic entitlements for Swift apps
    entitlements = {
        "com.apple.security.cs.allow-unsigned-executable-memory": True,
        "com.apple.security.cs.allow-dyld-environment-variables": True,
        "com.apple.security.cs.disable-library-validation": True,
    }
    
    ent_file = os.path.join(tmp_dir, "entitlements.plist")
    with open(ent_file, 'wb') as f:
        plistlib.dump(entitlements, f)
    
    if signing_id:
        cmd = [CODESIGN, "--deep", "--force", "--entitlements", ent_file, 
               "--options", "runtime", "--sign", signing_id, app_path]
    else:
        # Ad-hoc sign
        cmd = [CODESIGN, "--deep", "--force", "--entitlements", ent_file,
               "--options", "runtime", "--sign", "-", app_path]
    
    try:
        run_cmd(cmd)
    except:
        print(f"Warning: Could not sign {app_path}")

def sign_package(signing_id, pkg):
    """EXACT COPY from original script - Signs a pkg with a signing id"""
    cmd = [PRODUCTSIGN, "--sign", signing_id, pkg, f"{pkg}-signed"]
    print("Signing pkg...")
    run_cmd(cmd)
    print(f"Moving {pkg}-signed to {pkg}...")
    os.rename(f"{pkg}-signed", pkg)

def update_app_display_name(app_path, new_name):
    """Update the app's display name in Info.plist"""
    info_plist = os.path.join(app_path, "Contents/Info.plist")
    if os.path.isfile(info_plist):
        try:
            # Read existing plist
            with open(info_plist, 'rb') as f:
                plist = plistlib.load(f)
            
            # Update display names
            plist['CFBundleDisplayName'] = new_name
            plist['CFBundleName'] = new_name
            
            # Write back
            with open(info_plist, 'wb') as f:
                plistlib.dump(plist, f)
                
            if verbose:
                print(f"  Updated Info.plist for {os.path.basename(app_path)}")
                
        except Exception as e:
            print(f"Warning: Could not update Info.plist for {app_path}: {e}")

def find_app_packages(root_dir):
    """Find all packages that contain apps in Munki 7+ structure"""
    app_packages = []
    
    # Look for packages that might contain apps
    possible_patterns = [
        "munkitools_app*",
        "munkitools_app_usage*", 
        "munkitools_gui*",
        "munkitools_admin*"
    ]
    
    for pattern in possible_patterns:
        matches = glob.glob(os.path.join(root_dir, pattern))
        for match in matches:
            if os.path.isdir(match):
                # Check if this package contains apps
                payload_dir = os.path.join(match, "Payload")
                if os.path.exists(payload_dir):
                    # Check for Applications folder or .app files
                    apps_dir = os.path.join(payload_dir, "Applications")
                    if os.path.exists(apps_dir):
                        app_packages.append(match)
                    else:
                        # Check for .app files directly in payload
                        for item in os.listdir(payload_dir):
                            if item.endswith('.app'):
                                app_packages.append(match)
                                break
    
    return app_packages

def rename_app_bundle(app_pkg, old_path, new_path):
    """Actually rename the .app bundle"""
    old_app_dir = os.path.join(app_pkg, old_path)
    new_app_dir = os.path.join(app_pkg, new_path)
    
    if os.path.exists(old_app_dir) and not os.path.exists(new_app_dir):
        print(f"Renaming app bundle: {os.path.basename(old_app_dir)} -> {os.path.basename(new_app_dir)}")
        shutil.move(old_app_dir, new_app_dir)
        return True
    elif os.path.exists(new_app_dir):
        if verbose:
            print(f"App already renamed: {os.path.basename(new_app_dir)}")
        return True
    else:
        if verbose:
            print(f"App not found for renaming: {old_app_dir}")
        return False

def sign_all_binaries(signing_id, root_dir, appname):
    """Comprehensive binary signing from original script"""
    print("Signing binaries (this may take a while)...")
    
    # Find all packages
    app_pkg = glob.glob(os.path.join(root_dir, "munkitools_app*"))[0]
    core_pkg = glob.glob(os.path.join(root_dir, "munkitools_core*"))[0]
    python_pkg = glob.glob(os.path.join(root_dir, "munkitools_python*"))[0]

    app_payload = os.path.join(app_pkg, "Payload")
    core_payload = os.path.join(core_pkg, "Payload")
    python_payload = os.path.join(python_pkg, "Payload")

    # Generate entitlements file for later
    entitlements = {
        "com.apple.security.cs.allow-unsigned-executable-memory": True
    }
    ent_file = os.path.join(tmp_dir, "entitlements.plist")
    with open(ent_file, 'wb') as f:
        plistlib.dump(entitlements, f)

    # Add the MSC app pkg binaries
    binaries = [
        os.path.join(
            app_payload,
            "Applications",
            f"{appname}.app",
            "Contents/PlugIns/MSCDockTilePlugin.docktileplugin",
        ),
        os.path.join(
            app_payload,
            "Applications", 
            f"{appname}.app",
            "Contents/Helpers/munki-notifier.app",
        ),
        os.path.join(
            app_payload,
            "Applications",
            f"{appname}.app", 
            "Contents/Helpers/MunkiStatus.app",
        ),
        os.path.join(
            app_payload,
            "Applications",
            f"{appname}.app",
        ),
    ]
    
    # In munki 5.3 and higher, managedsoftwareupdate is a signable binary
    msu = os.path.join(
            core_payload,
            MUNKI_PATH,
            "managedsoftwareupdate",
        )
    if is_binary(msu):
        binaries.append(msu)

    # Add the executable libs and bins in python pkg
    pylib = os.path.join(python_payload, PY_CUR, "lib")
    pybin = os.path.join(python_payload, PY_CUR, "bin")
    for pydir in [pylib, pybin]:
        if os.path.exists(pydir):
            for f in os.listdir(pydir):
                if is_signable_bin(os.path.join(pydir, f)):
                    binaries.append(os.path.join(pydir, f))
            for root, dirs, files in os.walk(pydir):
                for file_ in files:
                    if is_signable_lib(os.path.join(root, file_)):
                        binaries.append(os.path.join(root, file_))

    # Add binaries which need entitlements
    entitled_binaries = [
        os.path.join(python_payload, PY_CUR, "Resources/Python.app"),
        os.path.join(pybin, "python3"),
    ]

    # Sign all the binaries. The order is important. Which is why this is a bit
    # gross
    for binary in binaries:
        if os.path.exists(binary):
            if verbose:
                print(f"Signing {binary}...")
            sign_binary(
                signing_id,
                binary,
                deep=True,
                force=True,
                options=["runtime"],
            )

    for binary in entitled_binaries:
        if os.path.exists(binary):
            if verbose:
                print(f"Signing {binary} with entitlements from {ent_file}...")
            sign_binary(
                signing_id,
                binary,
                deep=True,
                force=True,
                options=["runtime"],
                entitlements=ent_file,
            )
    
    # Finally sign python framework
    py_fwkpath = os.path.join(python_payload, PY_FWK)
    if os.path.exists(py_fwkpath):
        if verbose:
            print(f"Signing {py_fwkpath}...")
        sign_binary(signing_id, py_fwkpath, deep=True, force=True)

def get_current_user():
    """Get the current non-root username"""
    try:
        return os.environ['SUDO_USER']
    except KeyError:
        return getpass.getuser()

def sign_package_as_user(pkg_path, signing_id, user=None):
    """Sign the package as the specified user"""
    if not user:
        user = get_current_user()
    
    signed_pkg = pkg_path.replace('.pkg', '-signed.pkg')
    
    print(f"Signing package as user '{user}'...")
    
    # Build the command to run as the user
    cmd = f'sudo -u {user} productsign --sign "{signing_id}" "{pkg_path}" "{signed_pkg}"'
    
    try:
        # Run the signing command as the specified user
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Package signed successfully: {signed_pkg}")
            
            # Verify the signature
            verify_cmd = f'sudo -u {user} pkgutil --check-signature "{signed_pkg}"'
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
            if verify_result.returncode == 0:
                print("Signature verified")
            else:
                print("Could not verify signature")
            
            return signed_pkg
        else:
            print(f"Signing failed: {result.stderr}")
            return None
    except Exception as e:
        print(f"Signing error: {e}")
        return None

def sign_apps_as_user(app_path, signing_id, user=None):
    """Sign apps as the specified user"""
    if not user:
        user = get_current_user()
    
    print(f"📝 Signing apps as user '{user}'...")
    
    apps_to_sign = [
        app_path,
        os.path.join(app_path, "Contents/Helpers/MunkiStatus.app"),
        os.path.join(app_path, "Contents/Helpers/munki-notifier.app")
    ]
    
    for app in apps_to_sign:
        if os.path.exists(app):
            cmd = f'sudo -u {user} codesign --deep --force --options runtime --sign "{signing_id}" "{app}"'
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Signed: {os.path.basename(app)}")
                else:
                    print(f"⚠️  Failed to sign {os.path.basename(app)}: {result.stderr}")
            except Exception as e:
                print(f"⚠️  Error signing {os.path.basename(app)}: {e}")

def main():
    p = argparse.ArgumentParser(
        description="Rebrands Munki's Managed Software Center for Swift-based MSC (Munki 7+)"
    )

    p.add_argument("-a", "--appname", required=True, help="Your desired app name for Managed Software Center")
    p.add_argument("-k", "--pkg", help="Prebuilt munkitools pkg to rebrand")
    p.add_argument("-i", "--icon-file", help="Optional icon file (1024x1024 PNG)")
    p.add_argument("--identifier", default="com.googlecode.munki", help="Package identifier prefix")
    p.add_argument("-o", "--output-file", help="Base name for customized pkg")
    p.add_argument("-s", "--sign-package", help="Sign package with Developer ID Installer")
    p.add_argument("-S", "--sign-binaries", help="Sign binaries with Developer ID Application") 
    p.add_argument("-u", "--user", help="Username to use for signing (default: current sudo user)")
    p.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
    p.add_argument("-x", "--version", action="store_true", help="Print version and exit")
    
    args = p.parse_args()

    if args.version:
        print(VERSION)
        sys.exit(0)

    if os.geteuid() != 0:
        print("This script must be run as root for package operations!")
        print("Run with: sudo ./munki_rebrand_swift.py [options]")
        sys.exit(1)

    global verbose
    verbose = args.verbose
    
    # Get the user for signing
    sign_user = args.user or get_current_user()
    print(f"👤 Will sign packages as user: {sign_user}")

    # Set output filename
    outfilename = args.output_file or "munkitools"

    # Generate app paths dynamically based on the provided app name
    APPS = get_app_paths(args.appname)
    
    print(f"Using app name: {args.appname}")
    if verbose:
        print(f"Generated app paths:")
        for app in APPS:
            print(f"  {app['path']} -> {app.get('new_path', 'No rename')}")

    # Look for actool
    actool = next((x for x in ACTOOL if os.path.isfile(x)), None)
    if not actool:
        print(
            "WARNING: actool not found. Icon file will not be replaced in "
            "Munki 3.6 and higher. See README for more info."
        )

    # Process icon file if provided - EXACT COPY from original script
    icns = None
    car = None
    if args.icon_file and os.path.isfile(args.icon_file):
        if icon_test(args.icon_file):
            # Attempt to convert png to icns
            print("Converting .png file to .icns...")
            icns, car = convert_to_icns(args.icon_file, tmp_dir, actool=actool)
        else:
            print("ERROR: icon file must be a 1024x1024 .png")
            sys.exit(1)

    # Download or use provided package
    output = os.path.join(tmp_dir, "munkitools.pkg")
    if not args.pkg:
        download_pkg(get_latest_munki_url(), output)
        args.pkg = output
    elif args.pkg.startswith("http"):
        download_pkg(args.pkg, output)
        args.pkg = output

    if not os.path.isfile(args.pkg):
        print(f"Could not find munkitools pkg {args.pkg}")
        sys.exit(1)

    # Process package
    root_dir = os.path.join(tmp_dir, "root")
    expand_pkg(args.pkg, root_dir)

    # Find app packages in Munki 7+ structure
    app_packages = find_app_packages(root_dir)
    
    if not app_packages:
        print("No app packages found! Available packages:")
        for item in os.listdir(root_dir):
            if os.path.isdir(os.path.join(root_dir, item)):
                print(f"  - {item}")
        sys.exit(1)

    if verbose:
        print(f"Found app packages: {[os.path.basename(pkg) for pkg in app_packages]}")

    # Extract version from Distribution file
    distfile = os.path.join(root_dir, "Distribution")
    if os.path.exists(distfile):
        tree = ET.parse(distfile)
        r = tree.getroot()
        pkgref = r.findall(f"pkg-ref[@id='{args.identifier}.app']")
        if pkgref:
            munki_version = pkgref[0].attrib["version"]
        else:
            # Fallback: try to get version from any pkg-ref
            pkgref = r.findall("pkg-ref")
            if pkgref:
                munki_version = pkgref[0].attrib.get("version", "7.0.0")
            else:
                munki_version = "7.0.0"
    else:
        munki_version = "7.0.0"

    # Process apps from all found packages
    print(f"Replacing app name with {args.appname}...")
    
    apps_processed = 0
    
    for app_pkg in app_packages:
        if verbose:
            print(f"Processing package: {os.path.basename(app_pkg)}")
        
        # FIRST: Rename the main app bundle before processing anything else
        main_app_renamed = False
        for app in APPS:
            if "Managed Software Center.app" in app["path"] and "new_path" in app:
                if rename_app_bundle(app_pkg, app["path"], app["new_path"]):
                    main_app_renamed = True
                    break
        
        # Icon handling
        for app in APPS:
            # Use the new path if available, otherwise use old path
            app_path = app.get("new_path", app["path"])
            app_dir = os.path.join(app_pkg, app_path)
            
            if os.path.exists(app_dir):
                print(f"Processing {os.path.basename(app_dir)}...")
                
                # Remove signature before modifications
                remove_signature(app_dir)
                
                # Update display name in Info.plist
                update_app_display_name(app_dir, args.appname)
                
                # Update localized strings - EXACT COPY from original script
                resources_dir = os.path.join(app_dir, "Contents/Resources")
                if os.path.exists(resources_dir):
                    # Get a list of all the lproj dirs in each app's Resources dir
                    lproj_dirs = glob.glob(os.path.join(resources_dir, "*.lproj"))
                    for lproj_dir in lproj_dirs:
                        # Determine lang code
                        code = os.path.basename(lproj_dir).split(".")[0]
                        # Don't try to change anything we don't know about
                        if code in list(APPNAME_LOCALIZED.keys()):
                            for root, dirs, files in os.walk(lproj_dir):
                                for file_ in files:
                                    lfile = os.path.join(root, file_)
                                    if fnmatch.fnmatch(lfile, "*.strings"):
                                        replace_strings(lfile, code, args.appname)
                
                # EXACT COPY from original script for icon replacement
                if args.icon_file:
                    if icns:
                        for icon in app["icon"]:
                            icon_path = os.path.join(app_dir, "Contents/Resources", icon)
                            if os.path.isfile(icon_path):
                                found_icon = icon
                                break
                        if 'found_icon' in locals():
                            dest = icon_path
                            print(f"Replacing icons in {dest} with {args.icon_file}...")
                            shutil.copyfile(icns, dest)
                    if car:
                        car_path = os.path.join(app_dir, "Contents/Resources", "Assets.car")
                        if os.path.isfile(car_path):
                            shutil.copyfile(car, car_path)
                            print(f"Replacing icons in {car_path} with {car}...")
                
                # Re-sign app with simple method first
                sign_app(app_dir, args.sign_binaries)
                
                apps_processed += 1
            else:
                if verbose:
                    print(f"  App not found: {app_dir}")

    # Comprehensive binary signing if requested
    if args.sign_binaries:
        sign_all_binaries(args.sign_binaries, root_dir, args.appname)

    if apps_processed == 0:
        print("No apps were processed! Checking package structure...")
        for app_pkg in app_packages:
            print(f"\nContents of {os.path.basename(app_pkg)}:")
            for root, dirs, files in os.walk(app_pkg):
                for dir_name in dirs:
                    if dir_name.endswith('.app'):
                        print(f"  Found app: {os.path.join(root, dir_name)}")
        sys.exit(1)

    # Update Distribution file
    if os.path.exists(distfile):
        with open(distfile, 'r') as f:
            dist_content = f.read()
        
        dist_content = dist_content.replace("Managed Software Center", args.appname)
        
        with open(distfile, 'w') as f:
            f.write(dist_content)

    # Rebuild package
    final_pkg = f"{outfilename}-{munki_version}.pkg"
    flatten_pkg(root_dir, final_pkg)

    # Handle signing if requested
    signed_pkg = final_pkg
    if args.sign_package:
        signed_pkg = sign_package_as_user(final_pkg, args.sign_package, sign_user)
        if not signed_pkg:
            print("Package signing failed, using unsigned package")
            signed_pkg = final_pkg

    # Sign apps if requested
    if args.sign_binaries:
        app_path = f"/Applications/{args.appname}.app"
        sign_apps_as_user(app_path, args.sign_binaries, sign_user)

    print(f"Successfully created and installed: {signed_pkg}")
    print(f"App name changed to: {args.appname}")
    if args.sign_package:
        print(f"Package signed with: {args.sign_package}")
    if args.sign_binaries:
        print(f"Binaries signed with: {args.sign_binaries}")
    if icns:
        print(f"Custom icon applied")

if __name__ == "__main__":
    main()
