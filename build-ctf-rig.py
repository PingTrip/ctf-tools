#!/usr/bin/env python3

import apt
import re
import os
import sys
import time
import subprocess
import urllib.request
import zipfile
import shutil
import tarfile
from glob import glob


class LogInstallProgress(apt.progress.base.InstallProgress):
    def fork(self):
        pid = os.fork()
        if pid == 0:
            logfd = os.open("ctf_build.log", os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o644)
            os.dup2(logfd, 1)
            os.dup2(logfd, 2)
        return pid


def print_progress(msg):
    print("----------------------------------------------------------------------")
    print(f"| {msg}")
    print("----------------------------------------------------------------------")
    time.sleep(2)


def update_apt_repo():
    pass
    urllib.request.urlretrieve("https://packagecloud.io/AtomEditor/atom/gpgkey", '/tmp/atom.key')
    subprocess.run(["apt-key", "add", "/tmp/atom.key"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    repo_config = "deb [arch=amd64] https://packagecloud.io/AtomEditor/atom/any/ any main"
    subprocess.run(["add-apt-repository", repo_config], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def update_package_list():
    print_progress("Updating APT and upgrading packages...")
    apt_cache = apt.Cache()
    apt_cache.update()       # apt-get update
    apt_cache.open(None)     # Re-read package list
    apt_cache.upgrade()      # apt-get upgrade
    apt_cache.upgrade(True)  # apt-get dist-upgrade
    apt_cache.commit(install_progress=LogInstallProgress())


def uninstall_packages():
    print_progress("Uninstalling unwanted packages...")
    pkg_list = ["unattended-upgrades", "network-manager-config-connectivity-ubuntu"]
    apt_cache = apt.Cache()

    for pkg in pkg_list:
        pkg = apt_cache[pkg]
        pkg.mark_delete(purge=True)
        print(f'Uninstalling {pkg}: {pkg.marked_delete}')

    apt_cache.commit(install_progress=LogInstallProgress())
    subprocess.run(["apt-mark", "hold", "snapd"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def install_apt_packages(pkg_list):
    print_progress("Installing APT packages...")

    os.environ["DEBIAN_FRONTEND"] = 'noninteractive'
    apt_cache = apt.Cache()

    for pkg in pkg_list.split():
        pkg = apt_cache[pkg]
        pkg.mark_install()
        print(f'Installing {pkg}: {pkg.marked_install}')

    apt_cache.commit(install_progress=LogInstallProgress())


def install_pip_packages(pkg_list):
    print_progress("Installing PIP packages...")
    subprocess.run(["sudo", "-H", "pip3", "-q", "install", *pkg_list.split()])


def disable_cups_browsed():
    print_progress("Disabling cups-browsed...")
    subprocess.run(["systemctl", "stop", "cups-browsed"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["systemctl", "disable", "cups-browsed"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def create_shared_folder_mount():
    print_progress("Creating shared folder mount...")

    if not os.path.exists('/mnt/hgfs'):
        os.mkdir("/mnt/hgfs", 0o755)

    mount = ".host:/    /mnt/hgfs        fuse.vmhgfs-fuse    defaults,allow_other    0    0\n"

    with open("/etc/fstab", "r+") as fstab:
        for line in fstab:
            if mount in line:
                break
        else:
            fstab.write(mount)

    subprocess.run(["sudo", "mount", "/mnt/hgfs"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # sudo ln -s /mnt/hgfs/CTF-Data /CTF-Data


def setup_workenv():
    print_progress("Setting up work environment...")

    if not os.path.exists(f'{HOMEDIR}/Tools'):
        os.mkdir(f"{HOMEDIR}/Tools", 0o755)
        subprocess.run(["chown", "-R", f"{os.getenv('SUDO_USER')}:{os.getenv('SUDO_USER')}", f"{HOMEDIR}/Tools"])

    # ln -s /mnt/hgfs/CTF-Data/ctf-work/ HOMEDIR/Desktop/CTF-Work
    urllib.request.urlretrieve("https://raw.githubusercontent.com/PingTrip/ctf-tools/master/ctf_settings", f'{HOMEDIR}/Tools/ctf_settings')
    urllib.request.urlretrieve("https://raw.githubusercontent.com/PingTrip/ctf-tools/master/gdbinit", f'{HOMEDIR}/.gdbinit')
    subprocess.run(["chown", f"{os.getenv('SUDO_USER')}:{os.getenv('SUDO_USER')}", f"{HOMEDIR}/.gdbinit"])

    with open(f"{HOMEDIR}/.bashrc", "r+") as f:
        for line in f:
            if f"source {HOMEDIR}/Tools/ctf_settings" in line:
                break
        else:
            f.write(f"source {HOMEDIR}/Tools/ctf_settings")


def tweak_desktop_settings():

    print_progress("Tweaking desktop settings...")

    desktop_settings = [
        ["org.gnome.desktop.screensaver", "idle-activation-enabled", "false"],
        ["org.gnome.desktop.screensaver", "lock-enabled", "false"],
        ["org.gnome.desktop.session", "idle-delay", "0"],
        ["org.gnome.settings-daemon.plugins.power", "sleep-inactive-ac-type", "nothing"],
        ["org.gnome.desktop.background", "picture-uri", "https://pingtrip.com/static/images/ctf_wallpaper.png"]
    ]

    for setting in desktop_settings:
        subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "gsettings", "set", *setting])

    # Copy monitor.xml to .config
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "xrandr", "--output", "Virtual1", "--mode", "1440x900"])


def cleanup_packages():
    print_progress("Cleaning up packages...")
    apt_cache = apt.Cache()
    for pkg_name in apt_cache.keys():
        pkg = apt_cache[pkg_name]
        if (pkg.is_installed and pkg.is_auto_removable):
            pkg.mark_delete()

    apt_cache.commit(install_progress=LogInstallProgress())


def install_peda():
    print_progress("Installing PEDA...")
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "git", "clone", "https://github.com/longld/peda.git", f"{HOMEDIR}/Tools/peda"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def install_ctfhost():
    print_progress("Installing CTF-Host Utility...")
    urllib.request.urlretrieve("https://raw.githubusercontent.com/PingTrip/ctf-tools/master/ctf-host", f'{HOMEDIR}/Tools/ctf-host')
    os.chmod(f"{HOMEDIR}/Tools/ctf-host", 0o744)


def install_ghidra():
    print_progress("Installing Ghidra...")
    if not os.path.exists(f'{HOMEDIR}/Documents/Ghidra-Work'):
        os.mkdir(f"{HOMEDIR}/Documents/Ghidra-Work", 0o755)
        shutil.chown(f"{HOMEDIR}/Documents/Ghidra-Work", os.getenv('SUDO_USER'), os.getenv('SUDO_USER'))

    html = urllib.request.urlopen('https://ghidra-sre.org/')
    soup = BeautifulSoup(html.read(), features="html.parser")
    latest_ver = soup.find('a', href=True, string=re.compile('Download Ghidra'))['href']

    urllib.request.urlretrieve(f"https://ghidra-sre.org/{latest_ver}", '/tmp/ghidra.zip')

    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "unzip", "/tmp/ghidra.zip", "-d", f"{HOMEDIR}/Tools/"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    path = "/path_to_files"

    f = glob(os.path.join(HOMEDIR, "ghidra_*"))[0]
    os.rename(f, os.path.join(path, "ghidra"))
    # Launch Ghidra and create a new project with the name _CTF_ and project directory of _HOMEDIR/Documents/Ghidra-Work_


def install_gobuster():
    print_progress("Installing Gobuster...")
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "/bin/env", f"GOPATH={HOMEDIR}/Tools/go", "go", "get", "github.com/OJ/gobuster"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def install_cyberchef():
    print_progress("Installing CyberChef...")
    if not os.path.exists(f'{HOMEDIR}/Tools/cyberchef'):
        os.mkdir(f"{HOMEDIR}/Tools/cyberchef", 0o755)

    html = urllib.request.urlopen('https://gchq.github.io/CyberChef/')
    soup = BeautifulSoup(html.read(), features="html.parser")
    latest_ver = soup.select_one("a[download]")["href"]

    urllib.request.urlretrieve(f"https://gchq.github.io/CyberChef/{latest_ver}", '/tmp/cyberchef.zip')

    with zipfile.ZipFile('/tmp/cyberchef.zip', 'r') as zip_ref:
        zip_ref.extractall(f"{HOMEDIR}/Tools/cyberchef")

    # In your web browser of choice set a bookmark for _file:///home/[USERNAME]/Tools/cyberchef/CyberChef\_v9.21.0.html_


def install_rsactftool():
    print_progress("Installing RsaCtfTool...")
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "git", "clone", "https://github.com/Ganapati/RsaCtfTool.git", f"{HOMEDIR}/Tools/RsaCtfTool"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    # pip3 install -r "requirements.txt"


def install_metasploit():
    print_progress("Installing Metasploit...")
    urllib.request.urlretrieve("https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb", '/tmp/msfinstall')
    subprocess.run(["sudo", "sh", "/tmp/msfinstall"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    # $ msfconsole
    # Enter 'no' at prompt to create new database


def install_volatility():
    print_progress("Installing Volatility 3...")
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "git", "clone", "https://github.com/volatilityfoundation/volatility3.git", f"{HOMEDIR}/Tools/volatility3"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def install_yara():
    print_progress("Installing YARA...")
    # check for latest at https://github.com/VirusTotal/yara/releases)
    urllib.request.urlretrieve("https://github.com/VirusTotal/yara/archive/v4.0.2.tar.gz", '/tmp/yara.tar.gz')

    with tarfile.open('/tmp/yara.tar.gz') as tar:
        tar.extractall('/tmp')

    subprocess.run(["chown", "-R", os.getenv('SUDO_USER'), "/tmp/yara-4.0.2"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "./bootstrap.sh"], cwd="/tmp/yara-4.0.2", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "./configure"], cwd="/tmp/yara-4.0.2", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "make"], cwd="/tmp/yara-4.0.2", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["make", "install"], cwd="/tmp/yara-4.0.2", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def install_jdgui():
    print_progress("Installing JD-GUI...")
    # check for latest at http://java-decompiler.github.io/
    urllib.request.urlretrieve("https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar", f'{HOMEDIR}/Tools/jd-gui.jar')


def install_dextools():
    print_progress("Installing Dextools...")
    # check for latest at https://github.com/DexPatcher/dex2jar/releases/
    urllib.request.urlretrieve("https://github.com/DexPatcher/dex2jar/releases/download/v2.1-20171001-lanchon/dex-tools-2.1-20171001-lanchon.zip", '/tmp/dex-tools.zip')

    with zipfile.ZipFile('/tmp/dex-tools.zip', 'r') as zip_ref:
        zip_ref.extractall(f"{HOMEDIR}/Tools/")


def install_jtr():
    print_progress("Installing John the Ripper...")
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "git", "clone", "https://github.com/openwall/john", "-b", "bleeding-jumbo", f"{HOMEDIR}/Tools/jtr"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "./configure"], cwd=f'{HOMEDIR}/Tools/jtr/src/', stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "make", "-s", "clean"], cwd=f'{HOMEDIR}/Tools/jtr/src/', stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "make", "-sj4"], cwd=f'{HOMEDIR}/Tools/jtr/src/', stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def install_stegsolve():
    print_progress("Installing StegSolve...")
    urllib.request.urlretrieve("https://github.com/Giotino/stegsolve/releases/download/v.1.5/StegSolve-1.5-alpha1.jar", f'{HOMEDIR}/Tools/stegsolve.jar')


def install_torbrowser():
    print_progress("Installing TOR Browser...")

    html = urllib.request.urlopen('https://www.torproject.org/download/')
    soup = BeautifulSoup(html.read(), features="html.parser")
    latest_ver = soup.find('a', href=True, text='Download for Linux')['href']

    urllib.request.urlretrieve(f"https://www.torproject.org{latest_ver}", '/tmp/torbrowser.tar.xz')

    with tarfile.open('/tmp/torbrowser.tar.xz') as tar:
        tar.extractall(f'{HOMEDIR}/Tools/')

    subprocess.run(["chown", "-R", os.getenv('SUDO_USER'), f"{HOMEDIR}/Tools/"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "./start-tor-browser.desktop", "--register-app"], cwd=f'{HOMEDIR}/Tools/tor-browser_en-US/', stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def install_sqlmap():
    print_progress("Installing sqlmap...")
    subprocess.run(["sudo", "-u", os.getenv('SUDO_USER'), "git", "clone", "https://github.com/sqlmapproject/sqlmap.git", "--depth", "1", f"{HOMEDIR}/Tools/sqlmap"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


# ---------------------------------------------------------------- #


if not os.getenv("SUDO_USER"):
    print("Run with sudo")
    sys.exit(1)
elif os.getenv("SUDO_USER") == "root":
    print("Not as root")
    sys.exit(1)

HOMEDIR = os.path.expanduser('~' + os.getenv('SUDO_USER'))

apt_packages = "atom chromium-browser curl masscan nmap libimage-exiftool-perl openjdk-11-jdk golang-go git python3-pip python3-dev libpcap-dev libc6-i386 sonic-visualiser ewf-tools hydra binwalk samdump2 ghex ffmpeg gimp steghide foremost audacity libgmp3-dev libmpc-dev libssl-dev libbz2-dev automake libtool unrar pavucontrol qsstv gnupg2 wireshark upx-ucl sagemath mysql-server sqlite3"
pip_packages = "opencv-python matplotlib flake8 pwntools pefile yara-python testresources sympy cryptography urllib3 requests gmpy gmpy2 pycryptodome six beautifulsoup4"
manual_installs = "peda ctfhost ghidra gobuster cyberchef rsactftool metasploit volatility yara jdgui dextools jtr stegsolve torbrowser sqlmap"

disable_cups_browsed()
uninstall_packages()
update_apt_repo()
update_package_list()
install_apt_packages(apt_packages)
create_shared_folder_mount()
install_pip_packages(pip_packages)
cleanup_packages()
tweak_desktop_settings()
setup_workenv()

from bs4 import BeautifulSoup

for pkg in manual_installs.split():
    locals()["install_" + pkg]()


subprocess.run(["chown", "-R", f"{os.getenv('SUDO_USER')}:{os.getenv('SUDO_USER')}", f"{HOMEDIR}/Tools"])

print("The build process is complete. Power off the VM and take a snapshot.")

"""

function set_favorite_apps() {
    sudo -u $SUDO_USER gsettings set org.gnome.shell favorite-apps "$(gsettings get org.gnome.shell favorite-apps | sed s/.$//), 'org.gnome.Terminal.desktop']"

}

"""
