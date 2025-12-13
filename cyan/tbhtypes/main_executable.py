import os
import sys
import shutil
import subprocess
from typing import Optional

try:
  import lief  # type: ignore
except Exception:
  pass

from cyan import tbhutils
from .executable import Executable

class MainExecutable(Executable):
  def __init__(self, path: str, bundle_path: str):
    super().__init__(path)
    self.bundle_path = bundle_path

    self.inj: Optional = None  # type: ignore

    if os.path.isfile(self.idylib):
      self.inj_func = self.idyl_inject
    else:
      self.inj_func = self.lief_inject

  def inject(self, tweaks: dict[str, str], tmpdir: str, inject_to_path: bool = False, custom_path: bool = False, no_defualt_dependencies: bool = False) -> None:
    ENT_PATH = f"{self.bundle_path}/cyan.entitlements"
    PLUGINS_DIR = f"{self.bundle_path}/PlugIns"
    FRAMEWORKS_DIR = f"{self.bundle_path}/Frameworks"
    has_entitlements = self.write_entitlements(ENT_PATH)

    # iirc, injecting doesnt work (sometimes) if the file is signed
    self.remove_signature()

    if any(t.endswith(".appex") for t in tweaks):
      os.makedirs(PLUGINS_DIR, exist_ok=True)

    if any(
        t.endswith(k)
        for t in tweaks
        for k in (".deb", ".dylib", ".framework")
    ) and not inject_to_path:
      os.makedirs(FRAMEWORKS_DIR, exist_ok=True)
      # some apps really dont have this lol
      subprocess.run(
        [self.nt, "-add_rpath", "@executable_path/Frameworks", self.path],
        stderr=subprocess.DEVNULL
      )

    # `extract_deb()` will modify `tweaks`, which is why we make a copy
    cwd = os.getcwd()
    for bn, path in dict(tweaks).items():
      if bn.endswith(".deb"):
        tbhutils.extract_deb(path, tweaks, tmpdir)
        continue
    os.chdir(cwd)  # i fucking hate jailbroken iOS utils.

    needed: set[str] = set()
    CUSTOM_INJECTIONS = {
      "SwiftgramCrack.dylib": {
          "app_name": "Swiftgram",
          "target_binary": "Frameworks/TelegramUIFramework.framework/TelegramUIFramework"
      }
    }
    # inject/fix user things
    for bn, path in tweaks.items():
      if os.path.islink(path):
        continue  # symlinks can potentially have some security implications

      custom_rule = CUSTOM_INJECTIONS.get(bn)
      if custom_path and custom_rule and f"Payload/{custom_rule["app_name"]}.app" in self.bundle_path:
        target_path = f"{self.bundle_path}/{custom_rule["target_binary"]}"
      else:
        target_path = None

      if bn.endswith(".appex"):
        fpath = f"{PLUGINS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        shutil.copytree(path, fpath)
        location = "PlugIns/"
      elif bn.endswith(".dylib"):
        path = shutil.copy2(path, tmpdir)

        e = Executable(path)
        e.fix_common_dependencies(needed, no_defualt_dependencies)
        e.fix_dependencies(tweaks, inject_to_path)

        if inject_to_path:
          # Inject directly into @executable_path hehehe
          fpath = f"{self.bundle_path}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self.inj_func(f"@executable_path/{bn}", target_path)
            location = "@executable_path/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self.inj_func(f"@executable_path/{bn}")
            location = "@executable_path/"
          shutil.move(path, fpath)
        else:
          # Default zx behavior: inject into @executable_path/Frameworks
          fpath = f"{FRAMEWORKS_DIR}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self.inj_func(f"@rpath/{bn}", target_path)
            location = "Frameworks/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self.inj_func(f"@rpath/{bn}")
            location = "Frameworks/"
          shutil.move(path, fpath)
      elif bn.endswith(".framework"):
        if inject_to_path:
          # With -p flag, frameworks also go to @executable_path
          fpath = f"{self.bundle_path}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self.inj_func(f"@executable_path/{bn}/{bn[:-10]}", target_path)
            location = "@executable_path/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self.inj_func(f"@executable_path/{bn}/{bn[:-10]}")
            location = "@executable_path/"
          shutil.copytree(path, fpath)
        else:
          # Default zx behavior frameworks go to Frameworks/
          fpath = f"{FRAMEWORKS_DIR}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self.inj_func(f"@rpath/{bn}/{bn[:-10]}", target_path)
            location = "Frameworks/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self.inj_func(f"@rpath/{bn}/{bn[:-10]}")
            location = "Frameworks/"
          shutil.copytree(path, fpath)
      else:
        fpath = f"{self.bundle_path}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        try:
          shutil.copytree(path, fpath)
        except NotADirectoryError:
          shutil.copy2(path, self.bundle_path)
        location = "@executable_path/"

      if not existed:
        print(f"[*] injected {bn} -> {location}")

    # orion has a *weak* dependency to substrate,
    # but will still crash without it. nice !!!!!!!!!!!
    ## edit: actually, maybe this is in case someone uses Internal backend?
    ## someone test it pls!!!
    if "orion." in needed:
      needed.add("substrate.")

    for missing in needed:
      real = self.common[missing]["name"]  # e.g. "Orion.framework"
      ip = f"{FRAMEWORKS_DIR}/{real}"
      existed = tbhutils.delete_if_exists(ip, real)
      shutil.copytree(f"{self.install_dir}/extras/{real}", ip)

      if not existed:
        print(f"[*] auto-injected {real}")

    # FINALLY !!
    if self.inj is not None:  # type: ignore
      self.inj.write(self.path)  # type: ignore
      self.inj = None  # type: ignore

    if has_entitlements:
      self.sign_with_entitlements(ENT_PATH)
      print("[*] restored entitlements")

  def write_entitlements(self, output: str) -> bool:
    with open(output, "wb") as entf:
      proc = subprocess.run(
        [self.ldid, "-e", self.path],
        capture_output=True
      )

      entf.write(proc.stdout)

    return os.path.getsize(output) > 0

  def merge_entitlements(self, entitlements: str) -> None:
    if self.sign_with_entitlements(entitlements):
      print("[*] merged new entitlements")
    else:
      print("[!] failed to merge new entitlements, are they valid?")

  def sign_with_entitlements(self, entitlements: str) -> bool:
    return subprocess.run([
      self.ldid,
      f"-S{entitlements}", "-M", "-Cadhoc",
      f"-Q{self.install_dir}/extras/zero.requirements",
      self.path
    ]).returncode == 0

  def sign_plugin(self, target: str) -> bool:
    return subprocess.run([
      self.ldid,
      "-Cadhoc", "-s",
      f"-Q{self.install_dir}/extras/zero.requirements",
      target
    ]).returncode == 0

  def lief_inject(self, cmd: str, target: Optional[str] = None) -> None:
    if target is None:
      target = self.path

    if self.inj is None:  # type: ignore
      try:
        lief.logging.disable()  # type: ignore
      except Exception:
        sys.exit("[!] did you forget to install lief?")

      self.inj = lief.parse(target)  # type: ignore

    try:
      self.inj.add(lief.MachO.DylibCommand.weak_lib(cmd))  # type: ignore
    except AttributeError:
      sys.exit("[!] couldn't add LC (lief), did you use a valid app?")

  def idyl_inject(self, cmd: str, target: Optional[str] = None) -> None:
    if target is None:
      target = self.path

    proc = subprocess.run(
      [
        self.idylib, "--weak", "--inplace", "--all-yes",
        cmd, target
      ], capture_output=True, text=True
    )

    if proc.returncode != 0:
      sys.exit(f"[!] couldn't add LC (insert_dylib), error:\n{proc.stderr}")

  def patch_plugins(self, tmpdir: str, inject_to_path: bool = False, dylib: Optional[str] = None, arg_f: Optional[dict[str, str]] = None) -> None:
    arg_f_dict: dict[str, str] = arg_f if arg_f is not None else {}
    FRAMEWORKS_DIR = f"{self.bundle_path}/Frameworks"
    PLUGINS_DIR = f"{self.bundle_path}/PlugIns"
    if not inject_to_path:
      os.makedirs(FRAMEWORKS_DIR, exist_ok=True)
    if arg_f is None and not inject_to_path:
      subprocess.run(
        [self.nt, "-add_rpath", "@executable_path/Frameworks", self.path],
        stderr=subprocess.DEVNULL
      )
    if dylib is None:
      dylib_source = f"{self.install_dir}/extras/zxPluginsInject.dylib"
    else:
      dylib_source = dylib
    dylib_name = os.path.basename(dylib_source)
    path = shutil.copy2(dylib_source, tmpdir)
    if inject_to_path:
      location = f"@executable_path/{dylib_name}"
      old_location = f"@rpath/{dylib_name}"
      fpath = os.path.join(self.bundle_path, dylib_name)
      old_fpath = os.path.join(FRAMEWORKS_DIR, dylib_name)
    else:
      location = f"@rpath/{dylib_name}"
      old_location = f"@executable_path/{dylib_name}"
      fpath = os.path.join(FRAMEWORKS_DIR, dylib_name)
      old_fpath = os.path.join(self.bundle_path, dylib_name)
    shutil.move(path, fpath)

    targets = [self.path]
    found_dylib: Optional[str] = None
    
    if os.path.isdir(PLUGINS_DIR):
      for item in os.listdir(PLUGINS_DIR):
        if item.endswith(".appex"):
          binary_path = os.path.join(PLUGINS_DIR, item, item[:-6])
          if os.path.isfile(binary_path):
            targets.append(binary_path)
            injected_dylib = self.is_dylib_already_injected(binary_path, old_location)
            if injected_dylib is not None:
              found_dylib = injected_dylib

    count = 0
    for target in targets:
      a = self.is_dylib_already_injected(target, old_location)
      b = self.is_dylib_already_injected(target, location)
      if not b:
        if a and ((target == self.path and a == found_dylib) or (target != self.path)):
          self.change_dependency(old_location, location, target)
          count += 1
          if os.path.isfile(old_fpath):
            os.remove(old_fpath)
        else:
          self.remove_signature(target)
          self.inj_func(location, target)
          if self.inj is not None:  # type: ignore
            self.inj.write(target)  # type: ignore
            self.inj = None  # type: ignore
          self.sign_plugin(target)
          count += 1
      else:
        if (dylib_name in arg_f_dict and target == self.path):
          count += 1
          continue
        print(f"[?] {os.path.basename(target)} already patched")
    if count > 0:
      print(f"[*] patched \033[96m{count}\033[0m item(s) with {dylib_name}")
