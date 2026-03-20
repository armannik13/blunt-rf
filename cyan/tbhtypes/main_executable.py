import os
import sys
import shutil
import subprocess
from typing import Any, Callable, Optional, List

try:
  import lief  # type: ignore
except Exception:
  pass

from cyan import tbhutils
from .executable import Executable

# Type alias for the pending dict: maps target path -> lief binary object
LiefPending = dict[str, Any]

# Type alias for injection backend functions
InjFunc = Callable[[str, Optional[str], Optional[LiefPending]], None]


class MainExecutable(Executable):
  def __init__(self, path: str, bundle_path: str):
    super().__init__(path)
    self.bundle_path = bundle_path

    self.inj_func: InjFunc
    if os.path.isfile(self.idylib):
      self.inj_func = self.idyl_inject
    else:
      self.inj_func = self.lief_inject

  # ------------------------------------------------------------------
  # lief helpers — no instance state, purely local
  # ------------------------------------------------------------------

  def _lief_parse(self, target: str) -> Any:
    try:
      lief.logging.disable()  # type: ignore
    except Exception:
      sys.exit("[!] did you forget to install lief?")
    binary: Any = lief.parse(target)  # type: ignore[no-untyped-call]
    assert binary is not None, "[!] couldn't parse binary (lief), did you use a valid app?"
    return binary # type: ignore

  def _lief_add(self, pending: LiefPending, cmd: str, target: str) -> None:
    """Add a weak LC to `target` via lief, batching writes in `pending`."""
    if target not in pending:
      pending[target] = self._lief_parse(target)
    try:
      pending[target].add(lief.MachO.DylibCommand.weak_lib(cmd))  # type: ignore
    except AttributeError:
      sys.exit("[!] couldn't add LC (lief), did you use a valid app?")

  @staticmethod
  def _flush_pending(pending: LiefPending) -> None:
    """Write all batched lief binaries to disk and clear the dict."""
    for target, binary in pending.items():
      binary.write(target)  # type: ignore
    pending.clear()

  # ------------------------------------------------------------------
  # injection backends
  # ------------------------------------------------------------------

  def lief_inject(self, cmd: str, target: Optional[str] = None, pending: Optional[LiefPending] = None) -> None:
    """
    lief backend. If `pending` is supplied, the write is deferred —
    caller must call _flush_pending(pending) when done.
    If omitted, a temporary dict is used and flushed immediately.
    """
    if target is None:
      target = self.path
    own_pending = pending is None
    if own_pending:
      pending = {}
    self._lief_add(pending, cmd, target)
    if own_pending:
      self._flush_pending(pending)

  def idyl_inject(self, cmd: str, target: Optional[str] = None, pending: Optional[LiefPending] = None) -> None:
    """insert_dylib backend. `pending` is accepted but unused (writes in-place)."""
    if target is None:
      target = self.path
    proc = subprocess.run(
      [self.idylib, "--weak", "--inplace", "--all-yes", cmd, target],
      capture_output=True, text=True
    )
    if proc.returncode != 0:
      sys.exit(f"[!] couldn't add LC (insert_dylib), error:\n{proc.stderr}")

  def _inject(self, cmd: str, target: str, pending: LiefPending) -> None:
    """Unified injection call that always passes `pending` through."""
    self.inj_func(cmd, target, pending)

  # ------------------------------------------------------------------

  def inject(self, tweaks: dict[str, str], tmpdir: str, inject_to_path: bool = False, custom_path: bool = False, no_default_dependencies: bool = False, ignore_encrypted: bool = False, inject_all: bool = False) -> None:
    ENT_PATH = f"{self.bundle_path}/cyan.entitlements"
    PLUGINS_DIR = f"{self.bundle_path}/PlugIns"
    FRAMEWORKS_DIR = f"{self.bundle_path}/Frameworks"
    has_entitlements = self.write_entitlements(ENT_PATH)
    itp = inject_to_path and not inject_all

    # iirc, injecting doesnt work (sometimes) if the file is signed
    self.remove_signature()

    if any(t.endswith(".appex") for t in tweaks):
      os.makedirs(PLUGINS_DIR, exist_ok=True)

    if any(
        t.endswith(k)
        for t in tweaks
        for k in (".deb", ".dylib", ".framework")
    ):
      # some apps really dont have this lol
      if "@executable_path/Frameworks" not in self.get_rpaths():
        os.makedirs(FRAMEWORKS_DIR, exist_ok=True)
        subprocess.run(
          [self.nt, "-add_rpath", "@executable_path/Frameworks", self.path],
          stderr=subprocess.DEVNULL
        )

    # `extract_deb()` will modify `tweaks`, which is why we make a copy
    cwd = os.getcwd()
    try:
      for bn, path in dict(tweaks).items():
        if bn.endswith(".deb"):
          tbhutils.extract_deb(path, tweaks, tmpdir)
    finally:
      os.chdir(cwd)  # i fucking hate jailbroken iOS utils.

    needed: set[str] = set()
    CUSTOM_INJECTIONS: dict[str, dict[str, str]] = {
      "SwiftgramCrack.dylib": {
          "app_name": "Swiftgram",
          "target_binary": "Frameworks/TelegramUIFramework.framework/TelegramUIFramework"
      }
    }

    # All lief writes are batched here — keyed by target path.
    # insert_dylib writes in-place immediately, so it never touches this dict.
    pending: LiefPending = {}

    # inject/fix user things
    for bn, path in tweaks.items():
      if os.path.islink(path):
        print(f"[!] skipping symlink: {bn}")
        continue

      target_path: Optional[str] = None
      ent_path: Optional[str] = None
      binary_has_entitlements: Optional[bool] = None

      custom_rule = CUSTOM_INJECTIONS.get(bn)
      if custom_path and custom_rule and f"Payload/{custom_rule['app_name']}.app" in self.bundle_path:
        target_path = f"{self.bundle_path}/{custom_rule['target_binary']}"
        if self.is_encrypted(target_path) and ignore_encrypted:
          print(f"[?] {os.path.basename(target_path)} encrypted, ignoring")
        elif self.is_encrypted(target_path) and not ignore_encrypted:
          print(f"[?] {os.path.basename(target_path)} encrypted, use ignore encrypted")
          continue
        ent_path = f"{os.path.dirname(target_path)}/cyan.entitlements"
        binary_has_entitlements = self.write_entitlements(ent_path, target_path)
        self.remove_signature(target_path)

      if bn.endswith(".appex"):
        fpath = f"{PLUGINS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        shutil.copytree(path, fpath)
        location = "PlugIns/"
      elif bn.endswith(".dylib"):
        path = shutil.copy2(path, tmpdir)

        e = Executable(path)
        e.fix_common_dependencies(needed, no_default_dependencies)
        e.fix_dependencies(tweaks, itp)

        if itp:
          fpath = f"{self.bundle_path}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self._inject(tbhutils.get_relative_dylib_path(target_path, bn), target_path, pending)
            if ent_path and binary_has_entitlements:
              # must write before re-signing this specific target
              if target_path in pending:
                pending.pop(target_path).write(target_path)
              self.sign_with_entitlements(ent_path, target_path)
            location = "@executable_path/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self._inject(f"@executable_path/{bn}", self.path, pending)
            location = "@executable_path/"
          shutil.move(path, fpath)
        else:
          fpath = f"{FRAMEWORKS_DIR}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self._inject(f"@rpath/{bn}", target_path, pending)
            if ent_path and binary_has_entitlements:
              if target_path in pending:
                pending.pop(target_path).write(target_path)
              self.sign_with_entitlements(ent_path, target_path)
            location = "Frameworks/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self._inject(f"@rpath/{bn}", self.path, pending)
            location = "Frameworks/"
          shutil.move(path, fpath)
      elif bn.endswith(".framework"):
        if itp:
          fpath = f"{self.bundle_path}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self._inject(tbhutils.get_relative_dylib_path(target_path, f"{bn}/{bn[:-10]}"), target_path, pending)
            if ent_path and binary_has_entitlements:
              if target_path in pending:
                pending.pop(target_path).write(target_path)
              self.sign_with_entitlements(ent_path, target_path)
            location = "@executable_path/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self._inject(f"@executable_path/{bn}/{bn[:-10]}", self.path, pending)
            location = "@executable_path/"
          shutil.copytree(path, fpath)
        else:
          fpath = f"{FRAMEWORKS_DIR}/{bn}"
          existed = tbhutils.delete_if_exists(fpath, bn)
          if target_path and os.path.exists(target_path):
            self._inject(f"@rpath/{bn}/{bn[:-10]}", target_path, pending)
            if ent_path and binary_has_entitlements:
              if target_path in pending:
                pending.pop(target_path).write(target_path)
              self.sign_with_entitlements(ent_path, target_path)
            location = "Frameworks/ -> " + target_path.replace(self.bundle_path + "/", "")
          else:
            self._inject(f"@rpath/{bn}/{bn[:-10]}", self.path, pending)
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

    # Flush all remaining lief writes (main executable and any un-signed targets)
    self._flush_pending(pending)

    if has_entitlements:
      self.sign_with_entitlements(ENT_PATH)
      print("[*] restored entitlements")

  def inject_into_extension(self, target: str, tweaks: dict[str, str], ignore_encrypted: bool = False) -> None:
    target_name = os.path.basename(target)
    target_binary = f"{target}/{target_name[:-6]}"

    if self.is_encrypted(target_binary) and ignore_encrypted:
      print(f"[?] {target_name} encrypted, ignoring")
    elif self.is_encrypted(target_binary) and not ignore_encrypted:
      print(f"[?] {target_name} encrypted, use ignore encrypted")
      return

    dylibs = {k: v for k, v in tweaks.items() if k.endswith(".dylib")}
    if not dylibs:
      return

    ent_path = f"{target}/cyan.entitlements"
    has_entitlements = self.write_entitlements(ent_path, target_binary)
    self.remove_signature(target_binary)

    pending: LiefPending = {}
    for dylib in dylibs:
      self._inject(f"@rpath/{dylib}", target_binary, pending)

    self._flush_pending(pending)

    if has_entitlements:
      self.sign_with_entitlements(ent_path, target_binary)

    print(f"[*] injected into {target_name}")

  def write_entitlements(self, output: str, target: Optional[str] = None) -> bool:
    if target is None:
      target = self.path
    proc = subprocess.run(
      [self.ldid, "-e", target],
      capture_output=True
    )
    if proc.returncode != 0:
      return False
    with open(output, "wb") as entf:
      entf.write(proc.stdout)
    return os.path.getsize(output) > 0

  def merge_entitlements(self, entitlements: str) -> None:
    if self.sign_with_entitlements(entitlements):
      print("[*] merged new entitlements")
    else:
      print("[!] failed to merge new entitlements, are they valid?")

  def sign_with_entitlements(self, entitlements: str, target: Optional[str] = None) -> bool:
    if target is None:
      target = self.path
    return subprocess.run([
      self.ldid,
      f"-S{entitlements}", "-M", "-Cadhoc",
      f"-Q{self.install_dir}/extras/zero.requirements",
      target
    ]).returncode == 0

  def patch_plugins(self, tmpdir: str, dylib: Optional[str] = None, tweaks: Optional[dict[str, str]] = None, ignore_encrypted: bool = False, inject_all: bool = False) -> None:
    tweaks_dict: dict[str, str] = tweaks if tweaks is not None else {}
    ENT_PATH = f"{self.bundle_path}/cyan.entitlements"
    FRAMEWORKS_DIR = f"{self.bundle_path}/Frameworks"
    PLUGINS_DIR = f"{self.bundle_path}/PlugIns"
    if "@executable_path/Frameworks" not in self.get_rpaths():
      os.makedirs(FRAMEWORKS_DIR, exist_ok=True)
      subprocess.run(
        [self.nt, "-add_rpath", "@executable_path/Frameworks", self.path],
        stderr=subprocess.DEVNULL
      )

    dylib_source = dylib if dylib is not None else f"{self.install_dir}/extras/zxPluginsInject.dylib"
    dylib_name = os.path.basename(dylib_source)
    path = shutil.copy2(dylib_source, tmpdir)

    # zxPluginsInject MUST go to Frameworks/ to avoid iOS Extension Sandbox violations
    fpath = os.path.join(FRAMEWORKS_DIR, dylib_name)
    shutil.move(path, fpath)

    targets: list[str] = [self.path]

    if os.path.isdir(PLUGINS_DIR):
      for item in os.listdir(PLUGINS_DIR):
        if item.endswith(".appex"):
          binary_path = os.path.join(PLUGINS_DIR, item, item[:-6])
          if os.path.isfile(binary_path):
            targets.append(binary_path)

    count = 0
    for target in targets:
      if self.is_encrypted(target) and ignore_encrypted:
        print(f"[?] {os.path.basename(target)} encrypted, ignoring")
      elif self.is_encrypted(target) and not ignore_encrypted:
        print(f"[?] {os.path.basename(target)} encrypted, use ignore encrypted")
        continue

      if not self.is_dylib_already_injected(target, f"@rpath/{dylib_name}"):
        ent_path = ENT_PATH if target == self.path else f"{os.path.dirname(target)}/cyan.entitlements"
        has_entitlements = self.write_entitlements(ent_path, target)
        self.remove_signature(target)
        self.inj_func(f"@rpath/{dylib_name}", target, None)
        if has_entitlements:
          self.sign_with_entitlements(ent_path, target)
        count += 1
      else:
        if dylib_name in tweaks_dict and (target == self.path or inject_all):
          count += 1
        else:
          print(f"[?] {os.path.basename(target)} already patched")

    if count > 0:
      print(f"[*] patched \033[96m{count}\033[0m item(s) with {dylib_name}")

  def init_inject(self, tweaks: dict[str, str], tmpdir: str, inject_to_path: bool = False, custom_path: bool = False, no_default_dependencies: bool = False, ignore_encrypted: bool = False, inject_all: bool = False) -> None:
    self.inject(tweaks, tmpdir, inject_to_path, custom_path, no_default_dependencies, ignore_encrypted, inject_all)

    if not inject_all:
      return

    extensions: List[str] = []
    for subdir in ("PlugIns", "Extensions"):
      d = f"{self.bundle_path}/{subdir}"
      if os.path.exists(d):
        for item in os.listdir(d):
          if item.endswith(".appex"):
            extensions.append(os.path.join(d, item))

    if not extensions:
      print("[?] no app extensions found for -a")
      return

    for extension in extensions:
      self.inject_into_extension(extension, tweaks, ignore_encrypted)